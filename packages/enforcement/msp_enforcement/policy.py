"""Политика принуждения и её распространение (ТЗ §16, §21, §22, §49).

Опубликованная политика неизменяема. Узел получает подписанный пакет, проверяет контрольную сумму и подпись,
хранит последнюю проверенную копию и принимает решения только по ней — без обращения к плоскости управления
(§48, §49). Если копия слишком стара, узел переходит в безопасный режим (§22).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path

from pydantic import Field, model_validator

from .canary import CanaryScope
from .exceptions import EnforcementException
from .model import DEFAULT_FAIL_MODE, ControlState, ControlType, FailMode, Strict, utcnow

#: Предельные значения тайм-аута решения до очереди (мс): граница обязательна и ограничена (§14).
MAX_HARD_TIMEOUT_MS = 5000


class PolicyError(ValueError):
    pass


class ControlPolicy(Strict):
    control_type: ControlType
    state: ControlState = ControlState.SHADOW
    thresholds: Mapping[str, float] = Field(default_factory=dict)
    canary_scope: CanaryScope = Field(default_factory=CanaryScope)
    fail_mode: FailMode | None = None
    hard_timeout_ms: int = Field(default=1500, ge=50, le=MAX_HARD_TIMEOUT_MS)
    #: Общий ответ SMTP без внутренних оценок, правил и топологии (§53).
    reject_reply: str = "554 5.7.1 Message rejected by local policy"
    tempfail_reply: str = "451 4.7.1 Temporary local policy deferral, try again later"

    @model_validator(mode="after")
    def _check(self) -> ControlPolicy:
        # Постоянный отказ из-за внутренней ошибки запрещён: режим сбоя — только открытый или временный (§15).
        if self.fail_mode is not None and self.fail_mode not in (FailMode.FAIL_OPEN, FailMode.FAIL_TEMPFAIL):
            raise PolicyError("недопустимый режим сбоя")
        if not self.reject_reply.startswith("5") or not self.tempfail_reply.startswith("4"):
            raise PolicyError("ответы SMTP: 5xx для отказа и 4xx для временного отказа")
        return self

    def effective_fail_mode(self) -> FailMode:
        return self.fail_mode or DEFAULT_FAIL_MODE[self.control_type]


class EnforcementPolicy(Strict):
    version: str = Field(min_length=1)
    organization_id: str = ""
    controls: tuple[ControlPolicy, ...] = ()
    #: Снимок состояния известных пробелов на момент публикации: решение узла не зависит от реестра панели.
    gaps: Mapping[str, str] = Field(default_factory=dict)
    groups: Mapping[str, tuple[str, ...]] = Field(default_factory=dict)
    exceptions: tuple[EnforcementException, ...] = ()
    valid_from: datetime = Field(default_factory=utcnow)
    valid_until: datetime
    owner: str
    reviewer: str = ""
    rollback_target: str = ""
    notes: str = ""

    @model_validator(mode="after")
    def _check(self) -> EnforcementPolicy:
        if self.valid_until <= self.valid_from:
            raise PolicyError("срок действия политики задан неверно")
        seen = [c.control_type for c in self.controls]
        if len(seen) != len(set(seen)):
            raise PolicyError("контроль указан в политике дважды")
        return self

    def control(self, kind: ControlType) -> ControlPolicy | None:
        return next((c for c in self.controls if c.control_type is kind), None)

    def canonical(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode()

    def checksum(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()


class PolicyBundle(Strict):
    """Пакет распространения: политика, контрольная сумма и подпись (§21)."""

    policy: str  # каноническая JSON-строка
    checksum: str
    signature: str
    issued_at: datetime


def sign_policy(policy: EnforcementPolicy, key: bytes, *, issued_at: datetime | None = None) -> PolicyBundle:
    if len(key) < 32:
        raise PolicyError("ключ подписи политики короче 32 байт")
    body = policy.canonical().decode()
    issued = issued_at or utcnow()
    digest = hashlib.sha256(body.encode()).hexdigest()
    mac = hmac.new(key, f"{digest}|{issued.isoformat()}".encode(), hashlib.sha256).hexdigest()
    return PolicyBundle(policy=body, checksum=digest, signature=mac, issued_at=issued)


def verify_bundle(bundle: PolicyBundle, key: bytes) -> EnforcementPolicy:
    """Контрольная сумма и подпись обязательны; подменённый или неподписанный пакет не принимается."""
    if hashlib.sha256(bundle.policy.encode()).hexdigest() != bundle.checksum:
        raise PolicyError("контрольная сумма пакета не совпала")
    expected = hmac.new(
        key, f"{bundle.checksum}|{bundle.issued_at.isoformat()}".encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, bundle.signature):
        raise PolicyError("подпись пакета недействительна")
    policy = EnforcementPolicy.model_validate_json(bundle.policy)
    if policy.checksum() != bundle.checksum:
        raise PolicyError("пакет не в каноническом виде")
    return policy


class PolicyStatus(StrEnum):
    FRESH = "FRESH"
    STALE = (
        "STALE"  # свежее мягкого срока нет, но жёсткий срок не вышел: работает последняя проверенная копия
    )
    SAFE_MODE = "SAFE_MODE"  # жёсткий срок вышел, политика просрочена или её нет: только наблюдение
    INVALID = "INVALID"


class PolicyCache:
    """Локальная копия политики на узле (§49). Хранит последний проверенный пакет и время получения."""

    def __init__(
        self,
        directory: Path,
        key: bytes,
        *,
        soft_ttl: timedelta = timedelta(minutes=10),
        hard_ttl: timedelta = timedelta(hours=6),
    ) -> None:
        self.directory = Path(directory)
        self.key = key
        self.soft_ttl = soft_ttl
        self.hard_ttl = hard_ttl

    @property
    def _active(self) -> Path:
        return self.directory / "active.json"

    @property
    def _good(self) -> Path:
        return self.directory / "last_good.json"

    def install(self, bundle: PolicyBundle, *, now: datetime | None = None) -> EnforcementPolicy:
        """Проверить пакет и сделать его действующим. Неверный пакет не затрагивает текущую копию."""
        policy = verify_bundle(bundle, self.key)
        self.directory.mkdir(parents=True, exist_ok=True)
        record = {"bundle": bundle.model_dump(mode="json"), "received_at": (now or utcnow()).isoformat()}
        tmp = self.directory / ".active.tmp"
        tmp.write_text(json.dumps(record), encoding="utf-8")
        if self._active.exists():
            os.replace(self._active, self._good)
        os.replace(tmp, self._active)
        return policy

    def _read(self, path: Path) -> tuple[EnforcementPolicy, datetime] | None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            bundle = PolicyBundle.model_validate(raw["bundle"])
            return verify_bundle(bundle, self.key), datetime.fromisoformat(raw["received_at"])
        except (OSError, ValueError, KeyError, PolicyError):
            return None

    def load(self, now: datetime | None = None) -> tuple[EnforcementPolicy | None, PolicyStatus]:
        now = now or utcnow()
        current = self._read(self._active)
        if current is None:
            fallback = self._read(self._good)
            if fallback is None:
                return None, PolicyStatus.SAFE_MODE if not self._active.exists() else PolicyStatus.INVALID
            current = fallback
        policy, received = current
        age = now - received
        if now >= policy.valid_until or age > self.hard_ttl:
            return policy, PolicyStatus.SAFE_MODE
        if age > self.soft_ttl:
            return policy, PolicyStatus.STALE
        return policy, PolicyStatus.FRESH
