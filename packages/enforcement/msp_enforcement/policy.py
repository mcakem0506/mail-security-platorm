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


ALG_HMAC = "HMAC-SHA256"
ALG_ED25519 = "ED25519"
_ED25519_CONTEXT = b"msp-enforcement-policy-v1|ED25519|"


class PolicyBundle(Strict):
    """Пакет распространения: политика, контрольная сумма и подпись (§21).

    ``algorithm`` по умолчанию HMAC: пакеты, выпущенные до появления асимметричной подписи, остаются читаемыми.
    """

    policy: str  # каноническая JSON-строка
    checksum: str
    signature: str
    issued_at: datetime
    algorithm: str = ALG_HMAC


def _digest(policy: EnforcementPolicy) -> tuple[str, str]:
    body = policy.canonical().decode()
    return body, hashlib.sha256(body.encode()).hexdigest()


def decode_key(text: str) -> bytes:
    """Ключ из base64 (так он хранится в настройках и файлах). Не base64 — ошибка политики, а не молчаливая пустота."""
    import base64
    import binascii

    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PolicyError("ключ не в формате base64") from exc


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Новая пара: (закрытый ключ 32 байта, открытый ключ 32 байта)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw_private, raw_public


def _private_key(raw: bytes):  # type: ignore[no-untyped-def]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if len(raw) != 32:
        raise PolicyError("закрытый ключ Ed25519 должен быть длиной 32 байта")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_from_private(private_key: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return (
        _private_key(private_key)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _message(algorithm: str, digest: str, issued_at: datetime) -> bytes:
    prefix = _ED25519_CONTEXT if algorithm == ALG_ED25519 else b""
    return prefix + f"{digest}|{issued_at.isoformat()}".encode()


def sign_policy(policy: EnforcementPolicy, key: bytes, *, issued_at: datetime | None = None) -> PolicyBundle:
    """Подпись общим секретом (HMAC). Секрет есть и у панели, и у узла: см. ``sign_policy_ed25519``."""
    if len(key) < 32:
        raise PolicyError("ключ подписи политики короче 32 байт")
    body, digest = _digest(policy)
    issued = issued_at or utcnow()
    mac = hmac.new(key, _message(ALG_HMAC, digest, issued), hashlib.sha256).hexdigest()
    return PolicyBundle(policy=body, checksum=digest, signature=mac, issued_at=issued, algorithm=ALG_HMAC)


def sign_policy_ed25519(
    policy: EnforcementPolicy, private_key: bytes, *, issued_at: datetime | None = None
) -> PolicyBundle:
    """Подпись Ed25519: закрытый ключ только у панели, узлу достаточно открытого."""
    key = _private_key(private_key)
    body, digest = _digest(policy)
    issued = issued_at or utcnow()
    signature = key.sign(_message(ALG_ED25519, digest, issued)).hex()
    return PolicyBundle(
        policy=body, checksum=digest, signature=signature, issued_at=issued, algorithm=ALG_ED25519
    )


def verify_bundle(
    bundle: PolicyBundle, key: bytes = b"", *, public_key: bytes | None = None
) -> EnforcementPolicy:
    """Контрольная сумма и подпись обязательны; подменённый или неподписанный пакет не принимается.

    Режим выбирает узел, а не пакет. Узел с открытым ключом принимает только Ed25519 и отвергает HMAC: открытый ключ публичен,
    и если бы узел принимал ещё и HMAC, подпись «секретом» из открытого ключа была бы подделкой. Узел без открытого ключа
    принимает только HMAC.
    """
    if hashlib.sha256(bundle.policy.encode()).hexdigest() != bundle.checksum:
        raise PolicyError("контрольная сумма пакета не совпала")
    if public_key is not None:
        _verify_ed25519(bundle, public_key)
    else:
        _verify_hmac(bundle, key)
    policy = EnforcementPolicy.model_validate_json(bundle.policy)
    if policy.checksum() != bundle.checksum:
        raise PolicyError("пакет не в каноническом виде")
    return policy


def _verify_hmac(bundle: PolicyBundle, key: bytes) -> None:
    if bundle.algorithm != ALG_HMAC:
        raise PolicyError("узел не настроен на асимметричную подпись, а пакет подписан иначе")
    expected = hmac.new(
        key, _message(ALG_HMAC, bundle.checksum, bundle.issued_at), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, bundle.signature):
        raise PolicyError("подпись пакета недействительна")


def _verify_ed25519(bundle: PolicyBundle, public_key: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if len(public_key) != 32:
        raise PolicyError("открытый ключ узла недействителен")
    if bundle.algorithm != ALG_ED25519:
        # Понижение до HMAC: узел с открытым ключом общего секрета не признаёт.
        raise PolicyError("узел требует подпись Ed25519")
    try:
        signature = bytes.fromhex(bundle.signature)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, _message(ALG_ED25519, bundle.checksum, bundle.issued_at)
        )
    except (InvalidSignature, ValueError) as exc:
        raise PolicyError("подпись пакета недействительна") from exc


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
        public_key: bytes | None = None,
        soft_ttl: timedelta = timedelta(minutes=10),
        hard_ttl: timedelta = timedelta(hours=6),
    ) -> None:
        self.directory = Path(directory)
        self.key = key
        self.public_key = public_key
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
        policy = verify_bundle(bundle, self.key, public_key=self.public_key)
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
            return verify_bundle(bundle, self.key, public_key=self.public_key), datetime.fromisoformat(
                raw["received_at"]
            )
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
