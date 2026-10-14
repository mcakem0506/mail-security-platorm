"""Синхронизация узла с панелью: забрать назначенную конфигурацию и команду слива (ТЗ 1.1 §37–§40).

Работает от root, потому что применение требует ``postmap`` и ``postfix reload``, поэтому написан
осторожно: всё, что приходит от панели, — данные, которые проверяются так же, как пакет,
принесённый вручную. Токен панели даёт право *предложить* конфигурацию, но не право обойти узловую
проверку: белые списки параметров, состав файлов, контрольная сумма и проверка здоровья после
перезагрузки выполняются в ``apply_bundle`` независимо от источника.

Свойства, ради которых модуль устроен именно так:

* **Недоступная панель ничего не меняет.** Узел продолжает работать на последней применённой
  конфигурации; ошибка связи — не повод её сбрасывать и не повод останавливать почту.
* **Применяется только отличающееся.** Совпадение контрольной суммы — ничего не делаем: иначе
  каждый опрос перезагружал бы Postfix.
* **Итог всегда сообщается**, включая отказ и откат: оператор нажал «применить» и должен увидеть,
  что произошло, а не гадать.
* **Слив исполняется отдельно от конфигурации** и не зависит от неё: оператор, включивший слив
  перед обслуживанием, не должен ждать, пока применится обновление.

Только стандартная библиотека: модуль работает на узле.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .apply import ApplyResult, ConfigStore, Outcome, apply_bundle
from .state import is_draining, set_drain, write_recipient_meta

#: Предел размера ответа панели. Пакет с большим справочником велик, но не бесконечен.
MAX_RESPONSE_BYTES = 256 * 1024 * 1024


class PanelError(Exception):
    """Панель недоступна или ответила непригодным образом. Узел продолжает работать как работал."""


Fetch = Callable[[], dict[str, Any]]
Apply = Callable[[dict[str, bytes], dict[str, Any]], ApplyResult]
Report = Callable[[str, dict[str, object]], None]


def http_fetch(url: str, token: str, node_id: str, *, timeout: float = 20.0) -> Fetch:
    """Запрос конфигурации. Токен только в заголовке; адрес с токеном в строке запроса не строится."""
    if not url.startswith(("https://", "http://")):
        raise ValueError("адрес панели должен быть http(s)")
    target = f"{url.rstrip('/')}/config?{urllib.parse.urlencode({'node_id': node_id})}"

    def fetch() -> dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 - схема проверена выше
            target, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            raise PanelError(f"панель недоступна: {type(error).__name__}") from error
        if len(body) > MAX_RESPONSE_BYTES:
            raise PanelError("ответ панели больше допустимого")
        try:
            data = json.loads(body)
        except ValueError as error:
            raise PanelError("ответ панели не JSON") from error
        if not isinstance(data, dict):
            raise PanelError("ответ панели не объект")
        return data

    return fetch


@dataclass
class SyncResult:
    applied: bool = False
    outcome: str = ""
    detail: str = ""
    drain_changed: bool = False
    panel_reachable: bool = True


def _bundle_from(data: dict[str, Any]) -> tuple[dict[str, bytes], dict[str, Any]] | None:
    bundle = data.get("bundle")
    if not isinstance(bundle, dict):
        return None
    files = bundle.get("files")
    manifest = bundle.get("manifest")
    if not isinstance(files, dict) or not isinstance(manifest, dict):
        raise PanelError("пакет панели неполон")
    decoded: dict[str, bytes] = {}
    for name, text in files.items():
        if not isinstance(name, str) or not isinstance(text, str):
            raise PanelError("файл пакета имеет неверный тип")
        decoded[name] = text.encode("utf-8")
    return decoded, manifest


def sync_once(
    fetch: Fetch,
    store: ConfigStore,
    state_dir: Path,
    apply: Apply,
    report: Report,
    *,
    drain_setter: Callable[[bool], None] | None = None,
) -> SyncResult:
    """Один проход синхронизации."""
    result = SyncResult()
    try:
        data = fetch()
    except PanelError as error:
        result.panel_reachable = False
        result.detail = str(error)
        return result

    # Слив первым и независимо от конфигурации.
    wanted = data.get("drain")
    if isinstance(wanted, bool) and wanted != is_draining(state_dir):
        (drain_setter or (lambda on: set_drain(on, state_dir=state_dir)))(wanted)
        result.drain_changed = True
        report("drain", {"draining": wanted})

    try:
        parsed = _bundle_from(data)
    except PanelError as error:
        result.detail = str(error)
        report("config_applied", {"outcome": "REJECTED", "detail": str(error)[:300]})
        return result
    if parsed is None:
        return result
    files, manifest = parsed
    if manifest.get("checksum") == store.active_checksum():
        return result  # уже применено

    applied = apply(files, manifest)
    result.applied = applied.outcome is Outcome.ACTIVE
    result.outcome = applied.outcome.value
    result.detail = applied.message[:300]
    if result.applied:
        write_recipient_meta(manifest.get("recipients"), state_dir)
    report(
        "config_applied",
        {
            "outcome": applied.outcome.value,
            "stage": applied.stage.value,
            "version": str(manifest.get("version", ""))[:32],
            "checksum": str(manifest.get("checksum", ""))[:64],
            "detail": applied.message[:300],
        },
    )
    return result


def detect_drift(store: ConfigStore) -> dict[str, object] | None:
    """Расхождение файлов на диске с принятым описанием (ТЗ §40); ``None`` — расхождения нет."""
    active, disk = store.active_checksum(), store.drift_checksum()
    if active is None or disk is None or active == disk:
        return None
    return {"expected": active[:64], "found": disk[:64]}


def drift_state(store: ConfigStore) -> bool | None:
    """``True`` — расхождение, ``False`` — нет, ``None`` — сравнить не с чем (конфигурации ещё нет)."""
    active, disk = store.active_checksum(), store.drift_checksum()
    if active is None or disk is None:
        return None
    return active != disk


def default_apply(store: ConfigStore, **kwargs: Any) -> Apply:
    def run(files: dict[str, bytes], manifest: dict[str, Any]) -> ApplyResult:
        return apply_bundle(files, manifest, store, **kwargs)

    return run
