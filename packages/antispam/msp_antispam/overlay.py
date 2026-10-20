"""Сведение локальной конфигурации узла с назначением панели (ТЗ 1.2 §22, §27, §31).

Панель назначает сканеру то, что связано с политикой: пороги, провайдеров репутации, домены с
действующими ключами подписи и флаги Bayes/greylisting. Остальное определяет только узел:

* сети, которые вправе получать подпись (``sign_networks``) — панель их не расширяет;
* адреса DNS, Redis, пароль контроллера, каталог секретов;
* наличие закрытого ключа: домен без файла ключа на узле в конфигурацию не попадает, и это
  сообщается панели (``dkim_missing_keys``), а не молча игнорируется.

Назначение проходит ту же проверку модели, что и локальная конфигурация: произвольный UCL или Lua из
панели принят быть не может.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .providers import ReputationProvider
from .rspamd_config import (
    BayesSettings,
    ConfigError,
    DkimSigning,
    RspamdNodeConfig,
    SigningDomain,
    Thresholds,
)


@dataclass
class MergeResult:
    config: RspamdNodeConfig
    missing_keys: list[str] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)


def merge(
    base: RspamdNodeConfig, overlay: Mapping[str, Any], *, key_exists: Callable[[str], bool] | None = None
) -> MergeResult:
    """Новая конфигурация узла. Ошибка модели не подавляется: назначение, не прошедшее проверку,
    не применяется, а узел остаётся на прежней версии."""
    exists = key_exists or (lambda path: Path(path).is_file())
    ignored: list[str] = []
    missing: list[str] = []
    update: dict[str, Any] = {}

    thresholds = overlay.get("thresholds")
    if isinstance(thresholds, Mapping):
        update["thresholds"] = Thresholds.model_validate(dict(thresholds))

    providers_raw = overlay.get("providers")
    if isinstance(providers_raw, list):
        update["providers"] = tuple(ReputationProvider.model_validate(item) for item in providers_raw)

    domains: list[SigningDomain] = []
    for item in overlay.get("signing_domains") or []:
        domain = SigningDomain.model_validate(item)
        if exists(domain.private_key_file):
            domains.append(domain)
        else:
            missing.append(f"{domain.domain}:{domain.selector}")
    if domains:
        if not base.dkim_signing.sign_networks:
            ignored.append("signing_domains: на узле не заданы доверенные сети подписи")
        else:
            update["dkim_signing"] = DkimSigning(
                enabled=True, sign_networks=base.dkim_signing.sign_networks, domains=tuple(domains)
            )
    else:
        update["dkim_signing"] = DkimSigning(enabled=False)

    if overlay.get("bayes_enabled"):
        if base.redis is None:
            ignored.append("bayes: на узле нет Redis")
        else:
            update["bayes"] = BayesSettings(enabled=True, min_learns=base.bayes.min_learns)
    else:
        update["bayes"] = BayesSettings(enabled=False)
    update["greylisting"] = bool(overlay.get("greylisting")) and base.redis is not None
    if overlay.get("greylisting") and base.redis is None:
        ignored.append("greylisting: на узле нет Redis")
    update["symbol_mapping_version"] = str(
        overlay.get("symbol_mapping_version") or base.symbol_mapping_version
    )[:16]
    try:
        config = base.model_copy(update=update)
        config = RspamdNodeConfig.model_validate(config.model_dump())
    except ValueError as exc:  # pydantic.ValidationError — наследник ValueError
        raise ConfigError("назначение панели не прошло проверку модели") from exc
    return MergeResult(config=config, missing_keys=missing, ignored=ignored)
