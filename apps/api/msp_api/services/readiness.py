"""Deployment readiness: what this environment actually supports (ТЗ 1.0.1 §4.6, §12).

The probe answers the questions a written inventory was previously used for, by asking the live
environment instead: which endpoint, which authentication method, which Exchange build, which
EWS capabilities, whether the service mailbox is reachable, whether a pilot mailbox can be read,
and which prerequisites the Outlook add-in still needs.

Everything here is read-only. Remediation is reported as a *capability* — whether the platform
could act — and is never exercised: a probe that quarantined a message to prove it could would
be worse than no probe.

The outcome is one of three values, and the middle one is not a soft pass: READY_WITH_WARNINGS
means the deployment can start a shadow pilot while specific, listed items remain open.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from msp_contracts import utcnow

logger = logging.getLogger(__name__)


class Readiness(StrEnum):
    READY = "READY"
    READY_WITH_WARNINGS = "READY_WITH_WARNINGS"
    NOT_READY = "NOT_READY"


class CheckResult(StrEnum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class Check:
    """One probed fact. ``blocker`` marks a failure that prevents the pilot from starting."""

    name: str
    result: CheckResult
    detail: str = ""
    blocker: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "result": self.result.value,
            "detail": self.detail,
            "blocker": self.blocker,
            "evidence": self.evidence,
        }


@dataclass
class ProbeReport:
    section: str
    checks: list[Check] = field(default_factory=list)

    def add(
        self,
        name: str,
        result: CheckResult,
        detail: str = "",
        *,
        blocker: bool = False,
        **evidence: Any,
    ) -> Check:
        check = Check(name=name, result=result, detail=detail, blocker=blocker, evidence=evidence)
        self.checks.append(check)
        return check

    @property
    def blockers(self) -> list[Check]:
        return [c for c in self.checks if c.blocker and c.result is CheckResult.FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.result is CheckResult.WARN]

    def as_dict(self) -> dict[str, Any]:
        return {"section": self.section, "checks": [c.as_dict() for c in self.checks]}


@dataclass
class ReadinessReport:
    sections: list[ProbeReport] = field(default_factory=list)
    generated_at: datetime = field(default_factory=utcnow)
    environment: str = ""
    commit: str = ""

    def section(self, name: str) -> ProbeReport:
        report = ProbeReport(section=name)
        self.sections.append(report)
        return report

    @property
    def blockers(self) -> list[Check]:
        return [check for section in self.sections for check in section.blockers]

    @property
    def warnings(self) -> list[Check]:
        return [check for section in self.sections for check in section.warnings]

    def decision(self) -> Readiness:
        """A blocker means NOT_READY. Warnings alone allow a shadow pilot to start."""
        if self.blockers:
            return Readiness.NOT_READY
        return Readiness.READY_WITH_WARNINGS if self.warnings else Readiness.READY

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision().value,
            "generated_at": self.generated_at.isoformat(),
            "environment": self.environment,
            "commit": self.commit,
            "blockers": [c.as_dict() for c in self.blockers],
            "warnings": [c.as_dict() for c in self.warnings],
            "sections": [s.as_dict() for s in self.sections],
        }

    def as_markdown(self) -> str:
        """A report that can be pasted straight into the acceptance document (ТЗ 1.0.1 §7)."""
        symbols = {
            CheckResult.OK: "OK",
            CheckResult.WARN: "ПРЕДУПРЕЖДЕНИЕ",
            CheckResult.FAIL: "ОШИБКА",
            CheckResult.SKIP: "не проверялось",
        }
        lines = [
            "# Отчёт о готовности среды",
            "",
            f"**Решение:** `{self.decision().value}`",
            f"**Сформирован:** {self.generated_at.isoformat(timespec='seconds')}",
        ]
        if self.environment:
            lines.append(f"**Окружение:** {self.environment}")
        if self.commit:
            lines.append(f"**Версия:** `{self.commit}`")
        lines.append("")

        if self.blockers:
            lines += ["## Блокеры", ""]
            lines += [f"- **{c.name}** — {c.detail}" for c in self.blockers]
            lines.append("")
        if self.warnings:
            lines += ["## Предупреждения", ""]
            lines += [f"- **{c.name}** — {c.detail}" for c in self.warnings]
            lines.append("")

        lines += ["## Результаты проверок", ""]
        for section in self.sections:
            lines += [f"### {section.section}", "", "| Проверка | Результат | Детали |", "|---|---|---|"]
            for check in section.checks:
                detail = (check.detail or "").replace("|", "\\|")
                lines.append(f"| {check.name} | {symbols[check.result]} | {detail} |")
            lines.append("")

        lines += [
            "## Что означает решение",
            "",
            "- `READY` — среда полностью проверена, блокеров и замечаний нет.",
            "- `READY_WITH_WARNINGS` — теневой пилот можно начинать; перечисленные выше замечания "
            "остаются открытыми и должны быть закрыты до контролируемого развёртывания.",
            "- `NOT_READY` — есть блокеры: пилот начинать нельзя.",
            "",
            "Проверка выполняется только на чтение. Возможность реагирования проверяется как "
            "право доступа и никогда не выполняется.",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------------------------
def probe_exchange(settings: Any, report: ReadinessReport, *, pilot_mailbox: str = "") -> None:
    """EWS endpoint, TLS, authentication, build and capabilities (ТЗ 1.0.1 §4.6)."""
    section = report.section("Exchange / EWS")
    from msp_exchange.ews import EwsAccessMode, EwsAuthMethod, EwsConfig, OnPremEwsExchangeProvider

    config = EwsConfig(
        endpoint=settings.ews_endpoint,
        autodiscover=settings.ews_autodiscover,
        primary_smtp_address=settings.ews_primary_smtp_address or settings.ews_username,
        username=settings.ews_username,
        password=settings.ews_password,
        auth_method=EwsAuthMethod(settings.ews_auth_method),
        auth_preference=tuple(EwsAuthMethod(m) for m in settings.ews_auth_preference_list),
        allow_basic_auth=settings.ews_allow_basic_auth,
        access_mode=EwsAccessMode(settings.ews_access_mode),
        verify_tls=settings.ews_verify_tls,
        ca_file=settings.ews_ca_file,
        timeout_seconds=settings.ews_timeout_seconds,
        mailbox_scope=settings.ews_mailbox_scope_list,
        remediation_account_enabled=settings.remediation_enabled,
    )

    if not config.configured:
        section.add(
            "Подключение EWS",
            CheckResult.SKIP,
            "EWS не настроен. Платформа работает через security mailbox и надстройку Outlook — "
            "это поддерживаемая конфигурация, а не ошибка.",
        )
        return

    section.add(
        "Способ определения endpoint",
        CheckResult.OK,
        "Autodiscover" if not settings.ews_endpoint else f"явный адрес {settings.ews_endpoint}",
        autodiscover=settings.ews_autodiscover,
    )
    section.add(
        "Проверка TLS",
        CheckResult.OK if config.verify_tls else CheckResult.FAIL,
        "включена" if config.verify_tls else "отключена: по этому каналу передаются учётные данные",
        blocker=not config.verify_tls,
        ca_file=config.ca_file,
    )

    provider = OnPremEwsExchangeProvider(config)
    allowed = [m.value for m in provider.auth_order()]
    section.add(
        "Разрешённые способы аутентификации",
        CheckResult.OK if allowed else CheckResult.FAIL,
        ", ".join(allowed) or "ни одного: Basic отключён, другие не настроены",
        blocker=not allowed,
        order=allowed,
    )
    if settings.ews_allow_basic_auth:
        section.add(
            "Basic-аутентификация",
            CheckResult.WARN,
            "включена явно: пароль сервисной учётной записи передаётся при каждом запросе. "
            "Готовность остаётся degraded до отдельного согласования.",
        )

    try:
        capability_report = provider.discover()
    except RuntimeError as exc:  # exchangelib absent
        section.add("Подключение EWS", CheckResult.SKIP, str(exc)[:200])
        return
    except Exception as exc:  # noqa: BLE001 - a probe reports failures, it does not raise them
        section.add("Подключение EWS", CheckResult.FAIL, type(exc).__name__, blocker=True)
        return

    if not capability_report.reachable:
        section.add(
            "Подключение EWS",
            CheckResult.FAIL,
            "; ".join(capability_report.errors[:2]) or "недоступен",
            blocker=True,
        )
        return

    section.add(
        "Подключение EWS",
        CheckResult.OK,
        f"{capability_report.server_version} через {capability_report.auth_method}",
        endpoint=capability_report.endpoint,
    )
    section.add(
        "Версия и сборка Exchange",
        CheckResult.OK,
        f"{capability_report.server_version} (build {capability_report.server_build})",
        note="версия определяется сервером и не влияет на логику адаптера",
    )
    section.add("Режим доступа к ящикам", CheckResult.OK, config.access_mode.value)

    capabilities = {c.value for c in capability_report.capabilities}
    for capability, label, required in (
        ("get_message", "Чтение MIME письма", True),
        ("get_headers", "Чтение заголовков", True),
        ("get_attachments", "Чтение вложений", False),
        ("search", "Поиск по ящикам", False),
    ):
        present = capability in capabilities
        section.add(
            label,
            CheckResult.OK if present else (CheckResult.FAIL if required else CheckResult.WARN),
            "доступно" if present else "недоступно в этой конфигурации",
            blocker=required and not present,
        )

    # Remediation is reported as an access right, never exercised (ТЗ 1.0.1 §8).
    if not settings.remediation_enabled:
        section.add(
            "Возможность реагирования",
            CheckResult.OK,
            "реагирование отключено — требование теневого пилота (dry_run_only)",
        )
    elif not settings.ews_mailbox_scope_list:
        section.add(
            "Область ящиков для реагирования",
            CheckResult.FAIL,
            "реагирование включено без явной области: развёртывание могло бы затронуть любой ящик",
            blocker=True,
        )
    else:
        section.add(
            "Возможность реагирования",
            CheckResult.WARN,
            f"включено для {len(settings.ews_mailbox_scope_list)} ящик(ов)/домен(ов); "
            "на этапе пилота должно быть отключено",
            scope=list(settings.ews_mailbox_scope_list),
        )

    if pilot_mailbox:
        _probe_pilot_mailbox(provider, pilot_mailbox, section)

    for blocker in provider.blockers():
        section.add("Замечание конфигурации", CheckResult.WARN, blocker)


def _probe_pilot_mailbox(provider: Any, mailbox: str, section: ProbeReport) -> None:
    """Confirm read access to one pilot mailbox without reading any message content."""
    from msp_exchange.base import CapabilityUnavailable
    from msp_exchange.ews import MailboxOutOfScope

    try:
        provider._account_for(mailbox)
    except MailboxOutOfScope:
        section.add(
            "Доступ к пилотному ящику",
            CheckResult.FAIL,
            f"{mailbox} вне заданной области MSP_EWS_MAILBOX_SCOPE",
            blocker=True,
        )
    except CapabilityUnavailable as exc:
        section.add("Доступ к пилотному ящику", CheckResult.WARN, str(exc)[:200])
    except Exception as exc:  # noqa: BLE001
        section.add("Доступ к пилотному ящику", CheckResult.FAIL, type(exc).__name__, blocker=True)
    else:
        section.add("Доступ к пилотному ящику", CheckResult.OK, mailbox)


def probe_security_mailbox(settings: Any, report: ReadinessReport) -> None:
    section = report.section("Security mailbox")
    if not settings.security_mailbox_host:
        section.add(
            "Security mailbox",
            CheckResult.FAIL if settings.exchange_provider == "security_mailbox" else CheckResult.WARN,
            "не настроен: без него и без EWS письма в платформу не попадают",
            blocker=settings.exchange_provider == "security_mailbox",
        )
        return

    from msp_exchange import SecurityMailboxConfig, SecurityMailboxProvider

    provider = SecurityMailboxProvider(
        SecurityMailboxConfig(
            host=settings.security_mailbox_host,
            port=settings.security_mailbox_port,
            username=settings.security_mailbox_user,
            password=settings.security_mailbox_password,
            folder=settings.security_mailbox_folder,
            use_ssl=settings.security_mailbox_ssl,
            ca_file=settings.security_mailbox_ca_file,
            max_message_size=settings.limit_message_size,
        )
    )
    health = provider.health()
    section.add(
        "Подключение к почтовому ящику",
        {"ok": CheckResult.OK, "degraded": CheckResult.WARN}.get(health.status, CheckResult.FAIL),
        health.detail or health.status,
        blocker=health.status == "unavailable",
    )
    section.add(
        "Папки Processed и Failed",
        CheckResult.OK,
        f"{provider.config.processed_folder} / {provider.config.failed_folder} "
        "(создаются автоматически при первом использовании)",
    )


def probe_directory(settings: Any, report: ReadinessReport) -> None:
    section = report.section("Active Directory")
    if not settings.ad_server:
        section.add("Active Directory", CheckResult.SKIP, "не настроен")
        return

    from msp_ad import ActiveDirectoryAuthenticator, AdAuthConfig, parse_group_role_map

    if settings.ad_use_ssl or settings.ad_start_tls:
        section.add("LDAPS / StartTLS", CheckResult.OK, "включено")
    else:
        section.add(
            "LDAPS / StartTLS",
            CheckResult.FAIL,
            "LDAP без TLS: пароли пользователей передавались бы открытым текстом",
            blocker=True,
        )
    if not settings.ad_verify_tls:
        section.add(
            "Проверка сертификата контроллера домена",
            CheckResult.FAIL,
            "отключена: канал, по которому передаются пароли, не аутентифицирован",
            blocker=True,
        )

    authenticator = ActiveDirectoryAuthenticator(
        AdAuthConfig(
            server=settings.ad_server,
            port=settings.ad_port,
            use_ssl=settings.ad_use_ssl,
            start_tls=settings.ad_start_tls,
            bind_dn=settings.ad_bind_dn,
            bind_password=settings.ad_bind_password,
            base_dn=settings.ad_base_dn,
            group_role_map=parse_group_role_map(settings.ad_group_role_map),
            ca_file=settings.ad_ca_file,
            verify_tls=settings.ad_verify_tls,
            timeout_seconds=settings.ad_timeout_seconds,
        )
    )
    health = authenticator.health()
    section.add(
        "Подключение к каталогу",
        {"ok": CheckResult.OK, "degraded": CheckResult.WARN, "not_configured": CheckResult.SKIP}.get(
            health["status"], CheckResult.FAIL
        ),
        health.get("detail") or health["status"],
        blocker=health["status"] == "unavailable",
    )
    if health.get("base_dn"):
        section.add("Base DN (RootDSE)", CheckResult.OK, str(health["base_dn"]))
    if settings.auth_backend == "ldap" and not settings.ad_group_role_map:
        section.add(
            "Сопоставление групп и ролей",
            CheckResult.WARN,
            f"не задано: все пользователи получат роль по умолчанию ({settings.ad_default_role})",
        )
    for problem in health.get("problems", []):
        section.add("Замечание каталога", CheckResult.WARN, str(problem))


def probe_mail_flow(settings: Any, report: ReadinessReport, *, registry: Any = None) -> None:
    """Trusted hops and gateways (ТЗ 1.0.1 §4.3, §4.4)."""
    section = report.section("Почтовый поток и шлюзы")
    hops = list(registry.hops()) if registry is not None else []
    providers = list(registry.providers) if registry is not None else []

    if not providers:
        section.add(
            "Внешний почтовый шлюз",
            CheckResult.OK,
            "не настроен (gateway_state=NOT_PRESENT). Это поддерживаемая конфигурация: "
            "платформа работает без SEG.",
        )
    else:
        section.add(
            "Настроенные шлюзы",
            CheckResult.OK,
            ", ".join(f"{p.provider_id} ({p.provider_type})" for p in providers),
        )
        for health in registry.health():
            section.add(
                f"Состояние шлюза {health.provider_id}",
                {"ok": CheckResult.OK, "disabled": CheckResult.SKIP}.get(health.status, CheckResult.WARN),
                health.detail or health.status,
            )

    if providers and not hops:
        section.add(
            "Доверенные узлы (TrustedMailHop)",
            CheckResult.WARN,
            "шлюз настроен, но ни один узел не описан: его заголовки будут показываться "
            "аналитику и не будут учитываться, так как прохождение через шлюз нечем подтвердить",
        )
    elif hops:
        section.add(
            "Доверенные узлы (TrustedMailHop)",
            CheckResult.OK,
            f"{len(hops)} узел(ов)",
            hostnames=[h.hostname for h in hops if h.hostname][:10],
        )

    authserv = {a for hop in hops for a in hop.authserv_ids} | set(settings.trusted_authserv_id_list)
    section.add(
        "Доверенные authserv-id",
        CheckResult.OK if authserv else CheckResult.WARN,
        ", ".join(sorted(authserv))
        or "не заданы: заголовки Authentication-Results читаются без проверки источника",
    )
    if not settings.internal_mail_network_list:
        section.add(
            "Внутренние сети почтового потока",
            CheckResult.WARN,
            "не заданы (MSP_INTERNAL_MAIL_NETWORKS): последний внешний hop определяется "
            "по крайнему звену цепочки",
        )


def probe_addin_prerequisites(settings: Any, report: ReadinessReport) -> None:
    """What the Outlook add-in needs before it can be deployed (ТЗ 1.0.1 §4.6)."""
    section = report.section("Надстройка Outlook")
    base_url = (settings.public_base_url or "").strip()
    if not base_url:
        section.add("Базовый адрес платформы", CheckResult.FAIL, "MSP_PUBLIC_BASE_URL не задан", blocker=True)
    elif not base_url.lower().startswith("https://"):
        section.add(
            "Базовый адрес платформы",
            CheckResult.FAIL,
            f"{base_url}: Outlook загружает надстройку только по HTTPS",
            blocker=True,
        )
    else:
        section.add("Базовый адрес платформы", CheckResult.OK, base_url)

    section.add(
        "Сертификат для надстройки",
        CheckResult.OK if base_url.lower().startswith("https://") else CheckResult.WARN,
        "сертификат должен быть доверенным на клиентских машинах; самоподписанный "
        "потребует установки в хранилище доверенных корневых центров",
    )
    section.add(
        "Совместимость Outlook",
        CheckResult.OK,
        "Outlook 2016 и новее, OWA — надстройка использует Office.js и не зависит от версии Exchange",
    )
    if not settings.cookie_secure:
        section.add(
            "Защищённые cookie",
            CheckResult.WARN,
            "MSP_COOKIE_SECURE отключён: допустимо только в лабораторной среде",
        )


def probe_pilot_policy(settings: Any, report: ReadinessReport) -> None:
    """Shadow-pilot constraints of ТЗ 1.0.1 §8."""
    section = report.section("Режим пилота")
    if settings.remediation_enabled and not settings.remediation_dry_run_only:
        section.add(
            "Автоматическое реагирование",
            CheckResult.FAIL,
            "реагирование включено не в режиме dry-run: теневой пилот запрещает изменение почты",
            blocker=True,
        )
    else:
        section.add(
            "Автоматическое реагирование",
            CheckResult.OK,
            "отключено или только dry-run — требование теневого пилота",
        )
    section.add(
        "Изменение mail flow",
        CheckResult.OK,
        "платформа не участвует в доставке: транспортные агенты и правила Exchange не изменяются",
    )
    if settings.environment == "production" and settings.debug:
        section.add("Режим отладки", CheckResult.FAIL, "debug включён в production", blocker=True)


def run_probe(settings: Any, *, pilot_mailbox: str = "", registry: Any = None) -> ReadinessReport:
    """Run every probe. Individual failures are reported, never raised."""
    report = ReadinessReport(environment=settings.environment)
    for probe in (
        lambda: probe_exchange(settings, report, pilot_mailbox=pilot_mailbox),
        lambda: probe_security_mailbox(settings, report),
        lambda: probe_directory(settings, report),
        lambda: probe_mail_flow(settings, report, registry=registry),
        lambda: probe_addin_prerequisites(settings, report),
        lambda: probe_pilot_policy(settings, report),
    ):
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 - one broken probe must not hide the others
            logger.warning("readiness.probe_failed", extra={"error": type(exc).__name__})
            report.section("Ошибка проверки").add(
                "Проверка не выполнена", CheckResult.WARN, type(exc).__name__
            )
    return report
