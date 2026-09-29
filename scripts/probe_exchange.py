"""Environment probe for Exchange, Active Directory and the security mailbox (ТЗ 44, 51).

Run this at the customer site to collect the environment inventory instead of asking for it in
writing. It connects with the configured credentials, reports what actually works, and prints
the remaining blockers.

The probe is read-only: it opens connections, lists capabilities and reads nothing beyond a
single message header. It never writes to a mailbox or to the directory.

Usage:
    python scripts/probe_exchange.py                 # uses the configured .env
    python scripts/probe_exchange.py --json          # machine-readable output
    python scripts/probe_exchange.py --ews-only
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from msp_api.config import get_settings

OK = "  OK "
WARN = " WARN"
FAIL = " FAIL"
SKIP = " SKIP"


def line(status: str, label: str, detail: str = "") -> None:
    print(f"[{status}] {label}" + (f" — {detail}" if detail else ""))


def probe_ews(settings: Any) -> dict[str, Any]:
    from msp_exchange.ews import EwsAccessMode, EwsAuthMethod, EwsConfig, probe_environment

    config = EwsConfig(
        endpoint=settings.ews_endpoint,
        autodiscover=settings.ews_autodiscover,
        primary_smtp_address=settings.ews_primary_smtp_address or settings.ews_username,
        username=settings.ews_username,
        password=settings.ews_password,
        auth_method=EwsAuthMethod(settings.ews_auth_method),
        auth_preference=tuple(EwsAuthMethod(m) for m in settings.ews_auth_preference_list),
        access_mode=EwsAccessMode(settings.ews_access_mode),
        verify_tls=settings.ews_verify_tls,
        ca_file=settings.ews_ca_file,
        timeout_seconds=settings.ews_timeout_seconds,
        mailbox_scope=settings.ews_mailbox_scope_list,
    )
    if not config.configured:
        line(SKIP, "EWS", "не настроен; платформа работает через security mailbox")
        return {"configured": False, "blockers": config.blockers()}

    try:
        report = probe_environment(config)
    except RuntimeError as exc:  # exchangelib not installed
        line(SKIP, "EWS", str(exc))
        return {"configured": True, "error": str(exc)}

    if not report.get("reachable"):
        line(FAIL, "EWS", "; ".join(report.get("errors", [])[:2]) or "недоступен")
    else:
        line(OK, "EWS", f"{report.get('server_version', '')} через {report.get('auth_method', '')}")
        line(OK, "  endpoint", str(report.get("endpoint", "")))
        line(OK, "  режим доступа", str(report.get("access_mode", "")))
        capabilities = report.get("capabilities", [])
        for capability in ("get_message", "get_headers", "get_attachments", "search"):
            status = OK if capability in capabilities else WARN
            line(status, f"  {capability}", "" if capability in capabilities else "недоступно")
    for blocker in report.get("blockers", []):
        line(WARN, "  блокер", blocker)
    return report


def probe_directory(settings: Any) -> dict[str, Any]:
    from msp_ad import ActiveDirectoryAuthenticator, AdAuthConfig, parse_group_role_map

    if not settings.ad_server:
        line(SKIP, "Active Directory", "не настроен")
        return {"configured": False}

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
    status_map = {"ok": OK, "degraded": WARN, "unavailable": FAIL, "not_configured": SKIP}
    line(status_map.get(health["status"], WARN), "Active Directory", health.get("detail") or health["status"])
    if health.get("base_dn"):
        line(OK, "  base DN", str(health["base_dn"]))
    for problem in health.get("problems", []):
        line(WARN, "  замечание", problem)
    return health


def probe_security_mailbox(settings: Any) -> dict[str, Any]:
    from msp_exchange import SecurityMailboxConfig, SecurityMailboxProvider

    if not settings.security_mailbox_host:
        line(SKIP, "Security mailbox", "не настроен")
        return {"configured": False}

    provider = SecurityMailboxProvider(
        SecurityMailboxConfig(
            host=settings.security_mailbox_host,
            port=settings.security_mailbox_port,
            username=settings.security_mailbox_user,
            password=settings.security_mailbox_password,
            folder=settings.security_mailbox_folder,
            use_ssl=settings.security_mailbox_ssl,
            ca_file=settings.security_mailbox_ca_file,
        )
    )
    health = provider.health()
    status_map = {"ok": OK, "degraded": WARN, "unavailable": FAIL, "not_configured": SKIP}
    line(status_map.get(health.status, WARN), "Security mailbox", health.detail or health.status)
    return {"status": health.status, "detail": health.detail}


def probe_gateway(settings: Any) -> dict[str, Any]:
    gateways = settings.trusted_gateway_list
    if not gateways:
        line(
            WARN,
            "Почтовый шлюз",
            "не указан: вердикты KSMG и других шлюзов учитываться не будут (MSP_TRUSTED_GATEWAYS)",
        )
    else:
        line(OK, "Почтовый шлюз", ", ".join(gateways))
    return {"trusted_gateways": list(gateways)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка окружения перед пилотом (ТЗ 51)")
    parser.add_argument("--json", action="store_true", help="машиночитаемый вывод")
    parser.add_argument("--ews-only", action="store_true")
    parser.add_argument("--ad-only", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    results: dict[str, Any] = {}

    if not args.json:
        print("Проверка окружения Mail Security Platform")
        print("=" * 60)

    run_all = not (args.ews_only or args.ad_only)
    if args.ews_only or run_all:
        results["ews"] = probe_ews(settings)
    if args.ad_only or run_all:
        results["active_directory"] = probe_directory(settings)
    if run_all:
        results["security_mailbox"] = probe_security_mailbox(settings)
        results["gateway"] = probe_gateway(settings)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2, default=str))
        return 0

    print("=" * 60)
    blockers = [b for section in results.values() for b in (section.get("blockers") or [])]
    if blockers:
        print(f"\nОстались блокеры ({len(blockers)}):")
        for blocker in blockers:
            print(f"  - {blocker}")
        print("\nПодробности: docs/EXCHANGE_COMPATIBILITY.md")
    else:
        print("\nБлокеров не обнаружено.")
    print(
        "\nПлатформа работает и без EWS: приём писем через security mailbox и надстройку "
        "Outlook не требует ни одной возможности Exchange API."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
