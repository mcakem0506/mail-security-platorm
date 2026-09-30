"""Read-only environment probe and compatibility report (ТЗ 1.0.1 §4.6, ТЗ 44, 51).

Run this at the customer site instead of collecting an environment inventory in writing. It
connects with the configured credentials, reports what the environment actually supports, and
prints a decision of READY, READY_WITH_WARNINGS or NOT_READY with the specific items behind it.

Nothing is changed. Remediation is reported as an access right and is never exercised: a probe
that quarantined a message to prove it could would be worse than no probe at all.

Usage::

    python scripts/probe_exchange.py                          # human-readable report
    python scripts/probe_exchange.py --json                   # machine-readable
    python scripts/probe_exchange.py --markdown report.md     # for the acceptance document
    python scripts/probe_exchange.py --pilot-mailbox user@corp.example
    python scripts/probe_exchange.py --section exchange --section directory

The exit code is 0 for READY and READY_WITH_WARNINGS, and 1 for NOT_READY, so the probe can gate
a deployment step in CI or a runbook.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from msp_api.config import get_settings
from msp_api.services.readiness import (
    CheckResult,
    Readiness,
    ReadinessReport,
    probe_addin_prerequisites,
    probe_directory,
    probe_exchange,
    probe_mail_flow,
    probe_pilot_policy,
    probe_security_mailbox,
)

_LABELS = {
    CheckResult.OK: "  OK  ",
    CheckResult.WARN: " ПРЕД ",
    CheckResult.FAIL: " ОШИБ ",
    CheckResult.SKIP: " ПРОП ",
}

SECTIONS = ("exchange", "mailbox", "directory", "mailflow", "addin", "pilot")


def _registry(settings: Any) -> Any:
    """The gateway registry, where a database is reachable.

    The probe is useful before the database exists, so a failure here degrades the mail-flow
    section rather than the whole report.
    """
    try:
        from msp_api.db.models import Organization
        from msp_api.db.session import session_scope
        from msp_api.services.gateways import build_registry
        from sqlalchemy import select

        with session_scope() as session:
            org = session.execute(select(Organization)).scalars().first()
            if org is None:
                return None
            return build_registry(session, settings, org.id)
    except Exception:  # noqa: BLE001 - the probe must work without a database
        return None


def render_text(report: ReadinessReport) -> str:
    lines = ["Проверка готовности среды Mail Security Platform", "=" * 70]
    for section in report.sections:
        lines.append(f"\n{section.section}")
        lines.append("-" * 70)
        for check in section.checks:
            suffix = f" — {check.detail}" if check.detail else ""
            lines.append(f"[{_LABELS[check.result]}] {check.name}{suffix}")
    lines.append("\n" + "=" * 70)
    decision = report.decision()
    lines.append(f"Решение: {decision.value}")
    if report.blockers:
        lines.append(f"\nБлокеры ({len(report.blockers)}):")
        lines += [f"  - {c.name}: {c.detail}" for c in report.blockers]
    if report.warnings:
        lines.append(f"\nЗамечания ({len(report.warnings)}):")
        lines += [f"  - {c.name}: {c.detail}" for c in report.warnings]
    if decision is Readiness.READY_WITH_WARNINGS:
        lines.append(
            "\nТеневой пилот можно начинать. Перечисленные замечания остаются открытыми и "
            "должны быть закрыты до контролируемого развёртывания."
        )
    elif decision is Readiness.NOT_READY:
        lines.append("\nПилот начинать нельзя: сначала закройте блокеры.")
    lines.append("\nПодробности: docs/EXCHANGE_PROBE_GUIDE.md")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка готовности среды (ТЗ 1.0.1 §4.6)")
    parser.add_argument("--json", action="store_true", help="машиночитаемый вывод")
    parser.add_argument("--markdown", metavar="FILE", help="записать отчёт в Markdown")
    parser.add_argument("--pilot-mailbox", default="", help="проверить доступ к ящику пилота")
    parser.add_argument(
        "--section",
        action="append",
        choices=SECTIONS,
        help="проверить только указанные разделы (можно повторять)",
    )
    args = parser.parse_args()

    settings = get_settings()
    selected = set(args.section or SECTIONS)
    report = ReadinessReport(environment=settings.environment)

    if "exchange" in selected:
        probe_exchange(settings, report, pilot_mailbox=args.pilot_mailbox)
    if "mailbox" in selected:
        probe_security_mailbox(settings, report)
    if "directory" in selected:
        probe_directory(settings, report)
    if "mailflow" in selected:
        probe_mail_flow(settings, report, registry=_registry(settings))
    if "addin" in selected:
        probe_addin_prerequisites(settings, report)
    if "pilot" in selected:
        probe_pilot_policy(settings, report)

    if args.markdown:
        Path(args.markdown).write_text(report.as_markdown(), encoding="utf-8")
    if args.json:
        print(json.dumps(report.as_dict(), ensure_ascii=False, indent=2, default=str))
    else:
        print(render_text(report))
        if args.markdown:
            print(f"\nMarkdown-отчёт записан: {args.markdown}")

    return 1 if report.decision() is Readiness.NOT_READY else 0


if __name__ == "__main__":
    sys.exit(main())
