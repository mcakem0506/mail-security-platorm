"""Run the golden dataset against the detection engine (ТЗ 1.0.3 §4, §9, §57).

This is what CI runs to block a detection regression, and what a detection engineer runs before
proposing a rule change.

Usage::

    python scripts/evaluate_detection.py                      # evaluate and print a summary
    python scripts/evaluate_detection.py --gate               # apply the release gate
    python scripts/evaluate_detection.py --markdown report.md
    python scripts/evaluate_detection.py --json result.json
    python scripts/evaluate_detection.py --update-baseline    # accept current results as the baseline
    python scripts/evaluate_detection.py --rules path/to/rules

Exit code is 1 when the gate blocks, so it can gate a pipeline step directly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

from msp_contracts import (  # noqa: E402
    ProtectedCategory,
    Severity,
    TrustedMailHop,
)
from msp_detection import (  # noqa: E402
    AnalysisContext,
    DirectoryUser,
    GatewayFindings,
    ProtectedIdentity,
)
from msp_detection.rules import RuleSet, find_rule_pack  # noqa: E402
from msp_detection_eval import (  # noqa: E402
    Baseline,
    EvaluationRunner,
    GateThresholds,
    check,
    render_markdown,
    render_text,
)
from msp_detection_eval.corpus import build_golden_dataset  # noqa: E402
from msp_mail_gateway import (  # noqa: E402
    GatewayProviderConfig,
    GatewayRegistry,
    KsmgGatewayProvider,
)

CORP = "corp.example"
DEFAULT_BASELINE = REPO_ROOT / "datasets" / "baseline.json"
DEFAULT_GATE = REPO_ROOT / "datasets" / "detection_gate.yaml"


def evaluation_context() -> AnalysisContext:
    """The organisation the golden corpus is written against.

    Its topology is described in full — gateway *and* mail relay — because a half-described
    topology produces a tampering signal on ordinary mail, and an evaluation run against that
    would measure the configuration rather than the rules (ТЗ 1.0.1 §4.3).
    """
    return AnalysisContext(
        organization_id="evaluation",
        organization_name="Corp",
        corporate_domains=(CORP,),
        trusted_infrastructure_domains=("mailer.trusted-service.example",),
        protected_identities=(
            ProtectedIdentity(
                "pi-ceo",
                "Иван Петров",
                f"ceo@{CORP}",
                (ProtectedCategory.EXECUTIVE,),
                risk_class="critical",
                vip=True,
            ),
            ProtectedIdentity(
                "pi-cfo",
                "Мария Кузнецова",
                f"cfo@{CORP}",
                (ProtectedCategory.FINANCE,),
                risk_class="high",
            ),
            ProtectedIdentity(
                "pi-hr", "Анна Петрова", f"hr@{CORP}", (ProtectedCategory.HR,), risk_class="high"
            ),
            ProtectedIdentity(
                "pi-it",
                "Сергей Иванов",
                f"it-admin@{CORP}",
                (ProtectedCategory.ADMINISTRATOR,),
                risk_class="critical",
            ),
        ),
        directory_users=tuple(
            DirectoryUser(f"{local}@{CORP}", display, department=department)
            for display, local, department in [
                ("Сергей Иванов", "ivanov", "ИТ"),
                ("Анна Петрова", "petrova", "Отдел кадров"),
                ("Пётр Сидоров", "sidorov", "Закупки"),
                ("Ольга Морозова", "morozova", "Финансовый отдел"),
                ("Дмитрий Волков", "volkov", "Коммерческий отдел"),
                ("Елена Соколова", "sokolova", "Юридический отдел"),
                ("Алексей Новиков", "novikov", "ИТ"),
                ("Наталья Зайцева", "zaytseva", "Финансовый отдел"),
                ("Бухгалтерия", "buh", "Финансовый отдел"),
            ]
        ),
        recipient_department="Финансовый отдел",
    )


def gateway_registry() -> GatewayRegistry:
    """The organisation's mail path: gateway in front, relay behind."""
    return GatewayRegistry(
        [
            KsmgGatewayProvider(
                GatewayProviderConfig(
                    provider_id="ksmg",
                    provider_type="ksmg",
                    display_name="KSMG",
                    trusted_hops=[
                        TrustedMailHop(
                            id="hop-ksmg",
                            provider_id="ksmg",
                            hostname=f"ksmg-01.{CORP}",
                            ip_networks=["10.20.0.0/24"],
                            authserv_ids=[f"ksmg-01.{CORP}"],
                        )
                    ],
                )
            )
        ],
        extra_hops=[
            TrustedMailHop(
                id="hop-relay",
                type="exchange_mailbox",
                hostname=f"mx.{CORP}",
                authserv_ids=[f"mx.{CORP}"],
            )
        ],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Оценка качества детектирования (ТЗ 1.0.3)")
    parser.add_argument("--rules", help="каталог с правилами (по умолчанию — найденный пакет)")
    parser.add_argument("--gate", action="store_true", help="применить релизный гейт")
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    parser.add_argument("--thresholds", default=str(DEFAULT_GATE))
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--markdown", metavar="FILE")
    parser.add_argument("--json", metavar="FILE")
    parser.add_argument("--version", default="2026.09.1")
    args = parser.parse_args()

    ruleset = RuleSet.from_directory(args.rules) if args.rules else RuleSet.from_directory(find_rule_pack())
    dataset, messages = build_golden_dataset(args.version)

    problems = dataset.validate()
    if problems:
        print("Датасет не прошёл проверку:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    # Gateway trust is decided per message: a header is forged only relative to that message's
    # own delivery chain, so findings are computed per case rather than once for the run.
    registry = gateway_registry()

    def findings_for(parsed):  # type: ignore[no-untyped-def]
        analysis = registry.analyze_message(
            parsed.headers,
            received=parsed.received,
            authentication_results=parsed.authentication_results,
            internet_message_id=parsed.message_id,
        )
        verification = analysis.verification
        return GatewayFindings(
            evidence=list(analysis.evidence),
            state=analysis.state,
            trusted_auth_results=list(analysis.trusted_auth_results),
            untrusted_auth_results=list(analysis.untrusted_auth_results),
            auth_tampering_suspected=analysis.auth_tampering_suspected,
            unverified_gateways=list(analysis.untrusted_gateways),
            position_mismatches=list(verification.position_mismatches) if verification else [],
            chain_verified=bool(verification and verification.matches),
        )

    runner = EvaluationRunner(
        ruleset=ruleset,
        context=evaluation_context(),
        resolver=lambda reference: messages[reference],
        findings_factory=findings_for,
    )
    result = runner.run(dataset)

    gate_result = None
    if args.gate:
        thresholds = (
            GateThresholds.load(args.thresholds) if Path(args.thresholds).is_file() else GateThresholds()
        )
        # Zero-weight rules carry context rather than detection, so they are exempt from the
        # noise check: "sender not seen before" is meant to fire on most mail.
        zero_weight = frozenset(
            rule.id for rule in ruleset.rules if rule.effective_weight == 0 or rule.severity is Severity.INFO
        )
        gate_result = check(result, thresholds, Baseline.load(args.baseline), zero_weight_rules=zero_weight)

    print(render_text(result, gate_result))

    if args.markdown:
        Path(args.markdown).write_text(render_markdown(result, gate_result), encoding="utf-8")
        print(f"\nMarkdown-отчёт: {args.markdown}")
    if args.json:
        Path(args.json).write_text(
            json.dumps(result.as_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"JSON-отчёт: {args.json}")

    if args.update_baseline:
        target = Baseline.from_result(result).write(args.baseline)
        print(f"Базовая линия обновлена: {target}")

    if gate_result is not None and not gate_result.passed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
