"""The organisation the golden corpus is written against (ТЗ 1.0.3 §5).

This lives here, beside the corpus, because the corpus and the environment it assumes are one
artefact. A case that expects a verdict only makes sense against a specific set of corporate
domains, protected identities and mail path, and the two cannot be allowed to drift apart.

They did drift: the CLI and the API each had their own copy, one of them named the relay
``mail.corp.example`` and the other ``mx.corp.example``, and the mismatch dropped recall from
0.990 to 0.904 — not because detection got worse, but because an unverified delivery chain made
the run measure the configuration instead of the rules. One definition, imported by both, is the
fix; the duplication was the defect.
"""

from __future__ import annotations

from msp_contracts import ProtectedCategory, TrustedMailHop
from msp_detection import AnalysisContext, DirectoryUser, GatewayFindings, ProtectedIdentity
from msp_mail_gateway import GatewayProviderConfig, GatewayRegistry, KsmgGatewayProvider

#: The corporate domain every corpus case is written against.
CORP = "corp.example"


def evaluation_context() -> AnalysisContext:
    """The organisation, described in full.

    The topology is complete — gateway *and* mail relay — because a half-described one produces
    a tampering signal on ordinary mail, and a run against that measures the configuration
    rather than the rules (ТЗ 1.0.1 §4.3).
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
                ip_networks=["10.10.0.0/24"],
                authserv_ids=[f"mx.{CORP}"],
            )
        ],
    )


def findings_factory(registry: GatewayRegistry):  # type: ignore[no-untyped-def]
    """Build the per-message gateway findings the runner needs.

    Trust is decided per message — a header is forged only relative to that message's own
    delivery chain — so this is computed per case rather than once for the run.
    """

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

    return findings_for
