"""Assembling the gateway layer for one organisation (ТЗ 1.0.2 §22, §23, §26, §28).

This is the seam between stored configuration and the vendor-neutral providers. It builds a
registry from the database, runs one message through every configured gateway under a single
trust decision, records the resulting evidence and conflicts, and hands the detection engine a
plain :class:`~msp_detection.GatewayFindings` so the engine keeps no dependency on any provider.

A deployment with no gateways configured goes through the same path and gets an empty registry:
``GatewayState.NOT_PRESENT`` is a supported state, not a failure (ТЗ 1.0.2 §31).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from msp_contracts import (
    GatewayDirection,
    GatewayEvidence,
    GatewayState,
    ProviderConflict,
    RiskLevel,
    TrustedMailHop,
)
from msp_detection import GatewayFindings
from msp_mail_gateway import (
    GatewayProviderConfig,
    GatewayRegistry,
    detect_conflicts,
)
from msp_mail_parser import ParsedMessage
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.base import utcnow
from ..db.models import (
    GatewayCapabilityState,
    GatewayConflict,
    GatewayEvidenceRecord,
    MailGateway,
    MessageTraceRecord,
    TrustedHop,
)

logger = logging.getLogger(__name__)

#: Provider types that a deployment can name in MSP_TRUSTED_GATEWAYS without any further setup.
#: They only parse headers, so the sole configuration they need is the trusted-hop topology.
_SIMPLE_TYPES = {"ksmg", "eop", "spamassassin", "generic_av"}


def _hop_from_row(row: TrustedHop) -> TrustedMailHop:
    try:
        direction = GatewayDirection(row.direction)
    except ValueError:
        direction = GatewayDirection.INBOUND
    return TrustedMailHop(
        id=row.id,
        type=row.hop_type,
        hostname=row.hostname,
        ip_networks=[str(n) for n in (row.ip_networks or [])],
        expected_headers=[str(h) for h in (row.expected_headers or [])],
        authserv_ids=[str(a) for a in (row.authserv_ids or [])],
        position_in_chain=row.position_in_chain,
        provider_id=row.gateway.provider_id if row.gateway is not None else "",
        direction=direction,
        enabled=row.enabled,
    )


def build_registry(session: Session, settings: Settings, organization_id: str) -> GatewayRegistry:
    """Build the registry for an organisation from stored configuration.

    ``MSP_TRUSTED_GATEWAYS`` remains supported as a shorthand for a deployment that has not yet
    described its topology in the console. Such a gateway is registered, but with no trusted
    hop — so its headers are parsed and shown, and are *not* believed, which is exactly the
    state §4.3 describes: naming the product is not proof the message went through it.
    """
    gateways = (
        session.execute(
            select(MailGateway).where(
                MailGateway.organization_id == organization_id, MailGateway.enabled.is_(True)
            )
        )
        .scalars()
        .all()
    )
    hop_rows = (
        session.execute(
            select(TrustedHop).where(
                TrustedHop.organization_id == organization_id, TrustedHop.enabled.is_(True)
            )
        )
        .scalars()
        .all()
    )
    hops_by_gateway: dict[str, list[TrustedMailHop]] = {}
    standalone: list[TrustedMailHop] = []
    for row in hop_rows:
        hop = _hop_from_row(row)
        if row.gateway_id:
            hops_by_gateway.setdefault(row.gateway_id, []).append(hop)
        else:
            standalone.append(hop)

    configs: list[GatewayProviderConfig] = []
    configured_ids: set[str] = set()
    for gateway in gateways:
        try:
            direction = GatewayDirection(gateway.direction)
        except ValueError:
            direction = GatewayDirection.INBOUND
        configs.append(
            GatewayProviderConfig(
                provider_id=gateway.provider_id,
                provider_type=gateway.provider_type,
                display_name=gateway.display_name or gateway.provider_id,
                enabled=gateway.enabled,
                direction=direction,
                trusted_hops=hops_by_gateway.get(gateway.id, []),
                settings=dict(gateway.settings or {}),
            )
        )
        configured_ids.add(gateway.provider_id)

    for name in settings.trusted_gateway_list:
        if name in configured_ids or name not in _SIMPLE_TYPES:
            continue
        configs.append(GatewayProviderConfig(provider_id=name, provider_type=name, display_name=name.upper()))

    return GatewayRegistry.from_configs(configs, extra_hops=standalone)


def collect_findings(
    registry: GatewayRegistry, parsed: ParsedMessage, *, platform_verdict: RiskLevel | None = None
) -> GatewayFindings:
    """Run one message through the gateway layer and produce facts for detection."""
    analysis = registry.analyze_message(
        parsed.headers,
        received=parsed.received,
        authentication_results=parsed.authentication_results,
        internet_message_id=parsed.message_id,
    )
    verification = analysis.verification
    conflicts = detect_conflicts(analysis.evidence, platform_verdict)
    return GatewayFindings(
        evidence=list(analysis.evidence),
        state=analysis.state,
        trusted_auth_results=list(analysis.trusted_auth_results),
        untrusted_auth_results=list(analysis.untrusted_auth_results),
        auth_tampering_suspected=analysis.auth_tampering_suspected,
        unverified_gateways=list(analysis.untrusted_gateways),
        missing_hops=list(verification.missing_hops) if verification else [],
        position_mismatches=list(verification.position_mismatches) if verification else [],
        chain_verified=bool(verification and verification.matches),
        conflicts=conflicts,
    )


def empty_findings() -> GatewayFindings:
    """Findings for a deployment with no gateway. Not an error state (§31)."""
    return GatewayFindings(state=GatewayState.NOT_PRESENT)


# ---------------------------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------------------------
def persist_evidence(
    session: Session, *, organization_id: str, message_id: str, evidence: list[GatewayEvidence]
) -> int:
    """Store normalised evidence. Replaces any earlier evidence for the same message."""
    existing = (
        session.execute(select(GatewayEvidenceRecord).where(GatewayEvidenceRecord.message_id == message_id))
        .scalars()
        .all()
    )
    for row in existing:
        session.delete(row)
    for item in evidence[:50]:
        session.add(
            GatewayEvidenceRecord(
                organization_id=organization_id,
                message_id=message_id,
                provider_id=item.provider_id[:64],
                provider_type=item.provider_type[:32],
                verdict=item.verdict.value,
                category=item.category.value,
                confidence=item.confidence,
                score=item.score,
                threat_name=item.threat_name[:255],
                engine=item.engine[:128],
                policy=item.policy[:255],
                evidence_source=item.source.value,
                trusted=item.trusted,
                trust_state=item.trust_state.value,
                trust_reason=item.trust_reason[:500],
                raw_reference=item.raw_reference[:255],
                normalized_detail=dict(item.normalized_detail),
                observed_at=item.timestamp,
            )
        )
    return len(evidence[:50])


def persist_conflicts(
    session: Session,
    *,
    organization_id: str,
    message_id: str,
    conflicts: list[ProviderConflict],
) -> int:
    """Record disagreements so they stay visible until an analyst closes them (§28)."""
    open_rows = {
        row.kind: row
        for row in session.execute(
            select(GatewayConflict).where(
                GatewayConflict.message_id == message_id, GatewayConflict.resolved_at.is_(None)
            )
        )
        .scalars()
        .all()
    }
    added = 0
    for conflict in conflicts:
        if conflict.kind.value in open_rows:
            continue
        session.add(
            GatewayConflict(
                organization_id=organization_id,
                message_id=message_id,
                kind=conflict.kind.value,
                summary=conflict.summary[:1000],
                providers=list(conflict.providers),
                detail=dict(conflict.detail),
                detected_at=conflict.detected_at,
            )
        )
        added += 1
    return added


def subject_hash(subject: str) -> str:
    """Stable correlation key for a subject line (ТЗ 1.0.2 §23)."""
    normalised = " ".join((subject or "").lower().split())
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def record_trace(
    session: Session,
    *,
    organization_id: str,
    message_id: str,
    parsed: ParsedMessage,
    provider_id: str = "",
    events: list[dict[str, Any]] | None = None,
    final_action: str = "",
) -> MessageTraceRecord:
    """Store the correlation keys that tie a gateway event to this message (§23)."""
    trace = MessageTraceRecord(
        organization_id=organization_id,
        message_id=message_id,
        provider_id=provider_id[:64],
        internet_message_id=parsed.message_id[:998],
        sender=(parsed.from_.address if parsed.from_ else "")[:320],
        recipient=(parsed.to[0].address if parsed.to else "")[:320],
        subject_hash=subject_hash(parsed.subject),
        content_sha256=parsed.sha256,
        events=list(events or []),
        final_action=final_action[:32],
        complete=bool(events),
    )
    session.add(trace)
    return trace


def refresh_capabilities(session: Session, registry: GatewayRegistry, organization_id: str) -> int:
    """Record what each gateway was observed to support (ТЗ 1.0.2 §22).

    Capabilities are written from probing, never from the product name, so the console shows
    what this deployment can actually do rather than what the vendor's datasheet claims.
    """
    rows = {
        gateway.provider_id: gateway
        for gateway in session.execute(
            select(MailGateway).where(MailGateway.organization_id == organization_id)
        )
        .scalars()
        .all()
    }
    written = 0
    now = utcnow()
    for provider in registry.providers:
        gateway = rows.get(provider.provider_id)
        if gateway is None:
            continue
        available = {c.value for c in provider.capabilities()}
        existing = {
            state.capability: state
            for state in session.execute(
                select(GatewayCapabilityState).where(GatewayCapabilityState.gateway_id == gateway.id)
            )
            .scalars()
            .all()
        }
        for capability in available:
            state = existing.get(capability)
            if state is None:
                session.add(
                    GatewayCapabilityState(
                        gateway_id=gateway.id, capability=capability, available=True, checked_at=now
                    )
                )
            else:
                state.available = True
                state.checked_at = now
            written += 1
        for capability, state in existing.items():
            if capability not in available:
                # A capability that disappeared is recorded as unavailable rather than deleted:
                # losing one is an operational event worth seeing.
                state.available = False
                state.checked_at = now
    return written
