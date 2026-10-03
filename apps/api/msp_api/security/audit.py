"""Audit trail (ТЗ 25).

Append-only by contract: this module offers no update or delete. Secrets, tokens and message
bodies are never written — a redaction pass strips them even if a caller passes them by mistake.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy.orm import Session

from ..db.models import AuditEvent

logger = logging.getLogger(__name__)


# Actions worth auditing (ТЗ 25). Kept explicit so new code cannot silently skip the trail.
class AuditAction:
    LOGIN = "auth.login"
    LOGIN_FAILED = "auth.login_failed"
    LOGOUT = "auth.logout"
    SESSION_REVOKED = "auth.session_revoked"
    PASSWORD_CHANGED = "auth.password_changed"  # noqa: S105  # nosec
    MESSAGE_VIEW = "message.view"
    MESSAGE_CONTENT_VIEW = "message.content_view"
    ATTACHMENT_ACCESS = "attachment.access"
    ATTACHMENT_DOWNLOAD = "attachment.download"
    ANALYSIS_REQUESTED = "analysis.requested"
    ANALYSIS_REPORTED = "analysis.reported"
    RULE_CHANGED = "rule.changed"
    EXCEPTION_CREATED = "exception.created"
    EXCEPTION_REVOKED = "exception.revoked"
    PROTECTED_IDENTITY_CHANGED = "protected_identity.changed"
    TI_CONFIG_CHANGED = "ti.config_changed"
    POLICY_CHANGED = "policy.changed"
    INCIDENT_CREATED = "incident.created"
    INCIDENT_STATUS_CHANGED = "incident.status_changed"
    REMEDIATION_PROPOSED = "remediation.proposed"
    REMEDIATION_APPROVED = "remediation.approved"
    REMEDIATION_REJECTED = "remediation.rejected"
    REMEDIATION_EXECUTED = "remediation.executed"
    REMEDIATION_FAILED = "remediation.failed"
    EXPORT = "data.export"
    USER_CHANGED = "user.changed"
    DIRECTORY_SYNC = "directory.sync"
    RETENTION_RUN = "retention.run"
    # Mail gateway lifecycle (ТЗ 1.0.2 §33). Trust changes are audited separately from
    # configuration changes, because a trusted-hop edit changes which headers are believed.
    GATEWAY_ADDED = "gateway.added"
    GATEWAY_UPDATED = "gateway.updated"
    GATEWAY_DISABLED = "gateway.disabled"
    GATEWAY_CAPABILITY_CHANGED = "gateway.capability_changed"
    GATEWAY_CREDENTIAL_ROTATED = "gateway.credential_rotated"  # nosec
    GATEWAY_CONFLICT_RESOLVED = "gateway.conflict_resolved"
    TRUSTED_HOP_CHANGED = "gateway.trusted_hop_changed"
    # Detection quality, rule lifecycle and analyst decisions (ТЗ 1.0.3 §56).
    # The analyst's classification is audited because every quality metric is derived from it:
    # if the record of who decided what can be lost, the metrics cannot be defended.
    INCIDENT_CLASSIFIED = "incident.classified"
    FALSE_POSITIVE_MARKED = "detection.false_positive_marked"
    FALSE_NEGATIVE_MARKED = "detection.false_negative_marked"
    RULE_STATUS_CHANGED = "rule.status_changed"
    RULE_SIMULATED = "rule.simulated"
    FEEDBACK_RECORDED = "detection.feedback"
    RULE_QUALITY_SNAPSHOT = "rule.quality_snapshot"
    # A candidate pack moves through review before it can ship; each step is audited so the
    # question "who approved this rule" has an answer that does not depend on memory.
    CANDIDATE_CREATED = "candidate.created"
    CANDIDATE_BENCHMARKED = "candidate.benchmarked"
    CANDIDATE_SUBMITTED = "candidate.submitted"
    CANDIDATE_REVIEWED = "candidate.reviewed"
    RELEASE_PUBLISHED = "release.published"
    REEVALUATION_CANCELLED = "detection.reevaluation_cancelled"
    # A rollout decides which people a rule protects, so starting and ending one are
    # audited as separate events from the rule's own status changes.
    CANARY_STARTED = "canary.started"
    CANARY_PROMOTED = "canary.promoted"
    CANARY_ABORTED = "canary.aborted"
    EXCEPTION_APPROVED = "exception.approved"
    EXCEPTION_REVIEW_DUE = "exception.review_due"
    GAP_REGISTERED = "gap.registered"
    GAP_CLOSED = "gap.closed"
    ANALYSIS_REPLAYED = "analysis.replayed"
    REEVALUATION_STARTED = "detection.reevaluation_started"
    DATASET_CHANGED = "detection.dataset_changed"
    INCIDENT_ASSIGNED = "incident.assigned"
    # Campaign curation is audited because a merge or a split changes what later readers
    # believe happened: a wave folded into another is one nobody investigates separately.
    CAMPAIGN_MERGED = "campaign.merged"
    CAMPAIGN_SPLIT = "campaign.split"
    CAMPAIGN_MESSAGE_ATTACHED = "campaign.message_attached"
    CAMPAIGN_MESSAGE_REJECTED = "campaign.message_rejected"
    # Durable intake and unscannable messages (ТЗ 1.0.1 §4.1, §4.2).
    INTAKE_DEAD_LETTER = "intake.dead_letter"
    MESSAGE_UNSCANNABLE = "intake.unscannable"


_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|cookie|session|"
    r"csrf|private[_-]?key|credential|bearer)"
)
_BODY_KEY_RE = re.compile(r"(?i)^(body|raw|raw_mime|raw_eml|content|html|text|normalized_text)$")
_MAX_VALUE_LEN = 500
_MAX_DEPTH = 4


def redact(value: Any, depth: int = 0) -> Any:
    """Strip secrets and full message bodies from an audit payload (ТЗ 25)."""
    if depth > _MAX_DEPTH:
        return "[truncated]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:50]:
            key_str = str(key)
            if _SENSITIVE_KEY_RE.search(key_str):
                out[key_str] = "[redacted]"
            elif _BODY_KEY_RE.match(key_str):
                out[key_str] = f"[omitted:{len(str(item))} chars]"
            else:
                out[key_str] = redact(item, depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [redact(v, depth + 1) for v in list(value)[:50]]
    if isinstance(value, str):
        return value[:_MAX_VALUE_LEN]
    if isinstance(value, int | float | bool) or value is None:
        return value
    return str(value)[:_MAX_VALUE_LEN]


def record(
    session: Session,
    *,
    action: str,
    actor_email: str = "",
    actor_id: str | None = None,
    actor_role: str = "",
    organization_id: str | None = None,
    object_type: str = "",
    object_id: str = "",
    outcome: str = "success",
    detail: dict[str, Any] | None = None,
    ip_address: str = "",
    user_agent: str = "",
    request_id: str = "",
) -> AuditEvent:
    """Append one audit event. The caller's transaction commits it together with its change."""
    event = AuditEvent(
        organization_id=organization_id,
        action=action,
        actor_id=actor_id,
        actor_email=actor_email[:320],
        actor_role=actor_role[:32],
        object_type=object_type[:64],
        object_id=str(object_id)[:64],
        outcome=outcome[:16],
        detail=redact(detail or {}),
        ip_address=ip_address[:64],
        user_agent=user_agent[:255],
        request_id=request_id[:64],
    )
    session.add(event)
    logger.info(
        "audit",
        extra={
            "audit_action": action,
            "actor": actor_email,
            "object_type": object_type,
            "object_id": str(object_id),
            "outcome": outcome,
            "request_id": request_id,
        },
    )
    return event
