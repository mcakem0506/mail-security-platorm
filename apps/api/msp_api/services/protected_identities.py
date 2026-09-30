"""Protected identities derived from Active Directory groups (ТЗ 1.0.1 §5).

A protected identity is someone whose name, impersonated, would make an attack work: the
executive who can authorise a payment, the accountant who makes it, the administrator who can
reset a password, the HR officer people send documents to.

Maintaining that list by hand goes stale the week after it is written. The directory already
knows who these people are — it is what the groups are for — so the mapping the organisation
configures is *group to risk class*, and membership does the rest.

Risk class is kept separate from category on purpose. A finance clerk and the CFO share a
category but not a blast radius, and the detection rules weight impersonation of a critical
identity differently from impersonation of a routine one.

Nothing here writes to the directory. Identities created from a group are marked
``source="directory"``; one an analyst created by hand is never overwritten by a sync.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from msp_contracts import ProtectedCategory
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.base import utcnow
from ..db.models import MailboxIdentity, ProtectedIdentity

logger = logging.getLogger(__name__)

#: Ordered from most to least severe, so the strongest match across several groups wins.
RISK_CLASSES: tuple[str, ...] = ("critical", "high", "medium", "low")

#: Sensible defaults per category, used when a group mapping does not state a risk class.
_DEFAULT_RISK: dict[ProtectedCategory, str] = {
    ProtectedCategory.EXECUTIVE: "critical",
    ProtectedCategory.ADMINISTRATOR: "critical",
    ProtectedCategory.FINANCE: "high",
    ProtectedCategory.SECURITY: "high",
    ProtectedCategory.HR: "high",
    ProtectedCategory.PROCUREMENT: "medium",
    ProtectedCategory.VIP: "critical",
}


@dataclass(frozen=True)
class ProtectedGroupRule:
    """One configured mapping: an AD group and what membership of it means."""

    group: str
    category: ProtectedCategory
    risk_class: str = "medium"
    vip: bool = False

    @property
    def normalized_group(self) -> str:
        return self.group.strip().lower()


@dataclass
class ProtectedSyncResult:
    created: int = 0
    updated: int = 0
    disabled: int = 0
    unchanged: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.created + self.updated + self.unchanged


def parse_protected_groups(raw: str) -> tuple[ProtectedGroupRule, ...]:
    """Parse ``MSP_AD_PROTECTED_GROUPS``.

    Format, semicolon-separated::

        CN=Executives,OU=Groups,DC=corp,DC=example=executive:critical:vip;
        Finance=finance:high;
        SOC=security

    The group may be a full DN or a bare CN. Category is required; risk class defaults to the
    category's usual severity, and ``vip`` is an optional third element. A malformed entry is
    skipped with a warning rather than failing start-up, because one bad line must not disable
    identity protection entirely.
    """
    rules: list[ProtectedGroupRule] = []
    for chunk in (raw or "").split(";"):
        entry = chunk.strip()
        if not entry or "=" not in entry:
            continue
        group, _, spec = entry.rpartition("=")
        group = group.strip()
        parts = [p.strip().lower() for p in spec.split(":") if p.strip()]
        if not group or not parts:
            logger.warning("protected_identities.malformed_group_rule", extra={"entry": entry[:120]})
            continue
        try:
            category = ProtectedCategory(parts[0])
        except ValueError:
            logger.warning(
                "protected_identities.unknown_category",
                extra={"category": parts[0][:40], "known": [c.value for c in ProtectedCategory]},
            )
            continue
        risk_class = _DEFAULT_RISK.get(category, "medium")
        vip = category is ProtectedCategory.VIP
        for part in parts[1:]:
            if part in RISK_CLASSES:
                risk_class = part
            elif part == "vip":
                vip = True
        rules.append(ProtectedGroupRule(group=group, category=category, risk_class=risk_class, vip=vip))
    return tuple(rules)


def _group_key(dn: str) -> tuple[str, str]:
    """Both forms a group may be configured as: the full DN and the bare CN, lower-cased."""
    dn = (dn or "").strip()
    lowered = dn.lower()
    first = dn.split(",", 1)[0]
    cn = first.split("=", 1)[1].strip().lower() if "=" in first else lowered
    return lowered, cn


def match_rules(
    group_dns: tuple[str, ...], rules: tuple[ProtectedGroupRule, ...]
) -> list[ProtectedGroupRule]:
    """Which configured rules this account's group membership satisfies."""
    if not rules:
        return []
    keys: set[str] = set()
    for dn in group_dns:
        keys.update(_group_key(dn))
    return [rule for rule in rules if rule.normalized_group in keys]


def _strongest(matched: list[ProtectedGroupRule]) -> tuple[str, bool]:
    """The most severe risk class across all matching groups, and whether any marks VIP."""
    risk = min((RISK_CLASSES.index(r.risk_class) for r in matched), default=len(RISK_CLASSES) - 1)
    return RISK_CLASSES[risk], any(r.vip for r in matched)


def sync_from_directory(
    session: Session,
    *,
    organization_id: str,
    entries: list,  # list[DirectoryEntry]; typed loosely to keep the provider optional
    rules: tuple[ProtectedGroupRule, ...],
    created_by: str = "directory-sync",
) -> ProtectedSyncResult:
    """Create, update and retire protected identities from directory group membership.

    An identity whose groups no longer match is *disabled*, not deleted: the history of why a
    message was once judged an impersonation attempt has to remain readable.
    """
    result = ProtectedSyncResult()
    if not rules:
        return result

    existing = {
        row.email.lower(): row
        for row in session.execute(
            select(ProtectedIdentity).where(ProtectedIdentity.organization_id == organization_id)
        )
        .scalars()
        .all()
    }
    seen: set[str] = set()

    for entry in entries:
        email = (getattr(entry, "mail", "") or "").lower()
        if not email:
            continue
        matched = match_rules(tuple(getattr(entry, "groups", ()) or ()), rules)
        if not matched:
            continue
        seen.add(email)
        risk_class, vip = _strongest(matched)
        categories = sorted({rule.category.value for rule in matched})
        if vip and ProtectedCategory.VIP.value not in categories:
            categories.append(ProtectedCategory.VIP.value)
        aliases = [a for a in (getattr(entry, "aliases", ()) or ()) if a != email]
        display_name = (getattr(entry, "display_name", "") or "").strip() or email.split("@")[0]

        row = existing.get(email)
        if row is None:
            mailbox = session.execute(
                select(MailboxIdentity).where(
                    MailboxIdentity.organization_id == organization_id,
                    func.lower(MailboxIdentity.address) == email,
                )
            ).scalar_one_or_none()
            session.add(
                ProtectedIdentity(
                    organization_id=organization_id,
                    mailbox_identity_id=mailbox.id if mailbox is not None else None,
                    display_name=display_name,
                    email=email,
                    categories=categories,
                    aliases=aliases,
                    department=getattr(entry, "department", "") or "",
                    title=getattr(entry, "title", "") or "",
                    risk_class=risk_class,
                    vip=vip,
                    protected=True,
                    source="directory",
                    enabled=bool(getattr(entry, "enabled", True)),
                    created_by=created_by,
                )
            )
            result.created += 1
            continue

        if row.source != "directory":
            # An analyst created this one by hand; the directory does not overwrite it.
            result.unchanged += 1
            continue
        changed = (
            row.categories != categories
            or row.risk_class != risk_class
            or row.vip != vip
            or row.display_name != display_name
            or not row.enabled
        )
        row.display_name = display_name
        row.categories = categories
        row.aliases = aliases
        row.department = getattr(entry, "department", "") or row.department
        row.title = getattr(entry, "title", "") or row.title
        row.risk_class = risk_class
        row.vip = vip
        row.protected = True
        row.enabled = bool(getattr(entry, "enabled", True))
        if changed:
            result.updated += 1
        else:
            result.unchanged += 1

    for email, row in existing.items():
        if email in seen or row.source != "directory" or not row.enabled:
            continue
        # No longer in any protected group — disabled, never deleted, so past verdicts stay
        # explainable.
        row.enabled = False
        result.disabled += 1
        logger.info("protected_identities.retired", extra={"reason": "no matching group"})

    return result


def coverage(session: Session, organization_id: str) -> dict[str, object]:
    """Who is protected, for the pilot report (ТЗ 1.0.1 §5, §12)."""
    rows = (
        session.execute(
            select(ProtectedIdentity).where(
                ProtectedIdentity.organization_id == organization_id,
                ProtectedIdentity.enabled.is_(True),
            )
        )
        .scalars()
        .all()
    )
    by_risk: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for row in rows:
        by_risk[row.risk_class] = by_risk.get(row.risk_class, 0) + 1
        for category in row.categories or []:
            by_category[str(category)] = by_category.get(str(category), 0) + 1
    return {
        "total": len(rows),
        "vip": sum(1 for row in rows if row.vip),
        "from_directory": sum(1 for row in rows if row.source == "directory"),
        "manual": sum(1 for row in rows if row.source != "directory"),
        "by_risk_class": by_risk,
        "by_category": by_category,
        "checked_at": utcnow().isoformat(),
    }
