"""Campaign correlation (ТЗ 18).

A message fingerprint combines normalised sender, subject shape, URL/domain set, attachment
hashes and a body simhash. Exact-fingerprint matches group immediately; near matches are found
by Hamming distance on the simhash plus a shared strong indicator, so a campaign that randomises
greetings or tracking links still clusters.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from msp_mail_parser import ParsedMessage, split_domain
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.base import utcnow
from ..db.models import Campaign, CampaignMessage, MailMessage

_SIMHASH_BITS = 64
_NEAR_DUPLICATE_DISTANCE = 6
_CORRELATION_WINDOW = timedelta(days=14)

_SUBJECT_NOISE = re.compile(
    r"(?i)^\s*(?:re|fwd?|fw|ответ|пересылка|автоответ|automatic reply)\s*:\s*", re.UNICODE
)
_DIGITS = re.compile(r"\d+")
_NON_WORD = re.compile(r"[^\w\s]+", re.UNICODE)
_TOKEN = re.compile(r"\w{3,}", re.UNICODE)


def normalize_subject(subject: str) -> str:
    """Strip reply/forward prefixes, numbers and punctuation — the campaign's subject shape."""
    text = subject or ""
    for _ in range(5):
        stripped = _SUBJECT_NOISE.sub("", text)
        if stripped == text:
            break
        text = stripped
    text = _DIGITS.sub("#", text.lower())
    text = _NON_WORD.sub(" ", text)
    return " ".join(text.split())[:200]


def simhash(text: str, bits: int = _SIMHASH_BITS) -> int:
    """Charikar simhash over word tokens — stable under small text edits."""
    tokens = _TOKEN.findall((text or "").lower())
    if not tokens:
        return 0
    vector = [0] * bits
    for token in tokens[:4000]:
        digest = int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big")
        for i in range(bits):
            vector[i] += 1 if (digest >> i) & 1 else -1
    value = 0
    for i, weight in enumerate(vector):
        if weight > 0:
            value |= 1 << i
    return value


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


@dataclass
class MessageFingerprint:
    value: str
    sender_key: str
    subject_key: str
    domain_set: tuple[str, ...]
    attachment_hashes: tuple[str, ...]
    simhash_hex: str
    components: dict[str, object] = field(default_factory=dict)


def build_fingerprint(msg: ParsedMessage) -> MessageFingerprint:
    sender = msg.from_
    # Sender key ignores the local part's random suffixes that bulk senders add.
    sender_key = ""
    if sender is not None and sender.domain:
        local = re.sub(r"[\d._\-+]{4,}$", "", sender.local_part)[:32]
        sender_key = f"{local}@{split_domain(sender.domain).registrable_ascii}"
    subject_key = normalize_subject(msg.subject)
    domains = sorted(
        {
            split_domain(u.host_ascii).registrable_ascii
            for u in msg.urls
            if u.host_ascii and not u.is_ip_literal
        }
    )[:20]
    hashes = sorted({a.meta.sha256 for a in msg.attachments if a.meta.depth == 0})[:20]
    body_simhash = simhash(msg.normalized_text)
    material = "|".join(
        [sender_key, subject_key, ",".join(domains), ",".join(hashes), f"{body_simhash:016x}"]
    )
    return MessageFingerprint(
        value=hashlib.sha256(material.encode("utf-8")).hexdigest(),
        sender_key=sender_key,
        subject_key=subject_key,
        domain_set=tuple(domains),
        attachment_hashes=tuple(hashes),
        simhash_hex=f"{body_simhash:016x}",
        components={
            "sender_key": sender_key,
            "subject_key": subject_key,
            "domains": domains,
            "attachments": hashes,
        },
    )


def similarity_score(a: MessageFingerprint, b_simhash: str, b_domains: set[str], b_hashes: set[str]) -> float:
    """0..1 similarity used to decide whether a message joins an existing campaign."""
    score = 0.0
    try:
        distance = hamming(int(a.simhash_hex, 16), int(b_simhash or "0", 16))
    except ValueError:
        distance = _SIMHASH_BITS
    if distance <= _NEAR_DUPLICATE_DISTANCE:
        score += 0.5 * (1 - distance / (_NEAR_DUPLICATE_DISTANCE + 1))
        score += 0.2
    if a.attachment_hashes and b_hashes & set(a.attachment_hashes):
        score += 0.45
    if a.domain_set and b_domains & set(a.domain_set):
        score += 0.3
    return min(score, 1.0)


@dataclass
class CorrelationResult:
    campaign: Campaign | None
    created: bool
    similarity: float
    matched_by: str


def correlate(
    session: Session,
    *,
    organization_id: str,
    message: MailMessage,
    fingerprint: MessageFingerprint,
    classification: str,
    min_similarity: float = 0.6,
) -> CorrelationResult:
    """Attach a message to an existing campaign or open a new one."""
    since = utcnow() - _CORRELATION_WINDOW

    existing = session.execute(
        select(Campaign).where(
            Campaign.organization_id == organization_id, Campaign.fingerprint == fingerprint.value
        )
    ).scalar_one_or_none()
    matched_by = "fingerprint"
    similarity = 1.0

    if existing is None:
        existing, similarity = _find_near_match(
            session,
            organization_id=organization_id,
            fingerprint=fingerprint,
            since=since,
            min_similarity=min_similarity,
        )
        matched_by = "similarity" if existing is not None else ""

    created = False
    if existing is None:
        existing = Campaign(
            organization_id=organization_id,
            fingerprint=fingerprint.value,
            name=(fingerprint.subject_key or fingerprint.sender_key or "Кампания")[:255],
            first_seen=message.received_at,
            last_seen=message.received_at,
            indicators=list(fingerprint.domain_set) + list(fingerprint.attachment_hashes),
            subjects=[message.subject[:200]] if message.subject else [],
            senders=[message.sender_address] if message.sender_address else [],
        )
        session.add(existing)
        session.flush()
        created = True
        matched_by = "new"
        similarity = 1.0

    link = session.execute(
        select(CampaignMessage).where(
            CampaignMessage.campaign_id == existing.id, CampaignMessage.message_id == message.id
        )
    ).scalar_one_or_none()
    if link is None:
        session.add(CampaignMessage(campaign_id=existing.id, message_id=message.id, similarity=similarity))
        existing.message_count += 1
        existing.recipient_count += max(message.recipient_count, 1)
        if message.reported_by:
            existing.reported_count += 1

    _update_campaign_aggregates(existing, message, fingerprint, classification)
    return CorrelationResult(existing, created, similarity, matched_by)


def _find_near_match(
    session: Session,
    *,
    organization_id: str,
    fingerprint: MessageFingerprint,
    since: datetime,
    min_similarity: float,
) -> tuple[Campaign | None, float]:
    """Compare against recent messages: a shared strong indicator plus a close body simhash."""
    candidates = session.execute(
        select(MailMessage, CampaignMessage.campaign_id)
        .join(CampaignMessage, CampaignMessage.message_id == MailMessage.id)
        .where(MailMessage.organization_id == organization_id, MailMessage.received_at >= since)
        .order_by(MailMessage.received_at.desc())
        .limit(500)
    ).all()

    best: tuple[Campaign | None, float] = (None, 0.0)
    for candidate, campaign_id in candidates:
        components = candidate.campaign_components or {}
        other_domains = set(components.get("domains", []) or [])
        other_hashes = set(components.get("attachments", []) or [])
        score = similarity_score(fingerprint, candidate.body_simhash, other_domains, other_hashes)
        if score >= min_similarity and score > best[1]:
            campaign = session.get(Campaign, campaign_id)
            if campaign is not None:
                best = (campaign, score)
    return best


def _update_campaign_aggregates(
    campaign: Campaign, message: MailMessage, fingerprint: MessageFingerprint, classification: str
) -> None:
    if message.received_at < campaign.first_seen:
        campaign.first_seen = message.received_at
    if message.received_at > campaign.last_seen:
        campaign.last_seen = message.received_at

    distribution = dict(campaign.verdict_distribution or {})
    distribution[classification] = int(distribution.get(classification, 0)) + 1
    campaign.verdict_distribution = distribution

    indicators = list(
        dict.fromkeys(
            list(campaign.indicators or [])
            + list(fingerprint.domain_set)
            + list(fingerprint.attachment_hashes)
        )
    )
    campaign.indicators = indicators[:100]
    if message.subject:
        subjects = list(dict.fromkeys([*(campaign.subjects or []), message.subject[:200]]))
        campaign.subjects = subjects[:25]
    if message.sender_address:
        senders = list(dict.fromkeys([*(campaign.senders or []), message.sender_address]))
        campaign.senders = senders[:50]
    if classification == "MALICIOUS":
        campaign.confirmed_malicious = True


def campaign_summary(campaign: Campaign) -> dict[str, object]:
    """The view required by ТЗ 18."""
    return {
        "campaign_id": campaign.id,
        "name": campaign.name,
        "first_seen": campaign.first_seen.isoformat(),
        "last_seen": campaign.last_seen.isoformat(),
        "message_count": campaign.message_count,
        "recipient_count": campaign.recipient_count,
        "reported_by_users": campaign.reported_count,
        "indicators": list(campaign.indicators or [])[:50],
        "verdict_distribution": dict(campaign.verdict_distribution or {}),
        "confirmed_malicious": campaign.confirmed_malicious,
        "remediation_state": campaign.remediation_state,
        "incident_id": campaign.incident_id,
    }
