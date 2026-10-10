"""Реестр вариантов защищаемых доменов (ТЗ 1.0.4 §4).

Реестр отвечает на один вопрос: **если письмо придёт с такого домена, что мы о нём уже
решили**. Он намеренно не отвечает на вопрос «зарегистрирован ли такой домен»: это потребовало
бы обращения наружу по каждому из сотен вариантов и выдало бы наружу список доменов, которые
организация защищает. Генерация чистая и офлайновая — ни DNS, ни WHOIS, ни обхода сети.

Смысл хранения в том, что статус — это память о решении человека. Без реестра аналитик принимал
бы одно и то же решение про «corps.example» столько раз, сколько приходит писем, и каждый раз
заново.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from msp_contracts import DomainVariantStatus, utcnow
from msp_detection.similarity import MAX_SHORT_LABEL, short_label_variants
from msp_mail_parser.domains import split_domain
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import ProtectedDomainVariant

logger = logging.getLogger(__name__)

#: Статусы, при которых вариант считается разобранным человеком.
DECIDED_STATUSES: frozenset[DomainVariantStatus] = frozenset(
    {
        DomainVariantStatus.APPROVED_SUSPICIOUS,
        DomainVariantStatus.KNOWN_LEGITIMATE,
        DomainVariantStatus.IGNORED,
    }
)

#: Статус, который гасит сигнал, и поэтому требует причины и владельца.
SUPPRESSING_STATUS = DomainVariantStatus.KNOWN_LEGITIMATE


class VariantError(RuntimeError):
    """Отказ с причиной, а не общее «нельзя»."""


@dataclass
class GenerationResult:
    protected_domain: str
    created: int
    existing: int
    skipped_reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "protected_domain": self.protected_domain,
            "created": self.created,
            "existing": self.existing,
            "skipped_reason": self.skipped_reason,
        }


def generate(session: Session, *, organization_id: str, protected_domain: str) -> GenerationResult:
    """Вычислить и сохранить все варианты одного защищаемого домена.

    Повторный вызов не создаёт дубликатов и **не сбрасывает статусы**: решение человека не
    должно исчезать от того, что реестр пересобрали.
    """
    domain = (protected_domain or "").strip().lower()
    if not domain:
        raise VariantError("домен не указан")

    label = split_domain(domain).label
    if not label:
        raise VariantError(f"из «{domain}» не выделяется метка домена")
    if len(label) > MAX_SHORT_LABEL:
        # Для длинных меток работает обычная проверка опечаточных доменов по расстоянию
        # редактирования; отдельный реестр вариантов для них не нужен и был бы огромным.
        return GenerationResult(domain, 0, 0, f"метка «{label}» длиннее {MAX_SHORT_LABEL} символов")

    suffix = domain[len(label) :]
    known = {
        row.candidate_domain
        for row in session.execute(
            select(ProtectedDomainVariant).where(
                ProtectedDomainVariant.organization_id == organization_id,
                ProtectedDomainVariant.protected_domain == domain,
            )
        ).scalars()
    }

    created = 0
    for variant_label, transform in sorted(short_label_variants(label).items()):
        candidate = f"{variant_label}{suffix}"
        if candidate == domain or candidate in known:
            continue
        session.add(
            ProtectedDomainVariant(
                organization_id=organization_id,
                protected_domain=domain,
                candidate_domain=candidate,
                transform_type=transform,
                distance=1,
                status=DomainVariantStatus.GENERATED,
            )
        )
        created += 1

    logger.info("domain_variants.generated", extra={"domain": domain, "created": created})
    return GenerationResult(domain, created, len(known))


def generate_for_organization(
    session: Session, *, organization_id: str, protected_domains: list[str]
) -> list[GenerationResult]:
    return [
        generate(session, organization_id=organization_id, protected_domain=domain)
        for domain in protected_domains
    ]


def record_observation(
    session: Session, *, organization_id: str, candidate_domain: str
) -> ProtectedDomainVariant | None:
    """Отметить, что вариант встретился в почте.

    Возвращает ``None``, если домена в реестре нет: это не ошибка, а обычный случай — почта
    приходит с миллионов доменов, и реестр описывает только варианты защищаемых.

    Статус, выставленный человеком, не перезаписывается. ``GENERATED`` переходит в ``OBSERVED``,
    потому что «вычислен и ни разу не встречался» и «вычислен и уже приходил» — разные факты, и
    второй стоит того, чтобы аналитик его увидел.
    """
    domain = (candidate_domain or "").strip().lower()
    if not domain:
        return None
    variant = session.execute(
        select(ProtectedDomainVariant).where(
            ProtectedDomainVariant.organization_id == organization_id,
            func.lower(ProtectedDomainVariant.candidate_domain) == domain,
        )
    ).scalar_one_or_none()
    if variant is None:
        return None

    now = utcnow()
    if variant.first_observed_at is None:
        variant.first_observed_at = now
    variant.last_observed_at = now
    variant.observed_count += 1
    if variant.status is DomainVariantStatus.GENERATED:
        variant.status = DomainVariantStatus.OBSERVED
    return variant


def decide(
    session: Session,
    *,
    variant: ProtectedDomainVariant,
    status: DomainVariantStatus,
    actor: str,
    reason: str = "",
) -> ProtectedDomainVariant:
    """Записать решение человека о варианте.

    ``KNOWN_LEGITIMATE`` требует причины, потому что гасит сигнал. Это тот же порядок, что для
    исключений: контроль, который делает платформу слепой, не ставится одним кликом, и через
    полгода должно быть видно, кто и почему его поставил.
    """
    if status in (DomainVariantStatus.GENERATED, DomainVariantStatus.OBSERVED):
        raise VariantError(
            f"{status.value} выставляется наблюдением, а не решением: "
            "это состояние реестра, а не вывод человека"
        )
    if status is SUPPRESSING_STATUS and not reason.strip():
        raise VariantError(
            "KNOWN_LEGITIMATE гасит сигнал по этому домену: нужна причина, "
            "иначе через полгода её никто не восстановит"
        )
    if not actor.strip():
        raise VariantError("решение без автора не записывается")

    variant.status = status
    variant.decided_by = actor.strip()
    variant.decided_at = utcnow()
    variant.reason = reason.strip()[:1000]
    return variant


def summary(session: Session, organization_id: str) -> dict[str, Any]:
    """Состояние реестра для консоли.

    Доли не считаются: при сотнях вычисленных вариантов и единицах встреченных процент
    говорил бы о размере алфавита, а не об обстановке.
    """
    rows = session.execute(
        select(ProtectedDomainVariant.status, func.count(ProtectedDomainVariant.id))
        .where(ProtectedDomainVariant.organization_id == organization_id)
        .group_by(ProtectedDomainVariant.status)
    ).all()
    by_status = {status.value: int(count) for status, count in rows}
    total = sum(by_status.values())
    observed = session.execute(
        select(func.count(ProtectedDomainVariant.id)).where(
            ProtectedDomainVariant.organization_id == organization_id,
            ProtectedDomainVariant.observed_count > 0,
        )
    ).scalar_one()
    return {
        "total": total,
        "by_status": by_status,
        "ever_observed": int(observed or 0),
        # Null, а не ноль, пока реестр пуст: доля от пустого реестра ничего не означает.
        "decided_share": (
            sum(by_status.get(status.value, 0) for status in DECIDED_STATUSES) / total if total else None
        ),
    }
