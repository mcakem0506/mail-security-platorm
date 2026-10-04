"""Реестр вариантов защищаемых доменов (ТЗ 1.0.4 §4).

Проверяется три свойства, на которых реестр держится: генерация ничего не спрашивает у сети,
решение человека не затирается пересборкой, и статус, гасящий сигнал, нельзя поставить молча.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from msp_api.db.models import ProtectedDomainVariant
from msp_api.services import domain_variants
from msp_contracts import DomainVariantStatus
from sqlalchemy import func, select

SERVICE = pathlib.Path("apps/api/msp_api/services/domain_variants.py")


class TestGenerationIsOfflineAndPure:
    def test_variants_cover_the_four_transforms(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        result = domain_variants.generate(
            db, organization_id=organization.id, protected_domain="corp.example"
        )
        db.commit()
        assert result.created > 300, "для четырёхбуквенной метки вариантов должно быть много"

        transforms = set(
            db.execute(
                select(ProtectedDomainVariant.transform_type).where(
                    ProtectedDomainVariant.organization_id == organization.id
                )
            )
            .scalars()
            .all()
        )
        assert transforms == {"insertion", "deletion", "substitution", "transposition"}

    def test_the_known_gap_examples_are_in_the_registry(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Те самые домены, из-за которых существовал GAP-001."""
        domain_variants.generate(
            db, organization_id=organization.id, protected_domain="corp.example"
        )
        db.commit()
        present = set(
            db.execute(
                select(ProtectedDomainVariant.candidate_domain).where(
                    ProtectedDomainVariant.organization_id == organization.id
                )
            )
            .scalars()
            .all()
        )
        assert {"coorp.example", "corpp.example", "crop.example", "cor.example"} <= present
        assert "corp.example" not in present, "сам защищаемый домен не является своим вариантом"

    def test_a_long_label_is_skipped_with_a_reason(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Для длинных меток работает обычная проверка по расстоянию редактирования."""
        result = domain_variants.generate(
            db, organization_id=organization.id, protected_domain="microsoft.example"
        )
        assert result.created == 0
        assert "длиннее" in result.skipped_reason

    def test_the_service_performs_no_lookups(self) -> None:
        """Проверено по дереву разбора, а не по тексту: обещание в комментарии — не проверка."""
        tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        forbidden = {"socket", "dns", "dnspython", "whois", "httpx", "requests", "urllib", "aiohttp"}
        assert not (imported & forbidden), f"реестр обращается к сети: {imported & forbidden}"


class TestRegenerationKeepsHumanDecisions:
    def test_a_second_run_creates_nothing_new(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        first = domain_variants.generate(
            db, organization_id=organization.id, protected_domain="corp.example"
        )
        db.commit()
        second = domain_variants.generate(
            db, organization_id=organization.id, protected_domain="corp.example"
        )
        db.commit()
        assert second.created == 0
        assert second.existing == first.created

    def test_a_decision_survives_regeneration(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Иначе пересборка реестра тихо возвращала бы погашенный сигнал."""
        domain_variants.generate(
            db, organization_id=organization.id, protected_domain="corp.example"
        )
        db.commit()
        variant = db.execute(
            select(ProtectedDomainVariant).where(
                ProtectedDomainVariant.candidate_domain == "corps.example"
            )
        ).scalar_one()
        domain_variants.decide(
            db,
            variant=variant,
            status=DomainVariantStatus.KNOWN_LEGITIMATE,
            actor="admin@corp.example",
            reason="Настоящий поставщик Corps Security, договор 2024-18",
        )
        db.commit()

        domain_variants.generate(
            db, organization_id=organization.id, protected_domain="corp.example"
        )
        db.commit()
        db.expire_all()
        again = db.execute(
            select(ProtectedDomainVariant).where(
                ProtectedDomainVariant.candidate_domain == "corps.example"
            )
        ).scalar_one()
        assert again.status is DomainVariantStatus.KNOWN_LEGITIMATE
        assert again.decided_by == "admin@corp.example"


class TestObservation:
    def test_an_observed_variant_changes_state_and_counts(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        domain_variants.generate(
            db, organization_id=organization.id, protected_domain="corp.example"
        )
        db.commit()
        first = domain_variants.record_observation(
            db, organization_id=organization.id, candidate_domain="coorp.example"
        )
        assert first is not None
        assert first.status is DomainVariantStatus.OBSERVED
        assert first.first_observed_at is not None
        domain_variants.record_observation(
            db, organization_id=organization.id, candidate_domain="COORP.EXAMPLE"
        )
        db.commit()
        assert first.observed_count == 2, "регистр домена не должен создавать второй вариант"

    def test_an_unknown_domain_is_not_an_error(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Почта приходит с миллионов доменов; реестр описывает только варианты защищаемых."""
        assert (
            domain_variants.record_observation(
                db, organization_id=organization.id, candidate_domain="unrelated.test"
            )
            is None
        )

    def test_observation_does_not_overwrite_a_decision(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        domain_variants.generate(
            db, organization_id=organization.id, protected_domain="corp.example"
        )
        db.commit()
        variant = db.execute(
            select(ProtectedDomainVariant).where(
                ProtectedDomainVariant.candidate_domain == "core.example"
            )
        ).scalar_one()
        domain_variants.decide(
            db,
            variant=variant,
            status=DomainVariantStatus.KNOWN_LEGITIMATE,
            actor="admin@corp.example",
            reason="Core Systems, обслуживание серверов",
        )
        db.commit()
        domain_variants.record_observation(
            db, organization_id=organization.id, candidate_domain="core.example"
        )
        db.commit()
        assert variant.status is DomainVariantStatus.KNOWN_LEGITIMATE
        assert variant.observed_count == 1, "наблюдение считается и для разобранного варианта"


class TestSuppressingStatusIsNotCheap:
    def _variant(self, db, organization) -> ProtectedDomainVariant:  # type: ignore[no-untyped-def]
        domain_variants.generate(
            db, organization_id=organization.id, protected_domain="corp.example"
        )
        db.commit()
        return db.execute(
            select(ProtectedDomainVariant).where(
                ProtectedDomainVariant.candidate_domain == "corpp.example"
            )
        ).scalar_one()

    def test_known_legitimate_requires_a_reason(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(domain_variants.VariantError, match="причина"):
            domain_variants.decide(
                db,
                variant=self._variant(db, organization),
                status=DomainVariantStatus.KNOWN_LEGITIMATE,
                actor="admin@corp.example",
                reason="   ",
            )

    def test_a_decision_requires_an_author(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(domain_variants.VariantError, match="автора"):
            domain_variants.decide(
                db,
                variant=self._variant(db, organization),
                status=DomainVariantStatus.IGNORED,
                actor="",
            )

    def test_generated_and_observed_are_not_decisions(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Это состояния реестра, а не вывод человека, и ставить их вручную нечестно."""
        for status in (DomainVariantStatus.GENERATED, DomainVariantStatus.OBSERVED):
            with pytest.raises(domain_variants.VariantError, match="наблюдением"):
                domain_variants.decide(
                    db,
                    variant=self._variant(db, organization),
                    status=status,
                    actor="admin@corp.example",
                    reason="почему-то",
                )


class TestSummary:
    def test_share_is_null_while_the_registry_is_empty(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        result = domain_variants.summary(db, organization.id)
        assert result["total"] == 0
        assert result["decided_share"] is None, "доля от пустого реестра ничего не означает"

    def test_summary_counts_by_status(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        domain_variants.generate(
            db, organization_id=organization.id, protected_domain="corp.example"
        )
        db.commit()
        domain_variants.record_observation(
            db, organization_id=organization.id, candidate_domain="coorp.example"
        )
        db.commit()
        result = domain_variants.summary(db, organization.id)
        total = db.execute(
            select(func.count(ProtectedDomainVariant.id)).where(
                ProtectedDomainVariant.organization_id == organization.id
            )
        ).scalar_one()
        assert result["total"] == total
        assert result["by_status"][DomainVariantStatus.OBSERVED.value] == 1
        assert result["ever_observed"] == 1
        assert result["decided_share"] == 0.0
