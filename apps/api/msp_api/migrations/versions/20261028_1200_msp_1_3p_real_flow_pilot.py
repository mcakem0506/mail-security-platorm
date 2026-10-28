"""msp_1_3p_real_flow_pilot

Revision ID: a3f1c9d27b64
Revises: 7d13e0f4a2b9
Create Date: 2026-10-28 12:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a3f1c9d27b64"
down_revision: str | None = "7d13e0f4a2b9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json() -> sa.types.TypeEngine:  # type: ignore[type-arg]
    return sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def _stamps() -> list[sa.Column]:  # type: ignore[type-arg]
    return [
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    ]


def upgrade() -> None:
    # Только новые таблицы: существующие не меняются, поэтому откат безопасен и не теряет данные этапов 1.1–1.3.
    op.create_table(
        "pilot_attestations",
        sa.Column("organization_id", sa.String(length=32), nullable=False),
        sa.Column("attestation_key", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("evidence_ref", sa.String(length=500), nullable=False),
        sa.Column("note", sa.String(length=1000), nullable=False),
        sa.Column("recorded_by", sa.String(length=320), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        *_stamps(),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_pilot_attestations_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pilot_attestations")),
    )
    op.create_index(
        op.f("ix_pilot_attestations_organization_id"), "pilot_attestations", ["organization_id"], unique=False
    )
    op.create_index(
        op.f("ix_pilot_attestations_created_at"), "pilot_attestations", ["created_at"], unique=False
    )
    op.create_index(
        "ix_pilot_attestation_key",
        "pilot_attestations",
        ["organization_id", "attestation_key", "recorded_at"],
        unique=False,
    )
    op.create_table(
        "pilot_phase_decisions",
        sa.Column("organization_id", sa.String(length=32), nullable=False),
        sa.Column("phase", sa.String(length=4), nullable=False),
        sa.Column("outcome", sa.String(length=8), nullable=False),
        sa.Column("state", sa.String(length=12), nullable=False),
        sa.Column("reasons", _json(), nullable=False),
        sa.Column("proposed_by", sa.String(length=320), nullable=False),
        sa.Column("approvals", _json(), nullable=False),
        sa.Column("gate_snapshot", _json(), nullable=False),
        sa.Column("risk_accept", sa.Text(), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=True),
        *_stamps(),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_pilot_phase_decisions_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pilot_phase_decisions")),
    )
    op.create_index(
        op.f("ix_pilot_phase_decisions_organization_id"),
        "pilot_phase_decisions",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_pilot_phase_decisions_created_at"), "pilot_phase_decisions", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_pilot_phase_decisions_state"), "pilot_phase_decisions", ["state"], unique=False)
    op.create_index(
        "ix_pilot_decision_phase",
        "pilot_phase_decisions",
        ["organization_id", "phase", "created_at"],
        unique=False,
    )
    op.create_table(
        "pilot_stops",
        sa.Column("organization_id", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=48), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=False),
        sa.Column("control_type", sa.String(length=24), nullable=False),
        sa.Column("opened_by", sa.String(length=320), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=10), nullable=False),
        sa.Column("resolved_by", sa.String(length=320), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rca_ref", sa.String(length=500), nullable=False),
        sa.Column("regression_ref", sa.String(length=500), nullable=False),
        *_stamps(),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_pilot_stops_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pilot_stops")),
    )
    op.create_index(op.f("ix_pilot_stops_organization_id"), "pilot_stops", ["organization_id"], unique=False)
    op.create_index(op.f("ix_pilot_stops_created_at"), "pilot_stops", ["created_at"], unique=False)
    op.create_index(op.f("ix_pilot_stops_state"), "pilot_stops", ["state"], unique=False)
    op.create_index("ix_pilot_stop_state", "pilot_stops", ["organization_id", "state"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_pilot_stop_state", table_name="pilot_stops")
    op.drop_index(op.f("ix_pilot_stops_state"), table_name="pilot_stops")
    op.drop_index(op.f("ix_pilot_stops_created_at"), table_name="pilot_stops")
    op.drop_index(op.f("ix_pilot_stops_organization_id"), table_name="pilot_stops")
    op.drop_table("pilot_stops")
    op.drop_index("ix_pilot_decision_phase", table_name="pilot_phase_decisions")
    op.drop_index(op.f("ix_pilot_phase_decisions_state"), table_name="pilot_phase_decisions")
    op.drop_index(op.f("ix_pilot_phase_decisions_created_at"), table_name="pilot_phase_decisions")
    op.drop_index(op.f("ix_pilot_phase_decisions_organization_id"), table_name="pilot_phase_decisions")
    op.drop_table("pilot_phase_decisions")
    op.drop_index("ix_pilot_attestation_key", table_name="pilot_attestations")
    op.drop_index(op.f("ix_pilot_attestations_created_at"), table_name="pilot_attestations")
    op.drop_index(op.f("ix_pilot_attestations_organization_id"), table_name="pilot_attestations")
    op.drop_table("pilot_attestations")
