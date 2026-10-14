"""MSP 1.1 транспорт почты: узлы, версии конфигурации, справочник получателей, копии писем

Revision ID: a1c4e7b90d11
Revises: 73468c34602f
Create Date: 2026-10-14 12:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

revision: str = "a1c4e7b90d11"
down_revision: str | None = "73468c34602f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "accepted_recipients",
        sa.Column("organization_id", sa.String(length=32), nullable=False),
        sa.Column("address", sa.String(length=320), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column(
            "aliases",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_accepted_recipients_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_accepted_recipients")),
        sa.UniqueConstraint("organization_id", "address", name="uq_accepted_recipient_address"),
    )
    op.create_index(op.f("ix_accepted_recipients_active"), "accepted_recipients", ["active"], unique=False)
    op.create_index(op.f("ix_accepted_recipients_address"), "accepted_recipients", ["address"], unique=False)
    op.create_index(
        op.f("ix_accepted_recipients_created_at"), "accepted_recipients", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_accepted_recipients_organization_id"),
        "accepted_recipients",
        ["organization_id"],
        unique=False,
    )
    op.create_table(
        "mail_transport_events",
        sa.Column("organization_id", sa.String(length=32), nullable=False),
        sa.Column("node_id", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "data", sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"), nullable=False
        ),
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_mail_transport_events_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mail_transport_events")),
    )
    op.create_index(
        op.f("ix_mail_transport_events_event_type"), "mail_transport_events", ["event_type"], unique=False
    )
    op.create_index(
        op.f("ix_mail_transport_events_node_id"), "mail_transport_events", ["node_id"], unique=False
    )
    op.create_index(
        op.f("ix_mail_transport_events_organization_id"),
        "mail_transport_events",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_transport_event_node_time",
        "mail_transport_events",
        ["organization_id", "node_id", "occurred_at"],
        unique=False,
    )
    op.create_table(
        "recipient_sync_runs",
        sa.Column("organization_id", sa.String(length=32), nullable=False),
        sa.Column(
            "status",
            sa.Enum("ACCEPTED", "REFUSED", "FAILED", name="recipient_sync_status_enum", native_enum=False),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("recipient_count", sa.Integer(), nullable=False),
        sa.Column("previous_count", sa.Integer(), nullable=False),
        sa.Column("rejected_count", sa.Integer(), nullable=False),
        sa.Column("conflict_count", sa.Integer(), nullable=False),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("source_generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_by", sa.String(length=320), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_recipient_sync_runs_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recipient_sync_runs")),
    )
    op.create_index(
        op.f("ix_recipient_sync_runs_organization_id"),
        "recipient_sync_runs",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_recipient_sync_runs_started_at"), "recipient_sync_runs", ["started_at"], unique=False
    )
    op.create_index(op.f("ix_recipient_sync_runs_status"), "recipient_sync_runs", ["status"], unique=False)
    op.create_table(
        "transport_certificates",
        sa.Column("organization_id", sa.String(length=32), nullable=False),
        sa.Column("node_id", sa.String(length=32), nullable=False),
        sa.Column("usage", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=False),
        sa.Column("issuer", sa.String(length=500), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_transport_certificates_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_transport_certificates")),
        sa.UniqueConstraint("organization_id", "node_id", "fingerprint", name="uq_transport_cert"),
    )
    op.create_index(
        op.f("ix_transport_certificates_created_at"), "transport_certificates", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_transport_certificates_node_id"), "transport_certificates", ["node_id"], unique=False
    )
    op.create_index(
        op.f("ix_transport_certificates_not_after"), "transport_certificates", ["not_after"], unique=False
    )
    op.create_index(
        op.f("ix_transport_certificates_organization_id"),
        "transport_certificates",
        ["organization_id"],
        unique=False,
    )
    op.create_table(
        "transport_config_versions",
        sa.Column("organization_id", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "DRAFT",
                "VALIDATED",
                "ACTIVE",
                "SUPERSEDED",
                "ROLLED_BACK",
                "FAILED",
                name="transport_config_status_enum",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "spec", sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"), nullable=False
        ),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.Column(
            "bundle",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("recipients_checksum", sa.String(length=64), nullable=False),
        sa.Column(
            "validation_errors",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("note", sa.String(length=500), nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_by", sa.String(length=320), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_transport_config_versions_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_transport_config_versions")),
        sa.UniqueConstraint("organization_id", "version", name="uq_transport_config_version"),
    )
    op.create_index(
        "ix_transport_config_status", "transport_config_versions", ["organization_id", "status"], unique=False
    )
    op.create_index(
        op.f("ix_transport_config_versions_created_at"),
        "transport_config_versions",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_transport_config_versions_organization_id"),
        "transport_config_versions",
        ["organization_id"],
        unique=False,
    )
    op.create_table(
        "transport_nodes",
        sa.Column("organization_id", sa.String(length=32), nullable=False),
        sa.Column("node_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "role",
            sa.Enum("INBOUND", "OUTBOUND", "BOTH", "LAB", name="transport_node_role_enum", native_enum=False),
            nullable=False,
        ),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config_version", sa.String(length=64), nullable=False),
        sa.Column("config_checksum", sa.String(length=64), nullable=False),
        sa.Column("queue_messages", sa.Integer(), nullable=False),
        sa.Column("pressure_state", sa.String(length=16), nullable=False),
        sa.Column("unparsed_log_lines", sa.Integer(), nullable=False),
        sa.Column("oldest_message_seconds", sa.Float(), nullable=False),
        sa.Column("exchange_ok", sa.Boolean(), nullable=True),
        sa.Column("open_relay_safe", sa.Boolean(), nullable=True),
        sa.Column("config_drift", sa.Boolean(), nullable=True),
        sa.Column("collector_report_age", sa.Float(), nullable=True),
        sa.Column("shadow_pending_seconds", sa.Float(), nullable=True),
        sa.Column("drain_requested", sa.Boolean(), nullable=False),
        sa.Column("drain_requested_by", sa.String(length=320), nullable=False),
        sa.Column("drain_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("flush_requested", sa.Boolean(), nullable=False),
        sa.Column("flush_requested_by", sa.String(length=320), nullable=False),
        sa.Column("flush_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "details",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_transport_nodes_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_transport_nodes")),
        sa.UniqueConstraint("organization_id", "node_id", name="uq_transport_nodes_node"),
    )
    op.create_index(op.f("ix_transport_nodes_created_at"), "transport_nodes", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_transport_nodes_last_heartbeat_at"), "transport_nodes", ["last_heartbeat_at"], unique=False
    )
    op.create_index(op.f("ix_transport_nodes_node_id"), "transport_nodes", ["node_id"], unique=False)
    op.create_index(
        op.f("ix_transport_nodes_organization_id"), "transport_nodes", ["organization_id"], unique=False
    )
    op.create_table(
        "transport_messages",
        sa.Column("organization_id", sa.String(length=32), nullable=False),
        sa.Column("node_id", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("queue_id", sa.String(length=40), nullable=False),
        sa.Column("internet_message_id", sa.String(length=998), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("envelope_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("client_address", sa.String(length=64), nullable=False),
        sa.Column("journaled_at", sa.Float(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "COLLECTED",
                "ANALYSIS_QUEUED",
                "ANALYSED",
                "ANALYSIS_FAILED",
                name="transport_message_state_enum",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column("raw_storage_key", sa.String(length=512), nullable=True),
        sa.Column("analysis_job_id", sa.String(length=32), nullable=True),
        sa.Column("duplicate_count", sa.Integer(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["analysis_job_id"],
            ["analysis_jobs.id"],
            name=op.f("fk_transport_messages_analysis_job_id_analysis_jobs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_transport_messages_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_transport_messages")),
        sa.UniqueConstraint("organization_id", "idempotency_key", name="uq_transport_message_key"),
    )
    op.create_index(
        "ix_transport_message_state", "transport_messages", ["organization_id", "state"], unique=False
    )
    op.create_index(
        op.f("ix_transport_messages_analysis_job_id"), "transport_messages", ["analysis_job_id"], unique=False
    )
    op.create_index(
        op.f("ix_transport_messages_content_sha256"), "transport_messages", ["content_sha256"], unique=False
    )
    op.create_index(
        op.f("ix_transport_messages_created_at"), "transport_messages", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_transport_messages_direction"), "transport_messages", ["direction"], unique=False
    )
    op.create_index(
        op.f("ix_transport_messages_internet_message_id"),
        "transport_messages",
        ["internet_message_id"],
        unique=False,
    )
    op.create_index(op.f("ix_transport_messages_node_id"), "transport_messages", ["node_id"], unique=False)
    op.create_index(
        op.f("ix_transport_messages_organization_id"), "transport_messages", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_transport_messages_state"), "transport_messages", ["state"], unique=False)


def downgrade() -> None:

    op.drop_index(op.f("ix_transport_messages_state"), table_name="transport_messages")
    op.drop_index(op.f("ix_transport_messages_organization_id"), table_name="transport_messages")
    op.drop_index(op.f("ix_transport_messages_node_id"), table_name="transport_messages")
    op.drop_index(op.f("ix_transport_messages_internet_message_id"), table_name="transport_messages")
    op.drop_index(op.f("ix_transport_messages_direction"), table_name="transport_messages")
    op.drop_index(op.f("ix_transport_messages_created_at"), table_name="transport_messages")
    op.drop_index(op.f("ix_transport_messages_content_sha256"), table_name="transport_messages")
    op.drop_index(op.f("ix_transport_messages_analysis_job_id"), table_name="transport_messages")
    op.drop_index("ix_transport_message_state", table_name="transport_messages")
    op.drop_table("transport_messages")
    op.drop_index(op.f("ix_transport_nodes_organization_id"), table_name="transport_nodes")
    op.drop_index(op.f("ix_transport_nodes_node_id"), table_name="transport_nodes")
    op.drop_index(op.f("ix_transport_nodes_last_heartbeat_at"), table_name="transport_nodes")
    op.drop_index(op.f("ix_transport_nodes_created_at"), table_name="transport_nodes")
    op.drop_table("transport_nodes")
    op.drop_index(
        op.f("ix_transport_config_versions_organization_id"), table_name="transport_config_versions"
    )
    op.drop_index(op.f("ix_transport_config_versions_created_at"), table_name="transport_config_versions")
    op.drop_index("ix_transport_config_status", table_name="transport_config_versions")
    op.drop_table("transport_config_versions")
    op.drop_index(op.f("ix_transport_certificates_organization_id"), table_name="transport_certificates")
    op.drop_index(op.f("ix_transport_certificates_not_after"), table_name="transport_certificates")
    op.drop_index(op.f("ix_transport_certificates_node_id"), table_name="transport_certificates")
    op.drop_index(op.f("ix_transport_certificates_created_at"), table_name="transport_certificates")
    op.drop_table("transport_certificates")
    op.drop_index(op.f("ix_recipient_sync_runs_status"), table_name="recipient_sync_runs")
    op.drop_index(op.f("ix_recipient_sync_runs_started_at"), table_name="recipient_sync_runs")
    op.drop_index(op.f("ix_recipient_sync_runs_organization_id"), table_name="recipient_sync_runs")
    op.drop_table("recipient_sync_runs")
    op.drop_index("ix_transport_event_node_time", table_name="mail_transport_events")
    op.drop_index(op.f("ix_mail_transport_events_organization_id"), table_name="mail_transport_events")
    op.drop_index(op.f("ix_mail_transport_events_node_id"), table_name="mail_transport_events")
    op.drop_index(op.f("ix_mail_transport_events_event_type"), table_name="mail_transport_events")
    op.drop_table("mail_transport_events")
    op.drop_index(op.f("ix_accepted_recipients_organization_id"), table_name="accepted_recipients")
    op.drop_index(op.f("ix_accepted_recipients_created_at"), table_name="accepted_recipients")
    op.drop_index(op.f("ix_accepted_recipients_address"), table_name="accepted_recipients")
    op.drop_index(op.f("ix_accepted_recipients_active"), table_name="accepted_recipients")
    op.drop_table("accepted_recipients")
