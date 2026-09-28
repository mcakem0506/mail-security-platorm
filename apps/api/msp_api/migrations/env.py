"""Alembic environment: schema is derived from the SQLAlchemy models."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
import sqlalchemy as sa
from sqlalchemy import engine_from_config, pool

from msp_api.config import get_settings
from msp_api.db.base import Base
from msp_api.db import models  # noqa: F401 - imported for metadata registration

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata
config.set_main_option("sqlalchemy.url", get_settings().database_url.replace("%", "%%"))


def render_item(type_, obj, autogen_context):
    """Render custom column types as plain SQLAlchemy, so migrations do not import app code."""
    if type_ == "type":
        from msp_api.db.base import UTCDateTime

        if isinstance(obj, UTCDateTime):
            autogen_context.imports.add("import sqlalchemy as sa")
            return "sa.DateTime(timezone=True)"
        if isinstance(obj, sa.JSON) or obj.__class__.__name__ == "JSON":
            autogen_context.imports.add("import sqlalchemy as sa")
            autogen_context.imports.add("from sqlalchemy.dialects import postgresql")
            return "sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')"
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        render_item=render_item,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_item=render_item,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
