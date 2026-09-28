"""Shared test fixtures."""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

os.environ.setdefault("MSP_ENVIRONMENT", "test")
os.environ.setdefault("MSP_SECRET_KEY", "test-secret-key-for-unit-tests-only-not-production")
os.environ.setdefault("MSP_OBJECT_STORAGE_BACKEND", "filesystem")
os.environ.setdefault("MSP_COOKIE_SECURE", "false")
os.environ.setdefault("MSP_CORPORATE_DOMAINS", "corp.example")
os.environ.setdefault("MSP_ORGANIZATION_NAME", "Corp")
os.environ.setdefault("MSP_LOG_FORMAT", "text")
os.environ.setdefault("MSP_LOG_LEVEL", "WARNING")


@pytest.fixture(scope="session")
def storage_dir() -> Iterator[str]:
    with tempfile.TemporaryDirectory(prefix="msp-storage-") as path:
        os.environ["MSP_OBJECT_STORAGE_PATH"] = path
        yield path


@pytest.fixture(scope="session", autouse=True)
def _configure(storage_dir: str) -> None:
    os.environ["MSP_DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
    from msp_api.config import reset_settings_cache

    reset_settings_cache()


@pytest.fixture
def settings():  # type: ignore[no-untyped-def]
    from msp_api.config import get_settings

    return get_settings()


@pytest.fixture
def engine(storage_dir: str):  # type: ignore[no-untyped-def]
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    from msp_api.db.models import Base

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine):  # type: ignore[no-untyped-def]
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def organization(db):  # type: ignore[no-untyped-def]
    from msp_api.db.models import MailboxIdentity, Organization, ProtectedIdentity

    org = Organization(
        id="org-test",
        name="Corp",
        corporate_domains=["corp.example"],
        trusted_infrastructure_domains=["mailer.trusted-service.example"],
    )
    db.add(org)
    db.add(
        MailboxIdentity(
            organization_id=org.id,
            address="buh@corp.example",
            display_name="Бухгалтерия",
            department="Финансовый отдел",
        )
    )
    db.add(
        MailboxIdentity(
            organization_id=org.id,
            address="ivanov@corp.example",
            display_name="Сергей Иванов",
            department="ИТ",
        )
    )
    db.add(
        ProtectedIdentity(
            organization_id=org.id,
            display_name="Иван Петров",
            email="ceo@corp.example",
            categories=["executive"],
        )
    )
    db.add(
        ProtectedIdentity(
            organization_id=org.id,
            display_name="Мария Кузнецова",
            email="cfo@corp.example",
            categories=["finance"],
        )
    )
    db.commit()
    return org


@pytest.fixture
def context(organization):  # type: ignore[no-untyped-def]
    from msp_contracts import ProtectedCategory
    from msp_detection import AnalysisContext, DirectoryUser, ProtectedIdentity

    return AnalysisContext(
        organization_id=organization.id,
        organization_name="Corp",
        corporate_domains=("corp.example",),
        trusted_infrastructure_domains=("mailer.trusted-service.example",),
        protected_identities=(
            ProtectedIdentity("pi-ceo", "Иван Петров", "ceo@corp.example", (ProtectedCategory.EXECUTIVE,)),
            ProtectedIdentity("pi-cfo", "Мария Кузнецова", "cfo@corp.example", (ProtectedCategory.FINANCE,)),
        ),
        directory_users=(
            DirectoryUser("ivanov@corp.example", "Сергей Иванов", department="ИТ"),
            DirectoryUser("buh@corp.example", "Бухгалтерия", department="Финансовый отдел"),
        ),
        recipient_department="Финансовый отдел",
    )


@pytest.fixture(scope="session")
def ruleset():  # type: ignore[no-untyped-def]
    from msp_detection import default_ruleset

    return default_ruleset()


@pytest.fixture
def corpus():  # type: ignore[no-untyped-def]
    from fixtures.corpus import CORPUS

    return CORPUS
