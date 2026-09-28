"""Application settings (ТЗ 28, 29, 30).

Secrets are never committed and never reach the frontend. Any setting ending in ``_file`` is read
from disk at startup, which is how Docker secrets and Vault-injected files are supported; the
plain env variant stays available for the pilot.
"""

from __future__ import annotations

import logging
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_SECRET_FIELDS = (
    "secret_key",
    "vt_api_key",
    "ad_bind_password",
    "security_mailbox_password",
    "ews_password",
    "smtp_password",
)


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    file = Path(path)
    if not file.is_file():
        logger.error("secret file not found: %s", path)
        return None
    return file.read_text(encoding="utf-8").strip() or None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MSP_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # -- runtime
    environment: Literal["development", "test", "staging", "production"] = "development"
    debug: bool = False
    api_root_path: str = ""
    public_base_url: str = "http://localhost:8080"
    request_timeout_seconds: float = 30.0

    # -- database / cache / storage
    database_url: str = "postgresql+psycopg://msp:msp@postgres:5432/msp"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    redis_url: str = "redis://redis:6379/0"
    object_storage_endpoint: str = "http://object-storage:9000"
    object_storage_bucket: str = "msp-content"
    object_storage_access_key: str = ""
    object_storage_secret_key: str = ""
    object_storage_secret_key_file: str | None = None
    object_storage_secure: bool = False
    object_storage_backend: Literal["s3", "filesystem"] = "s3"
    object_storage_path: str = "/var/lib/msp/content"

    # -- auth
    secret_key: str = ""
    secret_key_file: str | None = None
    session_ttl_minutes: int = 60
    session_idle_minutes: int = 20
    privileged_session_ttl_minutes: int = 30
    cookie_secure: bool = True
    cookie_domain: str | None = None
    cookie_name: str = "msp_session"
    csrf_cookie_name: str = "msp_csrf"
    auth_backend: Literal["local", "ldap", "oidc"] = "local"
    require_mfa_for_privileged: bool = True
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    bootstrap_admin_email: str | None = None

    # -- rate limits (ТЗ 30)
    rate_limit_login_per_minute: int = 10
    rate_limit_analysis_per_minute: int = 30
    rate_limit_api_per_minute: int = 300
    max_upload_bytes: int = 26 * 1024 * 1024

    # -- organisation defaults
    organization_name: str = "Организация"
    corporate_domains: str = ""
    trusted_infrastructure_domains: str = ""

    # -- detection thresholds
    suspicious_threshold: int = 25
    high_risk_threshold: int = 50
    malicious_threshold: int = 80

    # -- VirusTotal (ТЗ 14)
    vt_mode: Literal["disabled", "mock", "premium", "private_scanning"] = "disabled"
    vt_api_key: str = ""
    vt_api_key_file: str | None = None
    vt_allow_file_upload: bool = False
    vt_per_minute_limit: int = 300
    vt_per_day_limit: int = 50_000
    vt_timeout_seconds: float = 8.0

    # -- TI privacy policy (ТЗ 2.4)
    ti_allow_hash: bool = True
    ti_allow_domain: bool = True
    ti_allow_ip: bool = True
    ti_allow_url: bool = False
    ti_allow_url_path: bool = False
    ti_allow_sender_email: bool = False
    ti_allow_internal_domains: bool = False
    ti_timeout_seconds: float = 6.0

    # -- scanners
    clamav_enabled: bool = False
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    clamav_unix_socket: str | None = None
    clamav_max_size: int = 50 * 1024 * 1024

    # -- Exchange / security mailbox (ТЗ 7)
    exchange_provider: Literal["mock", "security_mailbox", "ews"] = "mock"
    security_mailbox_host: str = ""
    security_mailbox_port: int = 993
    security_mailbox_user: str = ""
    security_mailbox_password: str = ""
    security_mailbox_password_file: str | None = None
    security_mailbox_folder: str = "INBOX"
    security_mailbox_ssl: bool = True
    security_mailbox_ca_file: str | None = None
    ews_endpoint: str = ""
    ews_username: str = ""
    ews_password: str = ""
    ews_password_file: str | None = None
    ews_ca_file: str | None = None
    remediation_enabled: bool = False  # ТЗ 7.1 — remediation account off by default
    remediation_dry_run_only: bool = True
    remediation_second_approver_threshold: int = 10  # ТЗ 20.1

    # -- Active Directory (ТЗ 10)
    ad_enabled: bool = False
    ad_server: str = ""
    ad_port: int = 636
    ad_use_ssl: bool = True
    ad_bind_dn: str = ""
    ad_bind_password: str = ""
    ad_bind_password_file: str | None = None
    ad_base_dn: str = ""
    ad_ca_file: str | None = None
    ad_sync_interval_minutes: int = 360
    ad_include_optional_attributes: bool = False

    # -- semantic analysis (ТЗ 16.4)
    semantic_enabled: bool = False
    semantic_backend: Literal["disabled", "local", "external"] = "disabled"
    semantic_endpoint: str = ""
    semantic_external_dpa_approved: bool = False

    # -- URL fetching (ТЗ 11.4) — off by default, isolated egress required
    url_fetch_enabled: bool = False
    url_fetch_proxy: str | None = None
    url_fetch_timeout_seconds: float = 5.0
    url_fetch_max_redirects: int = 3
    url_fetch_max_body_bytes: int = 512 * 1024

    # -- retention (days, ТЗ 27)
    retention_metadata_days: int = 180
    retention_analysis_days: int = 365
    retention_raw_eml_days: int = 30
    retention_attachment_days: int = 30
    retention_audit_days: int = 400
    retention_malicious_sample_days: int = 365

    # -- notifications
    smtp_host: str = ""
    smtp_port: int = 25
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_password_file: str | None = None
    smtp_use_tls: bool = True
    smtp_from: str = "mail-security@localhost"
    security_team_email: str = ""

    # -- observability
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"
    metrics_enabled: bool = True

    @field_validator("corporate_domains", "trusted_infrastructure_domains")
    @classmethod
    def _strip(cls, value: str) -> str:
        return (value or "").strip()

    @model_validator(mode="after")
    def _load_secret_files(self) -> Settings:
        for field_name in _SECRET_FIELDS:
            file_attr = f"{field_name}_file"
            if not hasattr(self, file_attr):
                continue
            value = _read_secret_file(getattr(self, file_attr, None))
            if value:
                object.__setattr__(self, field_name, value)
        storage_secret = _read_secret_file(self.object_storage_secret_key_file)
        if storage_secret:
            object.__setattr__(self, "object_storage_secret_key", storage_secret)

        if not self.secret_key:
            if self.environment == "production":
                raise ValueError("MSP_SECRET_KEY (or MSP_SECRET_KEY_FILE) is required in production")
            object.__setattr__(self, "secret_key", secrets.token_urlsafe(48))
            logger.warning("generated an ephemeral secret key: sessions reset on restart")
        if self.environment == "production":
            if not self.cookie_secure:
                raise ValueError("cookie_secure must stay enabled in production")
            if self.vt_mode == "premium" and not self.vt_api_key:
                raise ValueError("VT_MODE=premium requires an API key")
            if self.debug:
                raise ValueError("debug must be disabled in production")
        if self.vt_allow_file_upload and self.vt_mode != "private_scanning":
            raise ValueError(
                "VirusTotal file upload requires VT_MODE=private_scanning (ТЗ 14.5)"
            )
        if self.semantic_enabled and self.semantic_backend == "external" and not self.semantic_external_dpa_approved:
            raise ValueError("external semantic analysis requires an explicit DPA approval flag")
        return self

    # -- helpers
    @property
    def corporate_domain_list(self) -> tuple[str, ...]:
        return tuple(d.strip().lower() for d in self.corporate_domains.split(",") if d.strip())

    @property
    def trusted_infrastructure_list(self) -> tuple[str, ...]:
        return tuple(d.strip().lower() for d in self.trusted_infrastructure_domains.split(",") if d.strip())

    def public_config(self) -> dict[str, Any]:
        """Configuration safe to expose to the frontend: never includes secrets (ТЗ 28)."""
        return {
            "environment": self.environment,
            "organization_name": self.organization_name,
            "vt_configured": self.vt_mode not in {"disabled"},
            "vt_mode": self.vt_mode if self.vt_mode != "disabled" else None,
            "ad_enabled": self.ad_enabled,
            "remediation_enabled": self.remediation_enabled and not self.remediation_dry_run_only,
            "url_fetch_enabled": self.url_fetch_enabled,
            "semantic_enabled": self.semantic_enabled,
            "thresholds": {
                "suspicious": self.suspicious_threshold,
                "high_risk": self.high_risk_threshold,
                "malicious": self.malicious_threshold,
            },
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
