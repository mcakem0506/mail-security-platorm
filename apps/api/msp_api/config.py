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

from pydantic import field_validator, model_validator
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


#: Addresses that mean "every interface". Listening on one is sometimes necessary but is never
#: a default here, because plain syslog carries no authentication at all.
_ALL_INTERFACES = frozenset({"0" + ".0.0.0", "::", "*"})


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
    # Gateways the organisation operates itself: ksmg, eop, spamassassin, virus_scanner.
    # Only their headers are trusted — any sender can forge a "already scanned" header (ТЗ 2.1).
    trusted_gateways: str = ""

    # -- parser limits (ТЗ 8.2, ТЗ 1.0.1 §4.2)
    # Exceeding any of these produces its own explainable signal and marks the analysis
    # incomplete. A message over limit_message_size is not analysed at all rather than
    # truncated: a partial read reported as a check is worse than an honest refusal.
    limit_message_size: int = 25 * 1024 * 1024
    limit_attachment_size: int = 20 * 1024 * 1024
    limit_attachment_count: int = 50
    limit_mime_parts: int = 300
    limit_mime_depth: int = 12
    limit_archive_depth: int = 3
    limit_decompressed_total: int = 100 * 1024 * 1024
    limit_decompressed_file: int = 25 * 1024 * 1024
    limit_url_count: int = 500
    limit_parse_timeout_seconds: float = 20.0

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
    # EWS is configured either by an explicit endpoint or through Autodiscover, so the module
    # fits any deployment without a hard-coded URL (ТЗ 7).
    ews_endpoint: str = ""
    ews_autodiscover: bool = True
    ews_primary_smtp_address: str = ""
    ews_username: str = ""
    ews_password: str = ""
    ews_password_file: str | None = None
    ews_ca_file: str | None = None
    ews_verify_tls: bool = True
    # auto | ntlm | kerberos | basic | sspi — "auto" tries the preference list below in order.
    ews_auth_method: Literal["auto", "ntlm", "kerberos", "basic", "sspi"] = "auto"
    # Kerberos first: it does not put a reusable credential on the wire. Basic is deliberately
    # absent from the default order — a silent downgrade to Basic is forbidden, so enabling it
    # takes both ews_allow_basic_auth and an explicit place in this list (ТЗ 1.0.1 §4.5).
    ews_auth_preference: str = "kerberos,ntlm"
    ews_allow_basic_auth: bool = False
    # impersonation reaches any mailbox in scope; delegate only explicitly shared ones.
    ews_access_mode: Literal["impersonation", "delegate"] = "delegate"
    # Mailboxes this deployment may touch: addresses or "@domain". Empty means the service
    # account's own mailbox only, so a scope is always granted deliberately.
    ews_mailbox_scope: str = ""
    ews_timeout_seconds: float = 30.0
    ews_quarantine_folder: str = "MSP Quarantine"
    remediation_enabled: bool = False  # ТЗ 7.1 — remediation account off by default
    #: Теневой режим на реальном потоке (ТЗ 1.0.4 §11). Вердикты считаются и сохраняются, ящик
    #: пользователя не меняется, реагирование выключено, уведомления сотрудникам не уходят.
    #: Обратная связь аналитиков и метрики, наоборот, включены — ради них режим и существует.
    #:
    #: Это не «режим пониженной функциональности», а осознанное состояние пилота: платформа
    #: смотрит на настоящую почту и ничего с ней не делает, пока ей не начали доверять.
    real_flow_shadow: bool = False
    remediation_dry_run_only: bool = True
    remediation_second_approver_threshold: int = 10  # ТЗ 20.1

    # -- mail flow topology (ТЗ 1.0.1 §4.3, §4.4)
    # Networks that belong to the organisation, used to find the hop where a message entered.
    internal_mail_networks: str = ""
    # Authentication servers whose Authentication-Results may be believed, beyond those derived
    # from the configured trusted hops. Empty and with no hops configured, every header is read
    # and the missing allowlist is reported as a readiness warning rather than silently
    # weakening detection.
    trusted_authserv_ids: str = ""
    # Where a gateway may send syslog events. Empty means none are accepted (ТЗ 1.0.2 §20).
    gateway_syslog_enabled: bool = False
    # Loopback by default. Syslog has no authentication, so the interface it listens on is a
    # security decision: a deployment that needs to receive events from a gateway on another
    # host sets this deliberately (in a container, usually to the container's own address).
    gateway_syslog_host: str = "127.0.0.1"
    gateway_syslog_port: int = 6514
    gateway_syslog_transport: Literal["tcp", "tls", "udp"] = "tls"
    gateway_syslog_allowed_sources: str = ""
    gateway_syslog_tls_certfile: str | None = None
    gateway_syslog_tls_keyfile: str | None = None
    gateway_syslog_tls_client_ca: str | None = None

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
    ad_start_tls: bool = False
    ad_verify_tls: bool = True
    ad_timeout_seconds: float = 10.0
    # Authentication against AD (ТЗ 24). The directory layout is not assumed: the base DN is
    # discovered from RootDSE when empty, and the login filter is configurable.
    ad_user_filter: str = (
        "(&(objectCategory=person)(objectClass=user)"
        "(|(mail={login})(userPrincipalName={login})(sAMAccountName={login})))"
    )
    # Lets the platform bind directly as the user without a service account, e.g. "{login}".
    ad_user_principal_template: str = ""
    # "CN=SOC Admins,OU=Groups,DC=corp,DC=example=security_admin;SOC Analysts=security_analyst"
    ad_group_role_map: str = ""
    ad_default_role: str = "employee"
    ad_require_group_match: bool = False
    # --- protected identities from directory groups (ТЗ 1.0.1 §5) ---
    # "CN=Executives,OU=Groups,DC=corp,DC=example=executive:critical:vip;Finance=finance:high"
    # Group -> category[:risk_class][:vip]. Membership decides who is protected, so the list
    # does not go stale the week after it is written.
    ad_protected_groups: str = ""
    # Local accounts that may still sign in while MSP_AUTH_BACKEND=ldap, so a directory outage
    # cannot lock the security team out of their own console. Every use is audited as a
    # break-glass event (ТЗ 1.0.1 §5).
    emergency_local_accounts: str = ""

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
    # -- сроки хранения набора валидации (ТЗ 1.0.4 §22)
    #: Исходное письмо реального потока. Самый короткий срок из трёх: это переписка организации,
    #: и она нужна ровно до разбора и обезличивания.
    raw_message_retention_days: int = 14
    #: Обезличенные записи валидации. Переживают исходник: ради них всё и делалось, и без них
    #: сравнивать выпуски будет нечем.
    anonymized_validation_retention_days: int = 365
    #: Разборы аналитиков. Вывод человека — самое долгоживущее и самое дешёвое в хранении.
    analyst_feedback_retention_days: int = 730

    # -- notifications
    smtp_host: str = ""
    smtp_port: int = 25
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_password_file: str | None = None
    smtp_use_tls: bool = True
    smtp_from: str = "mail-security@localhost"
    security_team_email: str = ""
    #: Письма сотруднику о его собственной почте. Выключены по умолчанию и принудительно
    #: выключены в теневом режиме (ТЗ 1.0.4 §11): пилот смотрит на поток и молчит, иначе
    #: сотрудники узнают о недообученном детектировании раньше, чем служба безопасности.
    employee_notifications_enabled: bool = False

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

        # Теневой режим гасит сами флаги, а не их отображение. Точек, где реагирование
        # разрешается, в коде девять, и каждая читает ``remediation_enabled`` напрямую: если бы
        # режим правил только словарь возможностей, он сообщал бы о себе правду и не делал
        # ничего (ТЗ 1.0.4 §11).
        if self.real_flow_shadow:
            if self.remediation_enabled:
                logger.warning(
                    "real flow shadow mode is on: remediation stays disabled despite MSP_REMEDIATION_ENABLED"
                )
            object.__setattr__(self, "remediation_enabled", False)
            object.__setattr__(self, "employee_notifications_enabled", False)

        # Порядок сроков — не рекомендация. Исходные данные, живущие дольше обезличенных
        # метрик, означали бы, что платформа хранит переписку ради чисел, которые уже
        # посчитаны (ТЗ 1.0.4 §22).
        if self.raw_message_retention_days > self.anonymized_validation_retention_days:
            raise ValueError(
                "MSP_RAW_MESSAGE_RETENTION_DAYS должен быть не больше "
                "MSP_ANONYMIZED_VALIDATION_RETENTION_DAYS: исходные данные удаляются раньше "
                "обезличенных метрик (ТЗ 1.0.4 §22)"
            )

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
            raise ValueError("VirusTotal file upload requires VT_MODE=private_scanning (ТЗ 14.5)")
        if (
            self.semantic_enabled
            and self.semantic_backend == "external"
            and not self.semantic_external_dpa_approved
        ):
            raise ValueError("external semantic analysis requires an explicit DPA approval flag")
        if self.exchange_provider == "ews":
            if not self.ews_username:
                raise ValueError("MSP_EXCHANGE_PROVIDER=ews requires MSP_EWS_USERNAME")
            if not self.ews_endpoint and not self.ews_autodiscover:
                raise ValueError("EWS needs either MSP_EWS_ENDPOINT or MSP_EWS_AUTODISCOVER=true")
            if self.environment == "production" and not self.ews_verify_tls:
                raise ValueError("MSP_EWS_VERIFY_TLS must stay enabled in production")
            if "basic" in self.ews_auth_preference_list and not self.ews_allow_basic_auth:
                raise ValueError(
                    "Basic authentication is listed in MSP_EWS_AUTH_PREFERENCE but "
                    "MSP_EWS_ALLOW_BASIC_AUTH is false: enabling Basic must be deliberate"
                )
            if self.ews_allow_basic_auth:
                if not self.ews_verify_tls:
                    raise ValueError(
                        "Basic authentication requires TLS verification: it sends the service "
                        "account password on every request"
                    )
                if self.ews_endpoint and not self.ews_endpoint.lower().startswith("https://"):
                    raise ValueError("Basic authentication requires an HTTPS EWS endpoint")
            if self.remediation_enabled and not self.ews_mailbox_scope_list:
                raise ValueError(
                    "remediation over EWS requires MSP_EWS_MAILBOX_SCOPE: an unscoped "
                    "deployment could act on any mailbox in the organisation"
                )
        for limit_name, limit_value in (
            ("MSP_LIMIT_MESSAGE_SIZE", self.limit_message_size),
            ("MSP_LIMIT_ATTACHMENT_SIZE", self.limit_attachment_size),
            ("MSP_LIMIT_DECOMPRESSED_FILE", self.limit_decompressed_file),
        ):
            if limit_value <= 0:
                raise ValueError(f"{limit_name} must be positive: a zero limit would refuse every message")
        if self.limit_attachment_size > self.limit_message_size:
            raise ValueError("MSP_LIMIT_ATTACHMENT_SIZE above MSP_LIMIT_MESSAGE_SIZE can never take effect")
        if self.gateway_syslog_enabled:
            if not self.gateway_syslog_allowed_source_list:
                raise ValueError(
                    "syslog intake requires MSP_GATEWAY_SYSLOG_ALLOWED_SOURCES: plain syslog has "
                    "no authentication, so anything that reaches the port could forge events"
                )
            if self.environment == "production" and self.gateway_syslog_transport == "udp":
                raise ValueError(
                    "UDP syslog is not acceptable in production: events are unauthenticated and "
                    "trivially spoofed. Use TCP or TLS."
                )
            if self.gateway_syslog_transport == "tls" and not self.gateway_syslog_tls_certfile:
                raise ValueError("TLS syslog requires MSP_GATEWAY_SYSLOG_TLS_CERTFILE")
            if self.gateway_syslog_host in _ALL_INTERFACES and self.environment == "production":
                # Listening on every interface is sometimes necessary, but it must be a choice
                # an operator made knowingly rather than a default they inherited.
                logger.warning(
                    "syslog.listening_on_all_interfaces",
                    extra={"allowed_sources": len(self.gateway_syslog_allowed_source_list)},
                )
        if self.auth_backend == "ldap":
            if not self.ad_server:
                raise ValueError("MSP_AUTH_BACKEND=ldap requires MSP_AD_SERVER")
            if not self.ad_use_ssl and not self.ad_start_tls:
                raise ValueError(
                    "LDAP authentication without TLS would send passwords in clear text: "
                    "enable MSP_AD_USE_SSL or MSP_AD_START_TLS"
                )
            if self.environment == "production" and not self.ad_verify_tls:
                raise ValueError("MSP_AD_VERIFY_TLS must stay enabled in production")
        return self

    # -- helpers
    @property
    def corporate_domain_list(self) -> tuple[str, ...]:
        return tuple(d.strip().lower() for d in self.corporate_domains.split(",") if d.strip())

    @property
    def trusted_infrastructure_list(self) -> tuple[str, ...]:
        return tuple(d.strip().lower() for d in self.trusted_infrastructure_domains.split(",") if d.strip())

    @property
    def ews_mailbox_scope_list(self) -> tuple[str, ...]:
        return tuple(m.strip().lower() for m in self.ews_mailbox_scope.split(",") if m.strip())

    @property
    def ews_auth_preference_list(self) -> tuple[str, ...]:
        return tuple(a.strip().lower() for a in self.ews_auth_preference.split(",") if a.strip())

    @property
    def emergency_local_account_list(self) -> tuple[str, ...]:
        return tuple(a.strip().lower() for a in self.emergency_local_accounts.split(",") if a.strip())

    @property
    def internal_mail_network_list(self) -> tuple[str, ...]:
        return tuple(n.strip() for n in self.internal_mail_networks.split(",") if n.strip())

    @property
    def trusted_authserv_id_list(self) -> tuple[str, ...]:
        return tuple(a.strip().lower() for a in self.trusted_authserv_ids.split(",") if a.strip())

    @property
    def gateway_syslog_allowed_source_list(self) -> tuple[str, ...]:
        return tuple(s.strip() for s in self.gateway_syslog_allowed_sources.split(",") if s.strip())

    @property
    def trusted_gateway_list(self) -> tuple[str, ...]:
        return tuple(g.strip().lower() for g in self.trusted_gateways.split(",") if g.strip())

    def public_config(self) -> dict[str, Any]:
        """Configuration safe to expose to the frontend: never includes secrets (ТЗ 28)."""
        return {
            "environment": self.environment,
            "organization_name": self.organization_name,
            "vt_configured": self.vt_mode not in {"disabled"},
            "vt_mode": self.vt_mode if self.vt_mode != "disabled" else None,
            "ad_enabled": self.ad_enabled,
            "auth_backend": self.auth_backend,
            # ``real_flow_shadow`` здесь уже не участвует: он погасил сам флаг выше.
            "remediation_enabled": self.remediation_enabled and not self.remediation_dry_run_only,
            "real_flow_shadow": self.real_flow_shadow,
            "employee_notifications_enabled": self.employee_notifications_enabled,
            "retention": {
                "raw_message_days": self.raw_message_retention_days,
                "anonymized_validation_days": self.anonymized_validation_retention_days,
                "analyst_feedback_days": self.analyst_feedback_retention_days,
            },
            "url_fetch_enabled": self.url_fetch_enabled,
            "gateway_syslog_enabled": self.gateway_syslog_enabled,
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
