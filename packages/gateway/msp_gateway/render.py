"""Генерация конфигурации Postfix из модели топологии (ТЗ 1.1 §13, §39, §64).

Генерация детерминирована: одна и та же модель даёт побайтно один и тот же результат, и поэтому
контрольная сумма пакета — это отпечаток **смысла** конфигурации. На ней держится обнаружение
дрейфа (§40): узел сообщает контрольную сумму того, что у него активно, и расхождение с тем,
что хотел центр управления, видно без чтения файлов.

Защита от инъекций устроена в два слоя, потому что одного мало.

1. Поля модели проверены до генерации (:mod:`validation`), и в конфигурацию попадают только
   они.
2. Готовый ``main.cf`` после генерации разбирается обратно, и **каждый** ключ должен входить в
   белый список :data:`MAIN_CF_PARAMETERS`. Если шаблон когда-нибудь будет изменён так, что
   значение сможет протащить строку-директиву, второй слой это поймает независимо от первого.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .bundle import (
    BundleError,
    bundle_checksum,
    check_main_cf,
)
from .recipients import RecipientEntry, map_text
from .spec import (
    DeploymentMode,
    Direction,
    GatewaySpec,
    InternalOwnedPolicy,
    OutboundMode,
    Route,
    TlsPolicy,
)

#: Домен-приёмник копии для анализа. Зарезервированная зона ``.invalid`` никогда не существует в
#: DNS, поэтому ошибка маршрутизации не отправит копию наружу.
JOURNAL_DOMAIN = "journal.msp.invalid"

#: Каталог изменяемых состояний. Живёт вне версий конфигурации: смена версии не должна сбрасывать
#: режим слива или состояние справочника получателей.
DEFAULT_STATE_DIR = "/var/lib/msp/state"


class RenderError(RuntimeError):
    """Результат генерации нельзя выпускать."""


@dataclass(frozen=True)
class Recipient:
    """Адресат справочника в том виде, в каком он попадает в карту."""

    address: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class RenderedConfig:
    files: dict[str, bytes]
    checksum: str
    manifest: dict[str, object] = field(default_factory=dict)


def _tls_security(policy: TlsPolicy) -> str:
    return {TlsPolicy.NONE: "none", TlsPolicy.OPPORTUNISTIC: "may", TlsPolicy.VERIFY: "verify"}[policy]


def _nexthop(route: Route) -> str:
    primary = route.ordered_targets()[0]
    return f"[{primary.host}]:{primary.port}"


def _transport_name(route: Route) -> str:
    return f"msp-r-{route.name}"


def render_main_cf(spec: GatewaySpec, *, config_dir: str, state_dir: str, log_file: str) -> str:
    limits = spec.limits
    smtpd_timeout = max(limits.command_timeout, limits.data_timeout, limits.idle_timeout)
    # Запас от места: Postfix сам отказывает новым сообщениям, когда свободно меньше этого, и
    # предупреждает при значении ниже 1,5 размера сообщения — берём не меньше двух.
    queue_minfree = max(spec.backpressure.disk_critical_free_bytes, 2 * limits.max_message_size)

    if spec.internal.owned_domain_policy is InternalOwnedPolicy.REJECT_LOOP:
        out_recipient = f"check_recipient_access hash:{config_dir}/owned_domains, permit"
    else:
        out_recipient = "permit"

    if spec.outbound.mode is OutboundMode.DISABLED:
        default_transport = "error:5.7.1 outbound delivery is disabled"
    elif spec.outbound.mode in (OutboundMode.SINK, OutboundMode.UPSTREAM):
        default_transport = f"msp-outbound:[{spec.outbound.host}]:{spec.outbound.port}"
    else:
        default_transport = "msp-outbound"

    lines = [
        "# Сгенерировано шлюзом MSP. Руками не править: изменения будут отменены при смене версии.",
        "compatibility_level = 3.9",
        "meta_directory = /etc/postfix",
        f"myhostname = {spec.hostname}",
        "myorigin = $myhostname",
        # Локальной доставки нет совсем: шлюз только передаёт почту дальше.
        "mydestination =",
        "local_recipient_maps =",
        "local_transport = error:5.2.1 local delivery is disabled",
        "alias_maps =",
        "alias_database =",
        # Глобально доверенных сетей нет; каждый слушатель задаёт свои.
        "mynetworks = 127.0.0.0/8",
        "inet_interfaces = all",
        "inet_protocols = ipv4",
        # Версию Postfix в приветствии не раскрываем.
        "smtpd_banner = $myhostname ESMTP",
        "biff = no",
        "append_dot_mydomain = no",
        "disable_vrfy_command = yes",
        "smtpd_helo_required = yes",
        # Маршрут внутри адреса — классический обход проверки релея: «user%внешний@наш» проходит
        # проверку по домену «наш», а доставляется на «внешний». Шлюз принимает адреса только в
        # обычной форме, поэтому все три приёма выключены явно, а не по умолчанию Postfix.
        "allow_percent_hack = no",
        "swap_bangpath = no",
        "allow_untrusted_routing = no",
        f"smtpd_peername_lookup = {'yes' if spec.inbound.peername_lookup else 'no'}",
        # SMTP smuggling (ТЗ §63): голый LF не нормализуется, а отвергается.
        "smtpd_forbid_bare_newline = reject",
        "smtpd_forbid_bare_newline_exclusions =",
        f"maillog_file = {log_file}",
        # Ограничения с пробелами в значении в master.cf ненадёжны (пробел разделяет поля), а
        # классы ограничений — штатный способ дать им имя и сослаться на него одним словом.
        "smtpd_restriction_classes = msp_in_client, msp_in_recipient, msp_out_client, msp_out_recipient",
        f"msp_in_client = check_client_access pcre:{state_dir}/drain.pcre",
        f"msp_in_recipient = check_recipient_access pcre:{state_dir}/recipient_gate.pcre,"
        " reject_unlisted_recipient",
        f"msp_out_client = check_client_access pcre:{state_dir}/drain.pcre, permit_mynetworks, reject",
        f"msp_out_recipient = {out_recipient}",
        f"relay_domains = hash:{config_dir}/relay_domains",
        f"relay_recipient_maps = hash:{config_dir}/relay_recipients",
        f"transport_maps = hash:{config_dir}/transport",
        # Неизвестный получатель отвергается явной проверкой в списке ограничений слушателя,
        # а не неявной: так перед ней можно поставить проверку свежести справочника (§16).
        "smtpd_reject_unlisted_recipient = no",
        f"default_transport = {default_transport}",
        f"message_size_limit = {limits.max_message_size}",
        "mailbox_size_limit = 0",
        f"smtpd_recipient_limit = {limits.max_recipients}",
        f"header_size_limit = {limits.max_header_size}",
        f"smtpd_client_connection_count_limit = {limits.max_connections_per_client}",
        f"smtpd_client_connection_rate_limit = {limits.connection_rate_limit}",
        "anvil_rate_time_unit = 60s",
        f"default_process_limit = {limits.max_concurrent_connections}",
        # Postfix не различает таймауты команды, данных и простоя: одно значение на каждое
        # чтение. Берётся наибольшее из трёх, иначе легитимная передача данных оборвётся
        # по более короткому пределу команд.
        f"smtpd_timeout = {smtpd_timeout}s",
        "smtpd_starttls_timeout = 300s",
        f"maximal_queue_lifetime = {spec.maximal_queue_lifetime_seconds}s",
        f"bounce_queue_lifetime = {spec.bounce_queue_lifetime_seconds}s",
        f"queue_minfree = {queue_minfree}",
        f"hopcount_limit = {spec.hopcount_limit}",
        f"smtpd_tls_cert_file = {spec.tls.certificate}",
        f"smtpd_tls_key_file = {spec.tls.private_key}",
        f"smtpd_tls_CAfile = {spec.tls.ca_bundle}",
        f"smtpd_tls_security_level = {_tls_security(spec.inbound.starttls)}",
        "smtpd_tls_protocols = >=TLSv1.2",
        "smtpd_tls_mandatory_protocols = >=TLSv1.2",
        f"smtp_tls_CAfile = {spec.tls.ca_bundle}",
        "smtp_tls_security_level = may",
        "smtp_tls_protocols = >=TLSv1.2",
        "smtp_tls_mandatory_protocols = >=TLSv1.2",
        "smtp_tls_loglevel = 1",
        "smtpd_tls_loglevel = 1",
        "smtpd_tls_received_header = yes",
        "smtp_tls_session_cache_database =",
        "smtpd_tls_session_cache_database =",
        "tls_random_source = dev:/dev/urandom",
    ]
    text = "\n".join(lines) + "\n"
    _assert_whitelisted(text)
    return text


def _assert_whitelisted(main_cf: str) -> None:
    """Второй слой защиты от инъекции: в main.cf только известные параметры.

    Списки общие с узлом (:mod:`bundle`): то, что допускает узел, и то, что генерирует центр,
    не могут разойтись.
    """
    try:
        check_main_cf(main_cf)
    except BundleError as exc:
        raise RenderError(str(exc)) from exc


def render_master_cf(spec: GatewaySpec, *, config_dir: str, state_dir: str) -> str:
    out: list[str] = [
        "# Сгенерировано шлюзом MSP. Руками не править.",
        "# service type  private unpriv  chroot  wakeup  maxproc command + args",
    ]

    if spec.inbound.enabled:
        out += [
            f"{spec.inbound.port} inet n - n - - smtpd",
            "  -o syslog_name=postfix-in",
            "  -o cleanup_service_name=msp-cleanup-in",
            # Пустой список: на публичном порту доверенных источников нет вообще, и
            # permit_mynetworks никогда не сработает, как бы ни был заполнен main.cf.
            "  -o mynetworks=",
            f"  -o smtpd_tls_security_level={_tls_security(spec.inbound.starttls)}",
            "  -o smtpd_client_restrictions=msp_in_client",
            "  -o smtpd_relay_restrictions=reject_unauth_destination",
            "  -o smtpd_recipient_restrictions=msp_in_recipient,permit",
            "  -o smtpd_data_restrictions=reject_unauth_pipelining",
        ]

    if spec.internal.enabled:
        relay = (
            "permit_mynetworks,reject"
            if spec.outbound.mode is not OutboundMode.DISABLED
            else "reject_unauth_destination"
        )
        out += [
            f"{spec.internal.port} inet n - n - - smtpd",
            "  -o syslog_name=postfix-out",
            "  -o cleanup_service_name=msp-cleanup-out",
            f"  -o mynetworks={','.join(spec.internal.trusted_networks)}",
            # STARTTLS на внутреннем порту обязателен всегда (ТЗ §23).
            "  -o smtpd_tls_security_level=encrypt",
            # Чужие отвергаются при подключении, а не на RCPT: им незачем даже начинать сессию.
            "  -o smtpd_delay_reject=no",
            "  -o smtpd_client_restrictions=msp_out_client",
            f"  -o smtpd_relay_restrictions={relay}",
            "  -o smtpd_recipient_restrictions=msp_out_recipient",
            "  -o smtpd_data_restrictions=reject_unauth_pipelining",
        ]

    out += _standard_services()

    shadow_user = "mspjournal"
    if spec.shadow.enabled:
        out += [
            "msp-cleanup-in unix n - n - 0 cleanup",
            f"  -o always_bcc=journal-in@{JOURNAL_DOMAIN}",
            "msp-cleanup-out unix n - n - 0 cleanup",
            f"  -o always_bcc=journal-out@{JOURNAL_DOMAIN}",
            # Копия не может задержать основную доставку: pipe пишет в локальную папку и
            # завершается успешно даже при сбое записи (сбой считается метрикой, а не
            # возвращается отправителю уведомлением о недоставке).
            "msp-journal unix - n n - 10 pipe",
            f"  flags=R user={shadow_user}",
            "  argv=/usr/local/bin/msp-journal-write ${queue_id} ${recipient} ${sender} "
            "${client_address} ${client_helo} ${size}",
        ]
    else:
        out += [
            "msp-cleanup-in unix n - n - 0 cleanup",
            "msp-cleanup-out unix n - n - 0 cleanup",
        ]

    for route in spec.routes:
        ordered = route.ordered_targets()
        policy = ordered[0].tls_policy
        out.append(f"{_transport_name(route)} unix - - n - - smtp")
        out.append(f"  -o smtp_tls_security_level={_tls_security(policy)}")
        if policy is TlsPolicy.VERIFY:
            out.append("  -o smtp_tls_verify_cert_match=hostname")
            out.append("  -o smtp_tls_mandatory_protocols=>=TLSv1.2")
        if len(ordered) > 1:
            fallback = ",".join(f"[{t.host}]:{t.port}" for t in ordered[1:])
            out.append(f"  -o smtp_fallback_relay={fallback}")

    if spec.outbound.mode is not OutboundMode.DISABLED:
        out.append("msp-outbound unix - - n - - smtp")
        out.append(f"  -o smtp_tls_security_level={_tls_security(spec.outbound.tls_policy)}")

    return "\n".join(out) + "\n"


def _standard_services() -> list[str]:
    """Служебные сервисы Postfix. Состав — минимально необходимый для транспорта."""
    return [
        "pickup unix n - n 60 1 pickup",
        "cleanup unix n - n - 0 cleanup",
        "qmgr unix n - n 300 1 qmgr",
        "tlsmgr unix - - n 1000? 1 tlsmgr",
        "rewrite unix - - n - - trivial-rewrite",
        "bounce unix - - n - 0 bounce",
        "defer unix - - n - 0 bounce",
        "trace unix - - n - 0 bounce",
        "verify unix - - n - 1 verify",
        "flush unix n - n 1000 0 flush",
        "proxymap unix - - n - - proxymap",
        "proxywrite unix - - n - 1 proxymap",
        "smtp unix - - n - - smtp",
        "relay unix - - n - - smtp",
        "showq unix n - n - - showq",
        "error unix - - n - - error",
        "retry unix - - n - - error",
        "discard unix - - n - - discard",
        "anvil unix - - n - 1 anvil",
        "scache unix - - n - 1 scache",
        "postlog unix-dgram n - n - 1 postlogd",
    ]


def render_relay_domains(spec: GatewaySpec) -> str:
    return "".join(f"{domain} OK\n" for domain in spec.owned_domains())


def render_owned_domains(spec: GatewaySpec) -> str:
    """Карта для отказа в петле: доверенный источник не должен возвращать нам наш же домен."""
    reason = "REJECT 5.4.6 Routing loop prevented: an owned domain must not be relayed back to the gateway"
    return "".join(f"{domain} {reason}\n" for domain in spec.owned_domains())


def render_transport(spec: GatewaySpec) -> str:
    rows: list[tuple[str, str]] = []
    for item in spec.relay_domains:
        if not item.enabled or item.direction is Direction.OUTBOUND or not item.route:
            continue
        route = spec.route_for(item.route)
        rows.append((item.domain, f"{_transport_name(route)}:{_nexthop(route)}"))
    if spec.shadow.enabled:
        rows.append((JOURNAL_DOMAIN, "msp-journal:"))
    rows.sort()
    return "".join(f"{key} {value}\n" for key, value in rows)


def render_relay_recipients(recipients: list[Recipient]) -> str:
    return map_text(RecipientEntry(item.address, aliases=item.aliases) for item in recipients)


def render(
    spec: GatewaySpec,
    recipients: list[Recipient] | None = None,
    *,
    recipients_meta: dict[str, object] | None = None,
    version: int = 0,
    config_dir: str = "/var/lib/msp/config/active",
    state_dir: str = DEFAULT_STATE_DIR,
    log_file: str = "/var/log/msp/postfix.log",
) -> RenderedConfig:
    """Собрать пакет конфигурации."""
    files = {
        "main.cf": render_main_cf(
            spec, config_dir=config_dir, state_dir=state_dir, log_file=log_file
        ).encode(),
        "master.cf": render_master_cf(spec, config_dir=config_dir, state_dir=state_dir).encode(),
        "relay_domains": render_relay_domains(spec).encode(),
        "owned_domains": render_owned_domains(spec).encode(),
        "transport": render_transport(spec).encode(),
        "relay_recipients": render_relay_recipients(recipients or []).encode(),
    }
    checksum = bundle_checksum(files)
    manifest: dict[str, object] = {
        "version": version,
        "checksum": checksum,
        "mode": spec.mode.value,
        "hash_maps": ["relay_domains", "owned_domains", "transport", "relay_recipients"],
        # Свежесть справочника: время формирования выгрузки, а не время применения пакета.
        "recipients": recipients_meta,
        "files": sorted(files),
        "deployment": "MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER"
        if spec.mode is not DeploymentMode.COMPANION_ONLY
        else "companion",
    }
    return RenderedConfig(files=files, checksum=checksum, manifest=manifest)


def manifest_bytes(config: RenderedConfig) -> bytes:
    return json.dumps(config.manifest, ensure_ascii=False, sort_keys=True, indent=2).encode()
