"""Пакет конфигурации: контрольная сумма и проверка целостности (ТЗ 1.1 §39–§40).

Модуль вынесен отдельно ради одного свойства: **только стандартная библиотека**. Его используют
и центр управления, который генерирует пакеты, и узел, который их применяет. Узел работает в
образе транспорта, где нет зависимостей продукта (pydantic и прочего), — и не должен их
получать: каждая лишняя зависимость в образе, принимающем почту из Интернета, — это ещё одна
поверхность для уязвимости, не имеющая отношения к доставке.

Первая версия держала функцию суммы в генераторе (``render``), а тот импортировал модель
топологии на pydantic. Узел падал при запуске с ``ModuleNotFoundError``. Граница теперь
проверяется тестом, а не соглашением.
"""

from __future__ import annotations

import hashlib
import re

from . import validation


class BundleError(ValueError):
    """Пакет повреждён или не соответствует своему описанию."""


def bundle_checksum(files: dict[str, bytes]) -> str:
    """Сумма пакета. Одна функция на центр и узел: расхождение в способе счёта выглядело бы дрейфом."""
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(files[name])
        digest.update(b"\0")
    return digest.hexdigest()


def manifest_names(manifest: dict[str, object], key: str) -> list[str]:
    """Список имён из описания пакета. Другая форма — повреждённое описание, а не пустой список."""
    value = manifest.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise BundleError(f"описание пакета: поле {key} должно быть списком строк")
    return [str(item) for item in value]


def verify_bundle(files: dict[str, bytes], manifest: dict[str, object]) -> str:
    """Сверить пакет с описанием: контрольная сумма и состав файлов.

    Сумма считается заново на узле, а не берётся из описания на веру: пакет мог быть изменён
    по дороге (§62: подмена очереди и конфигурации), и описание, лежащее рядом с файлами,
    изменилось бы вместе с ними. Сверка полезна только тогда, когда ожидаемую сумму узел
    получает отдельным каналом; здесь она сверяется с описанием, а канал — забота вызывающего.
    """
    declared = manifest.get("checksum")
    actual = bundle_checksum(files)
    if declared != actual:
        raise BundleError("контрольная сумма пакета не совпадает с описанием")
    if sorted(files) != sorted(manifest_names(manifest, "files")):
        raise BundleError("состав файлов пакета не совпадает с описанием")
    for name in files:
        if "/" in name or "\\" in name or name.startswith("."):
            raise BundleError("имя файла пакета содержит путь")
    # Сумма защищает от порчи, но не от подмены: кто может изменить файл, может пересчитать сумму.
    # Содержимое поэтому проверяется независимо от того, как и кем пакет собран.
    if "main.cf" in files:
        check_main_cf(files["main.cf"].decode("utf-8", errors="replace"))
    if "master.cf" in files:
        check_master_cf(files["master.cf"].decode("utf-8", errors="replace"))
    _check_recipients_not_empty(files)
    return actual


def _check_recipients_not_empty(files: dict[str, bytes]) -> None:
    """Пакет с доменами для приёма и пустым справочником отверг бы всю почту (ТЗ §16).

    Панель такое обновление не выпускает, но узел не обязан верить панели: пустая карта на
    работающем узле — это отказ в обслуживании, а не «справочник ещё не загружен».
    """
    domains = files.get("relay_domains")
    recipients = files.get("relay_recipients")
    if domains is None or recipients is None:
        return
    if domains.strip() and not recipients.strip():
        raise BundleError("справочник получателей пуст при настроенных доменах приёма")


def version_id(manifest: dict[str, object]) -> str:
    version = manifest.get("version", 0)
    if isinstance(version, bool) or not isinstance(version, int):
        raise BundleError("описание пакета: version должен быть целым числом")
    return f"{version:06d}-{str(manifest['checksum'])[:12]}"


# ---------------------------------------------------------------------------------------------
# Белые списки содержимого (ТЗ 1.1 §62, §64)
# ---------------------------------------------------------------------------------------------
#: Параметры main.cf, которые вправе содержать пакет. Любой другой ключ — отказ.
MAIN_CF_PARAMETERS = frozenset(
    {
        "compatibility_level",
        "meta_directory",
        "myhostname",
        "myorigin",
        "mydestination",
        "local_recipient_maps",
        "local_transport",
        "alias_maps",
        "alias_database",
        "mynetworks",
        "inet_interfaces",
        "inet_protocols",
        "smtpd_banner",
        "biff",
        "append_dot_mydomain",
        "disable_vrfy_command",
        "smtpd_helo_required",
        "smtpd_forbid_bare_newline",
        "smtpd_forbid_bare_newline_exclusions",
        "smtpd_peername_lookup",
        "allow_percent_hack",
        "swap_bangpath",
        "allow_untrusted_routing",
        "maillog_file",
        "maillog_file_prefixes",
        "relay_domains",
        "relay_recipient_maps",
        "transport_maps",
        "smtpd_reject_unlisted_recipient",
        "default_transport",
        "message_size_limit",
        "mailbox_size_limit",
        "smtpd_recipient_limit",
        "header_size_limit",
        "smtpd_client_connection_count_limit",
        "smtpd_client_connection_rate_limit",
        "anvil_rate_time_unit",
        "default_process_limit",
        "smtpd_timeout",
        "smtpd_starttls_timeout",
        "maximal_queue_lifetime",
        "bounce_queue_lifetime",
        "queue_minfree",
        "hopcount_limit",
        "smtpd_tls_cert_file",
        "smtpd_tls_key_file",
        "smtpd_tls_CAfile",
        "smtpd_tls_security_level",
        "smtpd_tls_protocols",
        "smtpd_tls_mandatory_protocols",
        "smtp_tls_CAfile",
        "smtp_tls_security_level",
        "smtp_tls_protocols",
        "smtp_tls_mandatory_protocols",
        "smtp_tls_loglevel",
        "smtpd_tls_loglevel",
        "smtpd_tls_received_header",
        "smtp_tls_session_cache_database",
        "smtpd_tls_session_cache_database",
        "tls_random_source",
        "smtpd_restriction_classes",
        "msp_in_client",
        "msp_in_recipient",
        "msp_out_client",
        "msp_out_recipient",
        "milter_protocol",
        "milter_default_action",
        "milter_connect_timeout",
        "milter_command_timeout",
        "milter_content_timeout",
    }
)

#: Программы, которые master.cf вправе запускать. Это список того, что запускает Postfix от имени
#: root и postfix; всё прочее — произвольное исполнение кода.
MASTER_CF_COMMANDS = frozenset(
    {
        "smtpd",
        "pickup",
        "cleanup",
        "qmgr",
        "tlsmgr",
        "trivial-rewrite",
        "bounce",
        "verify",
        "flush",
        "proxymap",
        "smtp",
        "showq",
        "error",
        "discard",
        "anvil",
        "scache",
        "postlogd",
        "pipe",
    }
)

#: Параметры, которые вправе переопределять строки ``-o`` в master.cf.
MASTER_CF_OPTIONS = frozenset(
    {
        "syslog_name",
        "cleanup_service_name",
        "mynetworks",
        "smtpd_tls_security_level",
        "smtpd_client_restrictions",
        "smtpd_relay_restrictions",
        "smtpd_recipient_restrictions",
        "smtpd_data_restrictions",
        "smtpd_delay_reject",
        "always_bcc",
        "smtp_tls_security_level",
        "smtp_tls_verify_cert_match",
        "smtp_tls_mandatory_protocols",
        "smtp_fallback_relay",
        "smtpd_milters",
        "milter_macro_daemon_name",
        "content_filter",
        "smtpd_helo_restrictions",
        "smtpd_sender_restrictions",
    }
)

#: Единственный исполняемый файл, который транспорт pipe вправе запускать, и единственный
#: пользователь, от имени которого он это делает (не postfix: у него нет прав на очередь).
ALLOWED_PIPE_EXECUTABLE = "/usr/local/bin/msp-journal-write"
ALLOWED_PIPE_USER = "mspjournal"

_FILTER = re.compile(r"smtp:\[[0-9]{1,3}(\.[0-9]{1,3}){3}\]:[0-9]{4,5}")
_KEY_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*) =( |$)")
_SERVICE_TYPES = frozenset({"inet", "unix", "unix-dgram", "fifo", "pass"})


def check_main_cf(text: str) -> None:
    """Каждая строка main.cf — ``параметр = значение`` с параметром из белого списка."""
    if "\r" in text or "\0" in text:
        raise BundleError("main.cf: управляющий символ")
    for number, line in enumerate(text.splitlines(), start=1):
        if not line or line.startswith("#"):
            continue
        match = _KEY_LINE.match(line)
        if match is None:
            raise BundleError(f"main.cf:{number}: строка не похожа на «параметр = значение»")
        if match.group(1) not in MAIN_CF_PARAMETERS:
            raise BundleError(f"main.cf:{number}: параметр вне белого списка")
        _check_main_value(match.group(1), line.partition("=")[2].strip(), number)


#: Значения, которые узел не примет ни от кого, даже от панели с верной контрольной суммой.
_FIXED_MAIN_VALUES = {
    # Сбой сканера не должен останавливать почту: по умолчанию Postfix выбирает tempfail (ТЗ 1.2 §4).
    "milter_default_action": "accept",
    "milter_protocol": "6",
}


def _check_main_value(name: str, value: str, number: int) -> None:
    expected = _FIXED_MAIN_VALUES.get(name)
    if expected is not None and value != expected:
        raise BundleError(f"main.cf:{number}: значение параметра {name} зафиксировано")


def check_master_cf(text: str) -> None:
    """Каждая служба — известная команда; строки ``-o`` — известные параметры; pipe — единственный файл."""
    if "\r" in text or "\0" in text:
        raise BundleError("master.cf: управляющий символ")
    service = ""
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] in " \t":
            _check_master_continuation(service, line.strip(), number)
            continue
        fields = line.split()
        if len(fields) < 8 or fields[1] not in _SERVICE_TYPES:
            raise BundleError(f"master.cf:{number}: строка службы не разобрана")
        service = fields[0]
        if fields[7] not in MASTER_CF_COMMANDS:
            raise BundleError(f"master.cf:{number}: команда вне белого списка")
        # Команда и её аргументы в одной строке: допустимы только строки -o (после команды).
        rest = fields[8:]
        index = 0
        while index < len(rest):
            if rest[index] == "-o" and index + 1 < len(rest):
                _check_option(rest[index + 1], number)
                index += 2
            else:
                raise BundleError(f"master.cf:{number}: аргумент службы вне белого списка")


def _check_option(option: str, number: int) -> None:
    name, _, value = option.partition("=")
    if name not in MASTER_CF_OPTIONS:
        raise BundleError(f"master.cf:{number}: параметр -o вне белого списка")
    if name == "smtpd_milters" and value:
        # Сокет сканера — единственное значение с адресом: другая форма (список, макросы,
        # несколько сокетов) отвергается, а не нормализуется.
        try:
            validation.milter_socket(value, "smtpd_milters")
        except validation.ConfigValueError as error:
            raise BundleError(f"master.cf:{number}: сокет Milter не принят") from error
    if name == "content_filter" and value and not _FILTER.fullmatch(value):
        # Фильтр — единственный адрес вида smtp:[IPv4]:порт (или пусто для слушателя повторной подачи).
        raise BundleError(f"master.cf:{number}: content_filter не принят")
    if name == "milter_macro_daemon_name":
        # Это значение сканер пишет в Authentication-Results как authserv-id: оно должно быть
        # именем узла, уникальным среди узлов (ТЗ 1.2 §12).
        try:
            validation.hostname(value, "milter_macro_daemon_name")
        except validation.ConfigValueError as error:
            raise BundleError(f"master.cf:{number}: authserv-id Milter не принят") from error


def _check_master_continuation(service: str, line: str, number: int) -> None:
    if line.startswith("-o "):
        _check_option(line[3:].strip(), number)
        return
    if line.startswith("flags="):
        # Для pipe: R добавляет Return-Path. Остальные флаги меняют содержимое письма.
        if line.split()[0] != "flags=R" and not line.startswith("flags=R "):
            raise BundleError(f"master.cf:{number}: флаги pipe вне белого списка")
        for token in line.split()[1:]:
            if token.startswith("user=") and token != f"user={ALLOWED_PIPE_USER}":
                raise BundleError(f"master.cf:{number}: pipe запускается не от разрешённого пользователя")
        return
    if line.startswith("argv="):
        executable = line[len("argv=") :].split()[0] if line[len("argv=") :].split() else ""
        if executable != ALLOWED_PIPE_EXECUTABLE:
            raise BundleError(f"master.cf:{number}: pipe запускает не разрешённый исполняемый файл")
        return
    raise BundleError(f"master.cf:{number}: строка продолжения вне белого списка")
