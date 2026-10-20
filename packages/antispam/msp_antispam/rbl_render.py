"""Правила провайдеров репутации для модуля rbl сканера (ТЗ 1.2 §14, §15).

Отдельный модуль, чтобы генерация правил не смешивалась с остальной конфигурацией: именно здесь
решается, какие данные письма уходят во внешний DNS. Правило создаётся только для провайдера,
который прошёл лицензионный допуск, и только для тех типов запросов, которые включены явно.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .model import QueryType

if TYPE_CHECKING:
    from .rspamd_config import RspamdNodeConfig

#: Тип запроса -> настройки правила модуля rbl. Включаются по одному (ТЗ 1.2 §15): «все проверки
#: сразу» не существует, а каждый тип уносит из письма свой кусок данных.
RBL_CHECKS: dict[QueryType, dict[str, str]] = {
    QueryType.CLIENT_IP: {"checks": "['from']", "no_ip": "false"},
    QueryType.HELO: {"checks": "['helo']", "no_ip": "true"},
    QueryType.RDNS: {"checks": "['rdns']", "no_ip": "true"},
    QueryType.SENDER_DOMAIN: {
        "checks": "[]",
        "no_ip": "true",
        "selector": 'from("smtp"):domain',
    },
    QueryType.DKIM_DOMAIN: {"checks": "['dkim']", "no_ip": "true"},
    QueryType.URL_HOST: {"checks": "['urls']", "no_ip": "true"},
    QueryType.REPLY_TO_DOMAIN: {"checks": "['replyto']", "no_ip": "true", "emails_domainonly": "true"},
}

_SAFE = re.compile(r"^[A-Za-z0-9_.\-/$(){}\"':,\[\] ]+$")


def quote(value: str) -> str:
    """Значение в кавычки UCL. Модель уже запретила кавычки и переводы строк; это второй барьер."""
    if re.search(r"[\\\n\r\x00]", value) or not _SAFE.match(value):
        raise ValueError("значение содержит недопустимый символ")
    return '"' + value.replace('"', '\\"') + '"'


def render_rbl(cfg: RspamdNodeConfig) -> str:
    """Секция модуля rbl целиком. Файл лежит в override.d: список публичных списков, который
    поставляется с пакетом, не должен остаться активным ни частично, ни «по умолчанию»."""
    rules: list[str] = []
    for provider in cfg.providers:
        if not provider.is_usable():
            continue
        for query in provider.query_types:
            options = RBL_CHECKS.get(query)
            if options is None:
                continue
            symbol = f"MSP_RBL_{provider.id.upper()}_{query.value}"
            # Имя зоны с секретом в выпуск не попадает: файл из хранилища секретов узла содержит одну
            # строку ``rbl = "<зона>";`` и подключается внутрь правила. Остальное правило типовое.
            if provider.zone_secret_file is not None:
                zone_line = f'        .include(try=false) "{provider.zone_secret_file}"'
            else:
                zone_line = f"        rbl = {quote(provider.zone_reference())};"
            codes = ", ".join(f'"{code}"' for code in provider.return_codes)
            lines = [
                f"    {provider.id}_{query.value.lower()} {{",
                f'        symbol = "{symbol}";',
                zone_line,
                f"        checks = {options['checks']};",
                f"        no_ip = {options['no_ip']};",
                "        ignore_defaults = true;",
                # Без значений по умолчанию семейства адресов нужно включить явно.
                "        ipv4 = true;",
                "        ipv6 = true;",
                "        disable_monitoring = true;",
                f"        returncodes {{ {symbol} = [{codes}]; }}",
            ]
            if "selector" in options:
                lines.append(f"        selector = {quote(options['selector'])};")
            if "emails_domainonly" in options:
                lines.append("        emails_domainonly = true;")
            lines.append("    }")
            rules.append("\n".join(lines) + "\n")
    if not rules:
        return "# Одобренных провайдеров репутации нет: модуль выключен.\nenabled = false;\n"
    return (
        "# Сгенерировано MSP. Секция заменяет пакетную целиком.\n"
        "enabled = true;\n"
        "default_exclude_users = true;\n"
        "default_unknown = false;\n"
        "url_whitelist = [];\n"
        "attached_maps = [];\n"
        'disabled_rbl_suffixes_map = "${LOCAL_CONFDIR}/maps.d/empty.map";\n'
        "rbls {\n" + "".join(rules) + "}\n"
    )
