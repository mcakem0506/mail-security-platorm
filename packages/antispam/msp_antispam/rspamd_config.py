"""Генерация и выпуск конфигурации Rspamd (ТЗ 1.2 §27, §31).

Правила, которые здесь зафиксированы:

* UI и база не принимают произвольный UCL или Lua: конфигурация собирается из проверяемой модели,
  где каждое значение проходит схему, а неизвестное поле — ошибка;
* файлы пакета не редактируются; всё лежит в ``local.d`` / ``maps.d`` / ``scripts`` выпуска;
* сторонние источники по умолчанию выключены (RBL, SURBL, emails, fuzzy, ASN, обновления):
  публичный DNSBL нельзя включать в корпоративной эксплуатации без проверки лицензии (§14);
* поток выпуска: generate → validate → stage → activate → reload → healthcheck → rollback.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .providers import ReputationProvider
from .rbl_render import render_rbl

SCHEMA_VERSION = 1

_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$")
_DOMAIN = _HOST
_PATH = re.compile(r"^/[A-Za-z0-9._/\-]{1,200}$")


def path_ok(value: str) -> bool:
    """Абсолютный путь без выхода из каталога: «..» и «//» недопустимы."""
    return bool(_PATH.match(value)) and ".." not in value.split("/") and "//" not in value


_ID = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_NETWORK = re.compile(r"^[0-9a-fA-F:.]+(/[0-9]{1,3})?$")


class ConfigError(ValueError):
    """Модель или результат генерации не принят. Текст не повторяет само значение."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RedisSettings(_Strict):
    host: str
    port: int = Field(default=6379, ge=1, le=65535)
    #: Пароль — файл в смонтированном хранилище секретов, не значение (§31).
    password_file: str | None = None

    @field_validator("host")
    @classmethod
    def _host_ok(cls, value: str) -> str:
        if not _HOST.match(value):
            raise ConfigError("redis.host: неверное имя")
        return value

    @field_validator("password_file")
    @classmethod
    def _pw(cls, value: str | None) -> str | None:
        if value is not None and not path_ok(value):
            raise ConfigError("redis.password_file: неверный путь")
        return value


#: Порог родных действий Rspamd, которого оценка не достигает: письмо не отклоняется, не откладывается
#: и не меняется.
UNREACHABLE_SCORE = 1000000.0


class Thresholds(_Strict):
    """Пороги предложения. В конфигурацию Rspamd они не попадают (там недостижимые значения): по ним
    панель считает ``suggested_action`` по оценке (§6)."""

    greylist: float = Field(default=4.0, ge=0, le=100)
    add_header: float = Field(default=6.0, ge=0, le=100)
    reject: float = Field(default=15.0, ge=0, le=100)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if not (self.greylist <= self.add_header <= self.reject):
            raise ConfigError("thresholds: порядок должен быть greylist <= add_header <= reject")
        return self


class SigningDomain(_Strict):
    domain: str
    selector: str
    #: Файл закрытого ключа в хранилище секретов. Сам ключ в конфигурацию не попадает (§22).
    private_key_file: str

    @field_validator("domain")
    @classmethod
    def _d(cls, value: str) -> str:
        if not _DOMAIN.match(value) or "." not in value:
            raise ConfigError("signing.domain: неверное имя")
        return value.lower()

    @field_validator("selector")
    @classmethod
    def _s(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9\-]{0,62}", value):
            raise ConfigError("signing.selector: неверное имя")
        return value

    @field_validator("private_key_file")
    @classmethod
    def _k(cls, value: str) -> str:
        if not path_ok(value):
            raise ConfigError("signing.private_key_file: неверный путь")
        return value


class DkimSigning(_Strict):
    """Подпись исходящей почты (§22–§24). Только доверенный путь Exchange → шлюз."""

    enabled: bool = False
    #: Подписывается только письмо с этих адресов. Для внешнего источника подпись невозможна.
    sign_networks: tuple[str, ...] = ()
    domains: tuple[SigningDomain, ...] = ()

    @field_validator("sign_networks")
    @classmethod
    def _n(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not _NETWORK.match(value):
                raise ConfigError("dkim_signing.sign_networks: неверная сеть")
            if value in ("0.0.0.0/0", "::/0") or value.endswith("/0"):
                raise ConfigError("dkim_signing.sign_networks: сеть «все адреса» недопустима")
        return values

    @model_validator(mode="after")
    def _need_networks(self) -> Self:
        if self.enabled and not self.sign_networks:
            raise ConfigError("dkim_signing: без доверенных сетей подпись включать нельзя")
        return self


class BayesSettings(_Strict):
    """Bayes включается только при готовности обучения (§20); автообучения по умолчанию нет."""

    enabled: bool = False
    min_learns: int = Field(default=200, ge=200, le=1_000_000)
    autolearn: bool = False


class EnforcementGate(_Strict):
    """Шлюз принуждения до очереди (ТЗ 1.3 §11, §13, §14). По умолчанию выключен.

    Адрес — только IP узла и фиксированный путь: произвольный адрес сделал бы сканер клиентом чужого сервиса.
    Тайм-аут ограничен сверху: ответ SMTP не должен ждать дольше (§14).
    """

    enabled: bool = False
    url: str = "http://127.0.0.1:11390/v1/decide"
    timeout_ms: int = Field(default=1500, ge=100, le=3000)

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        if not re.fullmatch(r"http://[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{2,5}/v1/decide", value):
            raise ConfigError("enforcement.url: ожидался http://IP:порт/v1/decide")
        return value


class RspamdNodeConfig(_Strict):
    """Желаемое состояние сканера на узле."""

    #: Уникальный authserv-id шлюза (§12). Входит в модель доверия платформы.
    authserv_id: str
    nameservers: tuple[str, ...] = ()
    dns_timeout_seconds: float = Field(default=2.0, ge=0.2, le=10)
    dns_retransmits: int = Field(default=1, ge=0, le=5)
    redis: RedisSettings | None = None
    thresholds: Thresholds = Thresholds()
    #: Куда сканер присылает результаты: TCP-приёмник MSP на узле.
    exporter_host: str = "127.0.0.1"
    exporter_port: int = Field(default=11380, ge=1, le=65535)
    controller_password_file: str = "/run/secrets/rspamd/controller.inc"  # noqa: S105
    providers: tuple[ReputationProvider, ...] = ()
    dkim_signing: DkimSigning = DkimSigning()
    bayes: BayesSettings = BayesSettings()
    greylisting: bool = False
    enforcement: EnforcementGate = EnforcementGate()
    #: Версия правил отображения символов (§26): едет вместе с каждым анализом.
    symbol_mapping_version: str = "1"
    #: Сети, которые сканер считает «своими» и для которых не проверяет SPF/DKIM. Только
    #: доверенный путь Exchange. Приватные адреса по умолчанию «своими» НЕ считаются: без этого
    #: сканер молча пропустил бы проверку для любого отправителя из частной сети (лаборатория).
    local_networks: tuple[str, ...] = ()
    #: Компиляция регулярных выражений Hyperscan занимает минуты при первом запуске. В стенде
    #: выключается, в рабочей установке остаётся включённой.
    hyperscan: bool = True

    @field_validator("authserv_id")
    @classmethod
    def _a(cls, value: str) -> str:
        if not _HOST.match(value):
            raise ConfigError("authserv_id: неверное имя")
        return value.lower()

    @field_validator("nameservers")
    @classmethod
    def _ns(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not re.fullmatch(r"[0-9a-fA-F:.]{3,45}", value):
                raise ConfigError("nameservers: неверный адрес")
        return values

    @field_validator("local_networks")
    @classmethod
    def _ln(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not _NETWORK.match(value) or value.endswith("/0"):
                raise ConfigError("local_networks: неверная сеть")
        return values

    @field_validator("exporter_host")
    @classmethod
    def _eh(cls, value: str) -> str:
        if not _HOST.match(value):
            raise ConfigError("exporter_host: неверное имя")
        return value

    @field_validator("controller_password_file")
    @classmethod
    def _cp(cls, value: str) -> str:
        if not path_ok(value):
            raise ConfigError("controller_password_file: неверный путь")
        return value

    @model_validator(mode="after")
    def _unique(self) -> Self:
        ids = [p.id for p in self.providers]
        if len(ids) != len(set(ids)):
            raise ConfigError("providers: идентификатор указан дважды")
        if self.bayes.enabled and self.redis is None:
            raise ConfigError("bayes: без Redis обучение хранить негде")
        if self.greylisting and self.redis is None:
            raise ConfigError("greylisting: без Redis состояние хранить негде")
        return self


# ---------------------------------------------------------------------------------------------
# Генерация
# ---------------------------------------------------------------------------------------------
#: Модули с обращением к сторонним сервисам. Выключены, пока не пройдут проверку лицензии и
#: приватности (§14, §31): запрос уносит адрес клиента, домен отправителя или ссылки из письма.
THIRD_PARTY_MODULES = (
    "surbl",
    "emails",
    "fuzzy_check",
    "asn",
    "phishing",
    "rspamd_update",
    "url_redirector",
    "mx_check",
    "dcc",
    "p0f",
    "antivirus",
    "external_services",
    "spamassassin",
    "neural",
    "clickhouse",
    "elastic",
    "gpt",
    "contextal",
    "aws_s3",
)

DIRECTIONS = ("inbound", "outbound")


def _q(value: str) -> str:
    """Значение в кавычки UCL. Модель уже запретила кавычки и переводы строк, это второй барьер."""
    if re.search(r"[\"\\\n\r\x00]", value):
        raise ConfigError("значение содержит недопустимый символ")
    return f'"{value}"'


def _render_options(cfg: RspamdNodeConfig) -> str:
    lines = ["# Сгенерировано MSP. Руками не править."]
    lines.append("dns {")
    if cfg.nameservers:
        lines.append("    nameserver = [" + ", ".join(_q(n) for n in cfg.nameservers) + "];")
    lines.append(f"    timeout = {cfg.dns_timeout_seconds}s;")
    lines.append(f"    retransmits = {cfg.dns_retransmits};")
    lines.append("}")
    lines.append("history_rows = 200;")
    if not cfg.hyperscan:
        lines.append("disable_hyperscan = true;")
    return "\n".join(lines) + "\n"


def _render_options_override(cfg: RspamdNodeConfig) -> str:
    """Список «своих» сетей заменяется, а не дополняется: слияние сохранило бы частные сети по
    умолчанию, и сканер молча пропускал бы проверки для любого отправителя из них."""
    local = ["127.0.0.0/8", "::1", *cfg.local_networks]
    # Шаблон GTUBE даёт родное действие reject, которое Milter исполнил бы. Для проверки
    # работоспособности сканера он не нужен: этап 1.2 ничего не отклоняет (§6). Значение должно
    # перекрыть умолчание, поэтому оно лежит в слое override.
    return (
        "# Сгенерировано MSP.\nlocal_addrs = [" + ", ".join(_q(n) for n in local) + "];\n"
        'gtube_patterns = "disabled";\n'
    )


def _render_proxy(direction: str) -> str:
    settings_id = f"msp_{direction}"
    return (
        "# Сгенерировано MSP. Направление задаёт слушатель, к которому подключился Postfix.\n"
        "milter = yes;\n"
        "timeout = 30s;\n"
        # Сканирование внутри воркера: малому стенду отдельный сканер не нужен (§4). Архитектура
        # не исключает отдельные сканеры: достаточно заменить upstream на хосты сканеров.
        f'upstream "local" {{ default = yes; self_scan = yes; settings_id = "{settings_id}"; }}\n'
        "count = 1;\n"
        "max_retries = 1;\n"
        "discard_on_reject = false;\n"
        "quarantine_on_reject = false;\n"
        # Заголовок вердикта в письмо не добавляется: оценка и решение сканера наружу не уходят (§31).
        'spam_header = "";\n'
    )


def _render_settings(cfg: RspamdNodeConfig) -> str:
    return (
        "# Сгенерировано MSP. Политика входящих и исходящих писем разделена (§5).\n"
        'msp_inbound { id = "msp_inbound"; apply { symbols = ["MSP_DIRECTION_INBOUND"]; } '
        'symbols_disabled = ["DKIM_SIGNED"]; }\n'
        'msp_outbound { id = "msp_outbound"; apply { symbols = ["MSP_DIRECTION_OUTBOUND"]; } }\n'
        'msp_internal_test { id = "msp_internal_test"; apply { symbols = ["MSP_DIRECTION_INTERNAL_TEST"]; } '
        'symbols_disabled = ["DKIM_SIGNED"]; }\n'
    )


def _render_actions(cfg: RspamdNodeConfig) -> str:
    del cfg
    # Milter исполняет родное действие сканера: reject отклоняет письмо, greylist и soft reject
    # откладывают его,
    # add header меняет. Поэтому на этапе 1.2 пороги этих действий недостижимы, а «предложение» панель считает
    # по оценке и порогам узла (``msp-advisory.json``). Наблюдение — свойство конфигурации сканера, а не
    # только пометка в панели (§6).
    return (
        f"reject = {UNREACHABLE_SCORE};\n"
        f"add_header = {UNREACHABLE_SCORE - 1};\n"
        f"greylist = {UNREACHABLE_SCORE - 2};\n"
    )


def _render_advisory(cfg: RspamdNodeConfig) -> str:
    t = cfg.thresholds
    body = {"greylist": t.greylist, "add_header": t.add_header, "reject": t.reject}
    return json.dumps(body, sort_keys=True) + "\n"


def _render_milter_headers(cfg: RspamdNodeConfig) -> str:
    return (
        "# Сгенерировано MSP. Наружу не публикуются ни оценка, ни топология, ни секреты (§31).\n"
        'use = ["authentication-results", "x-rspamd-queue-id", "remove-headers"];\n'
        "extended_spam_headers = false;\n"
        "skip_local = false;\n"
        "skip_authenticated = false;\n"
        "routines {\n"
        "    authentication-results {\n"
        '        header = "Authentication-Results";\n'
        # Чужие Authentication-Results (вышестоящий шлюз) не удаляются: они нужны для сравнения (§25).
        # По умолчанию сканер удаляет их все (remove = 0), поэтому отключение задано явно.
        "        remove = false;\n"
        "        add_smtp_user = false;\n"
        "    }\n"
        "    x-rspamd-queue-id {\n"
        '        header = "X-MSP-Scan-ID";\n'
        "        remove = 0;\n"
        "    }\n"
        "    remove-headers {\n"
        # Подделанные заголовки сканера из внешнего письма не должны стать доказательством (§7).
        "        headers {\n"
        '            "X-Spamd-Result" = 0;\n'
        '            "X-Spamd-Bar" = 0;\n'
        '            "X-Spam-Status" = 0;\n'
        '            "X-Spam" = 0;\n'
        '            "X-Spam-Flag" = 0;\n'
        '            "X-Spam-Level" = 0;\n'
        '            "X-Rspamd-Score" = 0;\n'
        '            "X-Rspamd-Action" = 0;\n'
        '            "X-Rspamd-Server" = 0;\n'
        '            "X-Rspamd-Queue-Id" = 0;\n'
        "        }\n"
        "    }\n"
        "}\n"
        'authenticated_headers = ["authentication-results"];\n'
    )


def _render_authserv(cfg: RspamdNodeConfig) -> str:
    return f"hostname = {_q(cfg.authserv_id)};\n"


def _render_metadata_exporter(cfg: RspamdNodeConfig) -> str:
    return (
        "# Сгенерировано MSP. Результат уходит приёмнику MSP на узле, а не в письмо.\n"
        "rules {\n"
        "    MSP_SCAN {\n"
        '        backend = "json_raw_tcp";\n'
        f"        host = {_q(cfg.exporter_host)};\n"
        f"        port = {cfg.exporter_port};\n"
        '        selector = "default";\n'
        '        formatter = "json";\n'
        "        timeout = 3s;\n"
        "        defer = false;\n"
        "    }\n"
        "}\n"
    )


def _render_modules_off() -> dict[str, str]:
    body = "# Сгенерировано MSP: сторонний сервис выключен до проверки лицензии.\nenabled = false;\n"
    return {f"{name}.conf": body for name in THIRD_PARTY_MODULES}


def _render_dmarc() -> str:
    return (
        "# Сгенерировано MSP. Отчёты и родные действия DMARC выключены: на этапе 1.2 политика домена\n"
        "# сохраняется как предлагаемое решение, доставка продолжается (§10).\n"
        "reporting {\n    enabled = false;\n}\n"
        "actions = {};\n"
    )


def _render_spf() -> str:
    return "spf_cache_size = 2k;\nmax_dns_nesting = 10;\nmax_dns_requests = 40;\n"


def _render_dkim_verify() -> str:
    return (
        '# Сгенерировано MSP.\nsymbol_allow = "R_DKIM_ALLOW";\ntrusted_only = false;\nskip_multi = false;\n'
    )


def _render_redis(cfg: RspamdNodeConfig) -> str:
    if cfg.redis is None:
        return "# Redis не настроен: Bayes, репутация и greylisting работают частично (§30).\n"
    lines = [f"servers = {_q(f'{cfg.redis.host}:{cfg.redis.port}')};", "timeout = 1s;"]
    if cfg.redis.password_file:
        lines.append(f'.include(try=false) "{cfg.redis.password_file}"')
    return "\n".join(lines) + "\n"


def _render_dkim_signing(cfg: RspamdNodeConfig) -> tuple[str, str, str]:
    s = cfg.dkim_signing
    if not s.enabled or not s.domains:
        return "enabled = false;\n", "", ""
    ordered = sorted(s.domains, key=lambda d: d.domain)
    selectors = "".join(f"{d.domain} {d.selector}\n" for d in ordered)
    keymap = "".join(f"{d.domain} {d.private_key_file}\n" for d in ordered)
    conf = (
        "# Сгенерировано MSP. Подписываются только письма с доверенных сетей и только домены с\n"
        "# активным ключом; внешний источник подпись корпоративного домена получить не может (§23).\n"
        "enabled = true;\n"
        "sign_authenticated = false;\n"
        "sign_local = false;\n"
        "sign_inbound = false;\n"
        "sign_networks = [" + ", ".join(_q(n) for n in s.sign_networks) + "];\n"
        'use_domain = "header";\n'
        "use_esld = false;\n"
        "allow_hdrfrom_mismatch = false;\n"
        "allow_hdrfrom_multiple = false;\n"
        "allow_username_mismatch = true;\n"
        "try_fallback = false;\n"
        'selector_map = "${LOCAL_CONFDIR}/maps.d/dkim_selectors.map";\n'
        'path_map = "${LOCAL_CONFDIR}/maps.d/dkim_keys.map";\n'
        'symbol = "DKIM_SIGNED";\n'
    )
    return conf, selectors, keymap


def _render_statistic(cfg: RspamdNodeConfig) -> str:
    if not cfg.bayes.enabled:
        return (
            "# Bayes выключен: состояние NOT_TRAINED, обучения по своей оценке нет (§20).\n"
            'classifier "bayes" { enabled = false; autolearn = false; }\n'
        )
    return (
        'classifier "bayes" {\n'
        '    backend = "redis";\n'
        f"    min_learns = {cfg.bayes.min_learns};\n"
        f"    autolearn = {'true' if cfg.bayes.autolearn else 'false'};\n"
        "}\n"
    )


def _render_enforcement(cfg: RspamdNodeConfig) -> str:
    g = cfg.enforcement
    if not g.enabled:
        return "# Шлюз принуждения выключен.\nenabled = false;\n"
    return (
        "# Сгенерировано MSP. Решение принимает локальная служба по подписанной политике.\n"
        "enabled = true;\n"
        f"url = {_q(g.url)};\n"
        f"timeout = {g.timeout_ms / 1000:.3f};\n"
    )


def _render_greylist(cfg: RspamdNodeConfig) -> str:
    return f"enabled = {'true' if cfg.greylisting else 'false'};\n"


@dataclass(frozen=True)
class RenderedRspamd:
    files: dict[str, bytes]
    checksum: str
    config_version: str


def render(cfg: RspamdNodeConfig) -> RenderedRspamd:
    files: dict[str, str] = {
        "local.d/options.inc": _render_options(cfg),
        "override.d/options.inc": _render_options_override(cfg),
        "local.d/worker-proxy-inbound.inc": _render_proxy("inbound"),
        "local.d/worker-proxy-outbound.inc": _render_proxy("outbound"),
        "local.d/worker-controller.inc": (
            "# Контроллер слушает только 127.0.0.1; пароль — из хранилища секретов (§31).\n"
            'secure_ip = "127.0.0.1";\n'
            f'.include(try=false) "{cfg.controller_password_file}"\n'
        ),
        "local.d/settings.conf": _render_settings(cfg),
        "local.d/actions.conf": _render_actions(cfg),
        "msp-advisory.json": _render_advisory(cfg),
        "local.d/milter_headers.conf": _render_milter_headers(cfg),
        "local.d/metadata_exporter.conf": _render_metadata_exporter(cfg),
        "local.d/dmarc.conf": _render_dmarc(),
        "local.d/spf.conf": _render_spf(),
        "local.d/dkim.conf": _render_dkim_verify(),
        "local.d/redis.conf": _render_redis(cfg),
        "local.d/greylist.conf": _render_greylist(cfg),
        "local.d/msp_enforcement.conf": _render_enforcement(cfg),
        "local.d/statistic.conf": _render_statistic(cfg),
        "override.d/rbl.conf": render_rbl(cfg),
        "maps.d/empty.map": "",
        "local.d/arc.conf": "allow_envfrom_empty = true;\nallow_hdrfrom_mismatch = true;\n",
        "local.d/hfilter.conf": "# Сгенерировано MSP.\nenabled = true;\n",
        "local.d/logging.inc": 'level = "info";\n',
    }
    for name, body in _render_modules_off().items():
        files[f"local.d/{name}"] = body
    files["rspamd.local.lua"] = (Path(__file__).parent / "lua" / "rspamd.local.lua").read_text(
        encoding="utf-8"
    )
    signing, selectors_map, keys_map = _render_dkim_signing(cfg)
    files["local.d/dkim_signing.conf"] = signing
    files["maps.d/dkim_selectors.map"] = selectors_map
    files["maps.d/dkim_keys.map"] = keys_map
    for name, body in files.items():
        if "\r" in body or "\0" in body:
            raise ConfigError(f"{name}: управляющий символ")
    blobs = {name: body.encode("utf-8") for name, body in files.items()}
    digest = hashlib.sha256()
    for name in sorted(blobs):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(blobs[name])
        digest.update(b"\0")
    checksum = digest.hexdigest()
    return RenderedRspamd(files=blobs, checksum=checksum, config_version=checksum[:12])


# ---------------------------------------------------------------------------------------------
# Выпуск: stage → validate → activate → reload → healthcheck → rollback (§27)
# ---------------------------------------------------------------------------------------------
class ReleaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReleaseOutcome:
    outcome: str  # ACTIVE | REJECTED | ROLLED_BACK
    config_version: str
    detail: str = ""


class ReleaseStore:
    """Каталог выпусков: ``releases/<версия>/`` и символическая ссылка ``active``."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.releases = self.root / "releases"
        self.active_link = self.root / "active"
        self.manifest_name = "MANIFEST.json"

    def stage(self, rendered: RenderedRspamd) -> Path:
        target = self.releases / rendered.config_version
        target.mkdir(parents=True, exist_ok=True)
        for name, blob in rendered.files.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
        manifest = {
            "schema": SCHEMA_VERSION,
            "config_version": rendered.config_version,
            "checksum": rendered.checksum,
            "files": sorted(rendered.files),
        }
        (target / self.manifest_name).write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        return target

    def active_version(self) -> str | None:
        if not self.active_link.exists():
            return None
        return self.active_link.resolve().name

    def activate(self, version: str) -> None:
        target = self.releases / version
        if not target.is_dir():
            raise ReleaseError("выпуск не найден")
        tmp = self.root / ".active.new"
        if tmp.is_symlink() or tmp.exists():
            tmp.unlink()
        tmp.symlink_to(target, target_is_directory=True)
        tmp.replace(self.active_link)

    def verify(self, version: str) -> bool:
        target = self.releases / version
        manifest_path = target / self.manifest_name
        if not manifest_path.is_file():
            return False
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        digest = hashlib.sha256()
        for name in sorted(manifest["files"]):
            blob = (target / name).read_bytes()
            digest.update(name.encode())
            digest.update(b"\0")
            digest.update(blob)
            digest.update(b"\0")
        return digest.hexdigest() == manifest["checksum"]


def apply_release(
    store: ReleaseStore,
    cfg: RspamdNodeConfig,
    *,
    configtest: Callable[[Path], tuple[bool, str]],
    reload: Callable[[], None],
    healthcheck: Callable[[], bool],
    audit: Callable[[Path], tuple[bool, str]] | None = None,
) -> ReleaseOutcome:
    """Выпустить конфигурацию. При любой неудаче рабочая версия остаётся прежней."""
    try:
        rendered = render(cfg)
    except (ConfigError, ValueError) as error:
        return ReleaseOutcome("REJECTED", "", f"модель не принята: {error.__class__.__name__}")
    staged = store.stage(rendered)
    ok, detail = configtest(staged)
    if not ok:
        return ReleaseOutcome("REJECTED", rendered.config_version, f"configtest: {detail[:200]}")
    if audit is not None:
        # Неизвестный источник reject или soft reject блокирует активацию (ТЗ 1.3 §50).
        clean, audit_detail = audit(staged)
        if not clean:
            return ReleaseOutcome(
                "REJECTED", rendered.config_version, f"effective actions: {audit_detail[:300]}"
            )
    previous = store.active_version()
    store.activate(rendered.config_version)
    try:
        reload()
        healthy = healthcheck()
    except Exception as error:  # noqa: BLE001 - любая ошибка перезагрузки означает откат
        healthy = False
        detail = error.__class__.__name__
    if healthy:
        return ReleaseOutcome("ACTIVE", rendered.config_version)
    if previous:
        store.activate(previous)
        # Откат уже выполнен ссылкой; если перезагрузка не удалась, повторит оператор.
        with contextlib.suppress(Exception):
            reload()
    return ReleaseOutcome("ROLLED_BACK", rendered.config_version, detail or "проверка здоровья не пройдена")


def drift_state(reported_checksum: str | None, expected_checksum: str | None) -> str:
    """``IN_SYNC`` | ``DRIFTED`` | ``UNKNOWN`` (§27)."""
    if not reported_checksum or not expected_checksum:
        return "UNKNOWN"
    return "IN_SYNC" if reported_checksum == expected_checksum else "DRIFTED"


def providers_in(cfg: RspamdNodeConfig) -> Mapping[str, ReputationProvider]:
    return {p.id: p for p in cfg.providers}
