"""Модель топологии шлюза (ТЗ 1.1 §9–§13, §18–§19, §23–§25, §28–§29, §64).

Из этой модели генерируется вся конфигурация Postfix, и ничего другого в конфигурацию попасть
не может. Это не удобство, а граница безопасности (§64): интерфейс и API не вставляют в MTA
«сырые директивы», они заполняют поля, а каждое поле имеет формат, который проверяется до
генерации.

Две вещи заданы здесь намеренно строже, чем это нужно для работы лаборатории.

**Доверие по источнику, а не по заявлению.** Нет поля «доверять отправителю с таким HELO» или
«доверять домену»: доверенная сторона — только подсеть (§12). HELO и From пишет клиент, а
значит, любой клиент.

**Небезопасные значения не имеют представления.** Нет TLS-режима «проверка отключена» для
рабочего профиля, нет доверенной сети «весь Интернет», нет режима, в котором шлюз молча
принимает неизвестных получателей. Поле, которого нет, нельзя выставить по ошибке.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import validation


class StrictModel(BaseModel):
    """Неизвестное поле — ошибка, а не молчаливо отброшенное значение.

    Опечатка в имени настройки безопасности («trusted_netwroks») иначе давала бы шлюз без
    доверенных сетей, который выглядит настроенным.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


# ---------------------------------------------------------------------------------------------
# Перечисления
# ---------------------------------------------------------------------------------------------
class DeploymentMode(StrEnum):
    """Режим развёртывания (ТЗ §59). ``GATEWAY_PRODUCTION`` появится позже и здесь отсутствует."""

    COMPANION_ONLY = "COMPANION_ONLY"
    GATEWAY_LAB = "GATEWAY_LAB"
    GATEWAY_PILOT = "GATEWAY_PILOT"


class TlsPolicy(StrEnum):
    """Что требуется от TLS на соединении.

    ``VERIFY`` — шифрование плюс проверка цепочки и имени. Режима «шифровать, не проверяя»
    нет: оно защищает от пассивного наблюдателя и не защищает от подмены, а выглядит как
    защита.
    """

    NONE = "NONE"
    OPPORTUNISTIC = "OPPORTUNISTIC"
    VERIFY = "VERIFY"


class Direction(StrEnum):
    """Направление, в котором домен допускается к релею."""

    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    BOTH = "BOTH"


class OutboundMode(StrEnum):
    """Куда уходит почта, адресованная не нашим доменам (ТЗ §22).

    По умолчанию доставка наружу выключена. ``INTERNET`` требует отдельного явного
    подтверждения в :class:`Outbound`.
    """

    DISABLED = "DISABLED"
    SINK = "SINK"
    UPSTREAM = "UPSTREAM"
    INTERNET = "INTERNET"


class InternalOwnedPolicy(StrEnum):
    """Что делать, когда доверенный источник отправляет письмо на наш же домен (ТЗ §53).

    ``REJECT_LOOP`` — отказ. Это умолчание, потому что единственная ситуация, в которой
    Exchange отдаёт шлюзу письмо для нашего же домена, — это неверная маршрутизация, и
    возврат такого письма в Exchange замыкает петлю.
    """

    REJECT_LOOP = "REJECT_LOOP"
    ROUTE_TO_EXCHANGE = "ROUTE_TO_EXCHANGE"


class TlsProfile(StrEnum):
    """Строгость TLS на внутренних участках."""

    LAB = "LAB"
    REQUIRED = "REQUIRED"


# ---------------------------------------------------------------------------------------------
# Элементы
# ---------------------------------------------------------------------------------------------
HostName = Annotated[str, Field(min_length=1, max_length=253)]


class Target(StrictModel):
    """Один сервер-получатель в маршруте (ТЗ §18)."""

    host: HostName
    port: int = 25
    tls_policy: TlsPolicy = TlsPolicy.VERIFY
    #: Меньше — раньше. Порядок задаёт очерёдность запасных вариантов (ТЗ §19).
    priority: int = Field(default=10, ge=0, le=1000)
    enabled: bool = True

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        return validation.hostname(value, "target.host")

    @field_validator("port")
    @classmethod
    def _port(cls, value: int) -> int:
        return validation.port(value, "target.port")


class Route(StrictModel):
    """Маршрут доставки: упорядоченный список целей.

    Запасные цели ведут себя как MX-хосты одного назначения: Postfix пробует следующую при
    **любом временном** отказе предыдущей — и когда соединение не установилось, и когда сервер
    ответил 4xx, в том числе после DATA. Постоянный отказ (5xx) на следующую цель не передаётся:
    письмо возвращается отправителю.

    Первая версия этого описания утверждала обратное («при 4xx письмо остаётся в очереди»);
    проверка на настоящем Postfix показала, что это не так. Для пула серверов Exchange с одними и
    теми же ящиками поведение разумно, но цели должны быть эквивалентны: письмо, временно
    отвергнутое одним сервером, получит другой.
    """

    name: str
    targets: tuple[Target, ...] = Field(min_length=1, max_length=8)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not value or not value.replace("-", "").replace("_", "").isalnum() or len(value) > 32:
            raise validation.ConfigValueError("route.name: допустимы буквы, цифры, «-», «_», до 32 символов")
        return value.lower()

    @model_validator(mode="after")
    def _uniform_tls(self) -> Self:
        # Запасные цели Postfix живут внутри одного транспорта и делят его настройки TLS.
        # Разные политики в одном маршруте означали бы, что запасной сервер получит политику
        # основного, а оператор будет считать, что задал ему свою.
        policies = {t.tls_policy for t in self.targets if t.enabled}
        if len(policies) > 1:
            raise validation.ConfigValueError(
                "route.targets: у целей одного маршрута должна быть одинаковая политика TLS"
            )
        return self

    @model_validator(mode="after")
    def _unique_priorities(self) -> Self:
        priorities = [t.priority for t in self.targets if t.enabled]
        if len(priorities) != len(set(priorities)):
            raise validation.ConfigValueError(
                "route.targets: у включённых целей приоритеты должны различаться — иначе порядок "
                "запасных вариантов не определён"
            )
        if not priorities:
            raise validation.ConfigValueError("route.targets: нет ни одной включённой цели")
        return self

    def ordered_targets(self) -> tuple[Target, ...]:
        return tuple(sorted((t for t in self.targets if t.enabled), key=lambda t: t.priority))


class RelayDomain(StrictModel):
    """Домен, для которого шлюз принимает почту (ТЗ §13)."""

    domain: str
    direction: Direction = Direction.INBOUND
    #: Имя маршрута. Обязательно для входящих доменов.
    route: str | None = None
    enabled: bool = True

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        return validation.domain(value, "relay_domain.domain")


class Limits(StrictModel):
    """Ограничения сообщений и соединений (ТЗ §24)."""

    max_message_size: int = Field(default=50 * 1024 * 1024, ge=1024, le=1024**3)
    max_recipients: int = Field(default=100, ge=1, le=10_000)
    max_header_size: int = Field(default=102_400, ge=1024, le=10 * 1024 * 1024)
    max_connections_per_client: int = Field(default=20, ge=1, le=10_000)
    max_concurrent_connections: int = Field(default=100, ge=1, le=10_000)
    #: Новых соединений от одного клиента в минуту.
    connection_rate_limit: int = Field(default=60, ge=1, le=100_000)
    command_timeout: int = Field(default=300, ge=5, le=3600)
    data_timeout: int = Field(default=600, ge=5, le=7200)
    idle_timeout: int = Field(default=300, ge=5, le=3600)
    #: Предел сообщения у Exchange, если он известен. Шлюз не должен быть строже: письмо,
    #: которое Exchange принял бы, а шлюз отверг, исчезает по вине промежуточного звена.
    downstream_max_message_size: int | None = Field(default=None, ge=1024)

    @model_validator(mode="after")
    def _not_below_downstream(self) -> Self:
        if self.downstream_max_message_size and self.max_message_size < self.downstream_max_message_size:
            raise validation.ConfigValueError(
                "limits.max_message_size: предел шлюза меньше предела Exchange — часть писем, "
                "допустимых для получателя, будет отвергнута промежуточным звеном"
            )
        return self


class Backpressure(StrictModel):
    """Пороги состояний давления (ТЗ §25)."""

    #: Свободное место, ниже которого состояние PRESSURE.
    disk_pressure_free_bytes: int = Field(default=2 * 1024**3, ge=1)
    #: Ниже этого шлюз временно отказывает новым сообщениям: принятая почта важнее новой.
    disk_critical_free_bytes: int = Field(default=512 * 1024**2, ge=1)
    queue_pressure_messages: int = Field(default=5_000, ge=1)
    queue_critical_messages: int = Field(default=20_000, ge=1)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.disk_critical_free_bytes >= self.disk_pressure_free_bytes:
            raise validation.ConfigValueError(
                "backpressure: критический порог диска должен быть ниже порога давления"
            )
        if self.queue_critical_messages <= self.queue_pressure_messages:
            raise validation.ConfigValueError(
                "backpressure: критический порог очереди должен быть выше порога давления"
            )
        return self


class TlsFiles(StrictModel):
    """Пути к сертификатам внутри контейнера. Сами ключи в конфигурацию не попадают (§41)."""

    certificate: str = "/run/secrets/gateway/tls.crt"
    private_key: str = "/run/secrets/gateway/tls.key"
    ca_bundle: str = "/run/secrets/gateway/ca.crt"

    @field_validator("certificate", "private_key", "ca_bundle")
    @classmethod
    def _path(cls, value: str) -> str:
        return validation.absolute_path(value, "tls.path")


class InboundListener(StrictModel):
    """Публичный приёмный порт (ТЗ §10)."""

    enabled: bool = True
    port: int = 25
    starttls: TlsPolicy = TlsPolicy.OPPORTUNISTIC
    #: Искать имя клиента по адресу. Синхронный запрос до приветствия: без доступного DNS он
    #: ждёт таймаута, и приветствие запаздывает. Нужен журналу и будущим проверкам HELO/PTR.
    peername_lookup: bool = True

    @field_validator("port")
    @classmethod
    def _port(cls, value: int) -> int:
        return validation.port(value, "inbound.port")


class InternalListener(StrictModel):
    """Порт доверенного источника — Exchange (ТЗ §11).

    Отдельная граница доверия: на этом порту разрешён релей наружу, и только с перечисленных
    подсетей. Интернет-клиенты не должны иметь до него сетевого доступа, но даже если
    получат, ``trusted_networks`` не пропустит их на уровне MTA.
    """

    enabled: bool = True
    port: int = 2525
    trusted_networks: tuple[str, ...] = ()
    #: STARTTLS обязателен всегда (ТЗ §23): незашифрованный участок между Exchange и шлюзом —
    #: это переписка организации в открытом виде внутри сети.
    owned_domain_policy: InternalOwnedPolicy = InternalOwnedPolicy.REJECT_LOOP

    @field_validator("port")
    @classmethod
    def _port(cls, value: int) -> int:
        return validation.port(value, "internal.port")

    @field_validator("trusted_networks")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(validation.network(item, "internal.trusted_networks") for item in value)

    @model_validator(mode="after")
    def _needs_sources(self) -> Self:
        if self.enabled and not self.trusted_networks:
            raise validation.ConfigValueError(
                "internal.trusted_networks: слушатель включён, а доверенных источников нет — "
                "такой шлюз либо недоступен для Exchange, либо (при ошибке в генерации) открыт всем"
            )
        return self


class Outbound(StrictModel):
    """Доставка писем нашим пользователям во внешний мир (ТЗ §22)."""

    mode: OutboundMode = OutboundMode.DISABLED
    host: str | None = None
    port: int = 25
    tls_policy: TlsPolicy = TlsPolicy.OPPORTUNISTIC
    #: Прямая доставка в Интернет — только после явного подтверждения. Не защита от
    #: злоумышленника, а защита от опечатки в режиме и от «временно включим для проверки».
    internet_delivery_acknowledged: bool = False

    @field_validator("host")
    @classmethod
    def _host(cls, value: str | None) -> str | None:
        return None if value is None else validation.hostname(value, "outbound.host")

    @field_validator("port")
    @classmethod
    def _port(cls, value: int) -> int:
        return validation.port(value, "outbound.port")

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.mode in (OutboundMode.SINK, OutboundMode.UPSTREAM) and not self.host:
            raise validation.ConfigValueError("outbound.host: для режима SINK/UPSTREAM нужен адрес")
        if self.mode is OutboundMode.INTERNET and not self.internet_delivery_acknowledged:
            raise validation.ConfigValueError(
                "outbound.mode: прямая доставка в Интернет не включена по умолчанию; "
                "подтвердите это явно (internet_delivery_acknowledged)"
            )
        return self


class Shadow(StrictModel):
    """Копия для анализа (ТЗ §34).

    Копия пишется в локальный журнал, а не отправляется по SMTP на коллектор. Это решение, а
    не упрощение: отправка на коллектор по сети откладывалась бы при его недоступности и в
    конце концов возвращала отправителю уведомление о недоставке (backscatter), то есть тень
    ломала бы поведение основной доставки. Запись в локальную папку почти всегда успешна и
    от коллектора не зависит.
    """

    enabled: bool = True
    journal_directory: str = "/var/lib/msp/journal"

    @field_validator("journal_directory")
    @classmethod
    def _dir(cls, value: str) -> str:
        return validation.absolute_path(value, "shadow.journal_directory")


class Milter(StrictModel):
    """Подключение сканера Rspamd через Milter (ТЗ 1.2 §3, §4, §5).

    Направление письма определяется слушателем, а не заголовком From: у публичного порта
    собственный сокет сканера, у внутреннего — другой. Действие по умолчанию при недоступности
    сканера зафиксировано как ``accept`` и не настраивается: на этапе 1.2 сбой анализа не имеет
    права остановить транспорт (``milter_default_action=tempfail`` превратил бы падение Rspamd
    в отказ приёма всей почты).
    """

    enabled: bool = False
    #: Сокеты в форме ``inet:IP:port`` или ``unix:/путь``. Имя хоста запрещено: см. validation.milter_socket.
    inbound_socket: str = "inet:127.0.0.1:11332"
    outbound_socket: str = "inet:127.0.0.1:11333"
    connect_timeout_seconds: int = Field(default=5, ge=1, le=30)
    command_timeout_seconds: int = Field(default=15, ge=1, le=120)
    content_timeout_seconds: int = Field(default=60, ge=1, le=600)

    @field_validator("inbound_socket", "outbound_socket")
    @classmethod
    def _socket(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        return validation.milter_socket(value, f"milter.{info.field_name}")


# ---------------------------------------------------------------------------------------------
# Целиком
# ---------------------------------------------------------------------------------------------
class GatewaySpec(StrictModel):
    """Желаемое состояние узла шлюза."""

    hostname: str
    mode: DeploymentMode = DeploymentMode.GATEWAY_LAB
    tls_profile: TlsProfile = TlsProfile.LAB
    relay_domains: tuple[RelayDomain, ...] = ()
    routes: tuple[Route, ...] = ()
    inbound: InboundListener = InboundListener()
    internal: InternalListener = InternalListener(enabled=False)
    limits: Limits = Limits()
    backpressure: Backpressure = Backpressure()
    tls: TlsFiles = TlsFiles()
    outbound: Outbound = Outbound()
    shadow: Shadow = Shadow()
    milter: Milter = Milter()
    #: Предел числа пересылок (Received). Защита от петли, не зависящая от заголовков,
    #: которые можно подделать (ТЗ §29).
    hopcount_limit: int = Field(default=20, ge=5, le=50)
    maximal_queue_lifetime_seconds: int = Field(default=5 * 86400, ge=60)
    bounce_queue_lifetime_seconds: int = Field(default=5 * 86400, ge=60)

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, value: str) -> str:
        return validation.hostname(value, "hostname")

    @model_validator(mode="after")
    def _cross_checks(self) -> Self:
        route_names = [r.name for r in self.routes]
        if len(route_names) != len(set(route_names)):
            raise validation.ConfigValueError("routes: имена маршрутов должны быть уникальны")
        domains = [d.domain for d in self.relay_domains]
        if len(domains) != len(set(domains)):
            raise validation.ConfigValueError("relay_domains: домен указан дважды")

        for item in self.relay_domains:
            if item.direction in (Direction.INBOUND, Direction.BOTH) and item.enabled:
                if not item.route:
                    raise validation.ConfigValueError("relay_domains: у входящего домена не указан маршрут")
                if item.route.lower() not in route_names:
                    raise validation.ConfigValueError("relay_domains: маршрут не существует")

        own = {self.hostname, "localhost", "127.0.0.1", "::1"}
        listening = {self.inbound.port, self.internal.port}
        for route in self.routes:
            for target in route.targets:
                if target.host in own and target.port in listening:
                    raise validation.ConfigValueError(
                        "routes: цель указывает на собственный слушатель шлюза — это петля"
                    )

        if self.tls_profile is TlsProfile.REQUIRED:
            for route in self.routes:
                for target in route.targets:
                    if target.enabled and target.tls_policy is not TlsPolicy.VERIFY:
                        raise validation.ConfigValueError(
                            "routes: в профиле REQUIRED доставка в Exchange идёт только с проверкой TLS"
                        )
        if self.mode is DeploymentMode.GATEWAY_PILOT and self.tls_profile is not TlsProfile.REQUIRED:
            raise validation.ConfigValueError(
                "tls_profile: режим GATEWAY_PILOT требует профиль REQUIRED — пилот на почте "
                "организации без проверки TLS внутри сети не допускается"
            )
        if self.mode is not DeploymentMode.GATEWAY_LAB and self.maximal_queue_lifetime_seconds < 86400:
            raise validation.ConfigValueError(
                "maximal_queue_lifetime_seconds: вне лаборатории срок жизни очереди не короче суток — "
                "короткий срок превращает кратковременный сбой Exchange в потерю почты"
            )
        return self

    def owned_domains(self) -> tuple[str, ...]:
        """Домены, для которых шлюз принимает входящую почту."""
        return tuple(
            sorted(
                d.domain
                for d in self.relay_domains
                if d.enabled and d.direction in (Direction.INBOUND, Direction.BOTH)
            )
        )

    def route_for(self, name: str) -> Route:
        for route in self.routes:
            if route.name == name.lower():
                return route
        raise validation.ConfigValueError("маршрут не существует")
