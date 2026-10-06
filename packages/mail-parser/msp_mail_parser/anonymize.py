"""Обезличивание письма для валидации на реальном потоке (ТЗ 1.0.4 §9).

Задача здесь двойная и в этом вся сложность: **убрать персональные данные, не разрушив то, на
чём работает детектирование**. Письмо, из которого вычистили всё подряд, безопасно и бесполезно:
по нему нельзя проверить ни расхождение Reply-To, ни похожесть домена, ни результаты
аутентификации.

Поэтому обезличивание устроено как замена, а не как удаление, и замена **устойчивая**: один и
тот же адрес в одном и том же письме и в разных письмах одного набора превращается в один и тот
же псевдоним. Иначе «письмо от того же отправителя» перестало бы быть видно, а это ровно тот
признак, которым живёт корреляция кампаний.

Что сохраняется дословно (ТЗ §9):

* домены — и корпоративный, и внешние: отношения между ними и есть предмет анализа;
* расхождение Reply-To: локальные части разные до замены — разные и после;
* хост ссылки, кроме внутренних адресов организации;
* структура MIME, тип и контрольная сумма вложения;
* результаты аутентификации (``Authentication-Results``, ``Received-SPF``, ``DKIM-Signature``).

Что заменяется:

* локальные части адресов;
* отображаемые имена;
* телефоны и номера счетов;
* внутренние ссылки организации (целиком, вместе с хостом);
* ``Message-ID`` и ``References`` — при экспорте;
* строки, объявленные секретами организации.

Псевдоним считается через HMAC с солью набора данных. Соль не хранится вместе с результатом:
без неё восстановить адрес нельзя, а с ней — можно сверить, что два письма пришли от одного
отправителя, не зная, от кого именно.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from typing import Any

from .domains import split_domain, to_ascii

#: Заголовки, которые нельзя трогать: на них держится проверка подлинности письма.
PRESERVED_HEADERS: frozenset[str] = frozenset(
    {
        "authentication-results",
        "arc-authentication-results",
        "received-spf",
        "dkim-signature",
        "arc-seal",
        "arc-message-signature",
        "received",
        "content-type",
        "content-transfer-encoding",
        "content-disposition",
        "mime-version",
        "date",
    }
)

#: Заголовки с адресами: в них заменяются локальные части и отображаемые имена.
ADDRESS_HEADERS: tuple[str, ...] = (
    "from",
    "to",
    "cc",
    "bcc",
    "reply-to",
    "sender",
    "return-path",
    "x-original-sender",
    "x-sender",
    "delivered-to",
    "x-envelope-from",
    "x-envelope-to",
)

#: Заголовки, удаляемые при экспорте: они связывают письмо с конкретной перепиской.
EXPORT_STRIPPED_HEADERS: tuple[str, ...] = (
    "message-id",
    "references",
    "in-reply-to",
    "thread-index",
    "thread-topic",
    "x-ms-exchange-organization-network-message-id",
)

_ADDRESS_RE = re.compile(r"([A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
#: Телефон в международной или местной записи. Намеренно широкое: лучше заменить лишнее, чем
#: оставить настоящий номер.
_PHONE_RE = re.compile(r"(?<![\w-])(?:\+\d{1,3}[\s(-]*)?(?:\d[\s()-]*){9,14}\d(?![\w-])")
#: Номер счёта или карты: длинные последовательности цифр, возможно сгруппированные.
_ACCOUNT_RE = re.compile(r"(?<![\w.])\d{4}(?:[\s-]?\d{4}){2,5}(?![\w.])")
#: Длинная цифровая строка — расчётный счёт, ИНН, лицевой счёт.
_LONG_DIGITS_RE = re.compile(r"(?<![\w.])\d{11,20}(?![\w.])")

_PSEUDONYM_LENGTH = 10


@dataclass
class AnonymizationPolicy:
    """Что именно делать. Значения по умолчанию — самые осторожные."""

    #: Домены организации: ссылки на них считаются внутренними и заменяются целиком.
    corporate_domains: tuple[str, ...] = ()
    #: Строки, которые организация объявила своими секретами (имена систем, внутренние коды).
    organization_secrets: tuple[str, ...] = ()
    #: Убирать заголовки, связывающие письмо с перепиской. При экспорте — обязательно.
    strip_thread_headers: bool = True
    #: Оставлять байты вложений. По умолчанию нет: вложение — самое вероятное место, где
    #: окажется договор с фамилиями. Тип, имя, размер и контрольная сумма сохраняются как
    #: данные, поэтому «тип и хеш вложения» (ТЗ §9) не теряются.
    keep_attachment_bytes: bool = False
    #: Заменять телефоны и номера счетов в тексте.
    mask_numbers: bool = True


@dataclass
class AnonymizationResult:
    raw: bytes
    #: Сколько замен каждого вида сделано. Нужно, чтобы «обезличено» было проверяемым
    #: утверждением, а не отметкой в интерфейсе.
    replacements: dict[str, int] = field(default_factory=dict)
    #: Контрольные суммы вложений до замены: тип и хеш обязаны сохраниться (ТЗ §9).
    attachments: list[dict[str, Any]] = field(default_factory=list)
    #: Отпечаток письма, устойчивый к обезличиванию: по нему два экземпляра одного письма
    #: узнаются друг в друге, а восстановить содержимое по нему нельзя.
    fingerprint: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "replacements": dict(self.replacements),
            "attachments": list(self.attachments),
            "fingerprint": self.fingerprint,
        }


class Anonymizer:
    """Устойчивая замена персональных данных в границах одного набора.

    Соль задаётся вызывающей стороной и живёт столько же, сколько набор валидации. Один и тот же
    адрес даёт один и тот же псевдоним, пока соль та же; смена соли делает прежние псевдонимы
    несопоставимыми, и это свойство используется при экспорте наружу.
    """

    def __init__(self, salt: bytes, policy: AnonymizationPolicy | None = None) -> None:
        if not salt:
            raise ValueError("соль обязательна: без неё псевдонимы предсказуемы")
        self._salt = salt
        self.policy = policy or AnonymizationPolicy()
        self._counts: dict[str, int] = {}
        self._corporate = {to_ascii(domain).lower() for domain in self.policy.corporate_domains}

    # -- псевдонимы ----------------------------------------------------------------------------
    def _token(self, kind: str, value: str) -> str:
        digest = hmac.new(self._salt, f"{kind}:{value.strip().lower()}".encode(), hashlib.sha256).hexdigest()
        return digest[:_PSEUDONYM_LENGTH]

    def _count(self, kind: str) -> None:
        self._counts[kind] = self._counts.get(kind, 0) + 1

    def local_part(self, local: str, domain: str) -> str:
        """Псевдоним локальной части, устойчивый в пределах домена.

        Домен входит в основание: один и тот же ``info`` у двух контрагентов — разные люди, и
        сливать их в один псевдоним означало бы придумать связь, которой нет.
        """
        self._count("local_parts")
        return f"user-{self._token('local', f'{local}@{domain}')}"

    def display_name(self, name: str) -> str:
        self._count("display_names")
        return f"Person {self._token('name', name)[:6].upper()}"

    def is_internal(self, host: str) -> bool:
        host_ascii = to_ascii(host).lower()
        if not host_ascii:
            return False
        registrable = split_domain(host_ascii).registrable_ascii
        return host_ascii in self._corporate or registrable in self._corporate

    # -- текст ---------------------------------------------------------------------------------
    def text(self, value: str) -> str:
        """Обезличить произвольный текст: адреса, телефоны, номера, секреты организации."""
        if not value:
            return value

        def replace_address(match: re.Match[str]) -> str:
            local, domain = match.group(1), match.group(2)
            return f"{self.local_part(local, domain)}@{domain}"

        result = _ADDRESS_RE.sub(replace_address, value)

        for secret in self.policy.organization_secrets:
            if secret and secret in result:
                result = result.replace(secret, "[секрет организации]")
                self._count("organization_secrets")

        if self.policy.mask_numbers:

            def replace_account(match: re.Match[str]) -> str:
                self._count("account_numbers")
                return f"[счёт {self._token('account', match.group(0))[:6]}]"

            def replace_phone(match: re.Match[str]) -> str:
                self._count("phone_numbers")
                return f"[телефон {self._token('phone', match.group(0))[:6]}]"

            # Номера счетов — первыми: их запись пересекается с телефонной, и порядок решает,
            # чем окажется строка из шестнадцати цифр.
            result = _ACCOUNT_RE.sub(replace_account, result)
            result = _LONG_DIGITS_RE.sub(replace_account, result)
            result = _PHONE_RE.sub(replace_phone, result)
        return result

    def url(self, raw: str) -> str:
        """Внешняя ссылка сохраняет хост, внутренняя заменяется целиком.

        Хост внешней ссылки — это и есть предмет анализа: по нему видно и похожий домен, и
        подозрительную зону, и расхождение с видимым текстом. Внутренний адрес, наоборот,
        описывает устройство организации, и наружу ему нельзя.
        """
        match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s]+)(.*)$", raw)
        if not match:
            return raw
        scheme, authority, rest = match.groups()
        host = authority.rsplit("@", 1)[-1].split(":")[0]
        if self.is_internal(host):
            self._count("internal_urls")
            return f"{scheme}internal-{self._token('host', host)}.invalid/[внутренний адрес]"
        # Путь и строка запроса могут нести идентификаторы получателя.
        self._count("url_paths")
        return f"{scheme}{authority}/[путь скрыт]" if rest.strip("/") else f"{scheme}{authority}{rest}"

    # -- заголовки с адресами ------------------------------------------------------------------
    def address_header(self, value: str) -> str:
        """Переписать заголовок с адресами, сохранив форму и расхождения.

        Разбор нарочно текстовый, а не через ``email.utils``: заголовок недоверенного письма
        может быть сформирован так, что разбор его «исправит», а нам нужно сохранить именно то,
        что в нём написано — на этом держатся проверки расхождения From и Reply-To.
        """
        if not value:
            return value

        def replace(match: re.Match[str]) -> str:
            local, domain = match.group(1), match.group(2)
            return f"{self.local_part(local, domain)}@{domain}"

        result = _ADDRESS_RE.sub(replace, value)
        # Отображаемые имена: всё, что в кавычках, и всё, что стоит перед угловой скобкой.
        result = re.sub(
            r'"([^"]+)"',
            lambda m: f'"{self.display_name(m.group(1))}"',
            result,
        )
        result = re.sub(
            r"(^|,)\s*([^<>,\"]+?)\s*<",
            lambda m: f"{m.group(1)}{self.display_name(m.group(2))} <",
            result,
        )
        return result


def _payload_bytes(part: Any) -> bytes:
    """Байты одной части письма.

    ``get_payload(decode=True)`` объявлен возвращающим и сообщение, и байты, и ``None`` —
    типизация отражает то, что метод делает три разные вещи в зависимости от части. Здесь нужна
    одна: байты или ничего.
    """
    payload = part.get_payload(decode=True)
    return payload if isinstance(payload, bytes) else b""


def fingerprint(raw: bytes, salt: bytes, *, corporate_domains: tuple[str, ...] = ()) -> str:
    """Отпечаток письма, устойчивый к обезличиванию.

    Считается по тому, что обезличивание **сохраняет**: домен отправителя, число получателей,
    набор типов частей MIME, типы вложений, хосты внешних ссылок. Поэтому обезличенный
    экземпляр и исходный дают один отпечаток, а восстановить по нему письмо нельзя.

    Чего в основании нет и почему:

    * **тема и текст** — иначе отпечаток менялся бы от самой замены;
    * **контрольные суммы и размеры вложений** — их байты обезличивание удаляет, и отпечаток
      перестал бы воспроизводиться по копии. И хеш, и размер записываются в отчёт об
      обезличивании отдельно, где им и место: это данные о письме, а не способ его узнать;
    * **внутренние ссылки** — они заменяются целиком, поэтому исключаются по домену до замены и
      по признаку ``.invalid`` после.
    """
    message = message_from_bytes(raw, policy=policy.default)
    corporate = {to_ascii(domain).lower() for domain in corporate_domains}
    parts: list[str] = []

    sender = str(message.get("From", ""))
    match = _ADDRESS_RE.search(sender)
    parts.append(f"from-domain={match.group(2).lower() if match else ''}")

    recipients = 0
    for header in ("To", "Cc"):
        recipients += len(_ADDRESS_RE.findall(str(message.get(header, ""))))
    parts.append(f"recipients={recipients}")

    structure: list[str] = []
    attachments: list[str] = []
    hosts: set[str] = set()
    for part in message.walk():
        content_type = part.get_content_type()
        structure.append(content_type)
        disposition = str(part.get("Content-Disposition", ""))
        payload = _payload_bytes(part)
        if "attachment" in disposition.lower():
            # Только тип: размер не переживает удаления байтов, а хеш и подавно. Оба
            # записываются в отчёт об обезличивании, где им и место.
            attachments.append(content_type)
            continue
        if content_type in ("text/plain", "text/html"):
            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except LookupError:
                decoded = payload.decode("utf-8", errors="replace")
            for found in re.findall(r"[a-zA-Z][a-zA-Z0-9+.-]*://([^/\s\"'<>)]+)", decoded):
                host = found.rsplit("@", 1)[-1].split(":")[0].lower()
                if not host or host.endswith(".invalid"):
                    continue
                registrable = split_domain(host).registrable_ascii
                if host in corporate or registrable in corporate:
                    continue
                hosts.add(host)

    parts.append("structure=" + ",".join(structure))
    parts.append("attachments=" + ",".join(sorted(attachments)))
    parts.append("hosts=" + ",".join(sorted(hosts)))

    digest = hmac.new(salt, "|".join(parts).encode(), hashlib.sha256).hexdigest()
    return digest[:32]


def anonymize_message(
    raw: bytes, *, salt: bytes, policy_: AnonymizationPolicy | None = None
) -> AnonymizationResult:
    """Обезличить письмо, сохранив всё, на чём работает детектирование (ТЗ 1.0.4 §9).

    Возвращает новое письмо и отчёт о сделанных заменах. Отчёт существует, чтобы «обезличено»
    было проверяемым утверждением: по нему видно, сколько адресов, имён и номеров заменено, и
    какие вложения были в письме до замены.
    """
    anonymizer = Anonymizer(salt, policy_ or AnonymizationPolicy())
    result = AnonymizationResult(
        raw=b"",
        fingerprint=fingerprint(raw, salt, corporate_domains=anonymizer.policy.corporate_domains),
    )
    message = message_from_bytes(raw, policy=policy.default)

    # -- заголовки --------------------------------------------------------------------------
    for header in list(message.keys()):
        lowered = header.lower()
        if lowered in PRESERVED_HEADERS:
            continue
        if anonymizer.policy.strip_thread_headers and lowered in EXPORT_STRIPPED_HEADERS:
            del message[header]
            result.replacements["thread_headers"] = result.replacements.get("thread_headers", 0) + 1
            continue
        values = message.get_all(header) or []
        del message[header]
        for value in values:
            rendered = str(value)
            if lowered in ADDRESS_HEADERS:
                message[header] = anonymizer.address_header(rendered)
            else:
                message[header] = anonymizer.text(rendered)

    # -- тела ------------------------------------------------------------------------------
    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", "")).lower()
        payload = _payload_bytes(part)

        if "attachment" in disposition:
            result.attachments.append(
                {
                    "filename": part.get_filename() or "",
                    "content_type": content_type,
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
            if not anonymizer.policy.keep_attachment_bytes:
                # Байты убираются, а тип, имя, размер и контрольная сумма остаются данными:
                # «тип и хеш вложения» (ТЗ §9) сохранены, содержимое — нет. Вложение это самое
                # вероятное место, где окажется договор с фамилиями.
                # Кодировку надо снять: исходная часть была в base64, и заглушка в виде
                # сырых байтов под чужим Content-Transfer-Encoding не декодируется.
                del part["Content-Transfer-Encoding"]
                part.set_payload("[содержимое удалено]".encode())
                result.replacements["attachment_bodies"] = result.replacements.get("attachment_bodies", 0) + 1
            continue

        if content_type in ("text/plain", "text/html"):
            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except LookupError:
                decoded = payload.decode("utf-8", errors="replace")
            replaced = anonymizer.text(decoded)
            replaced = re.sub(
                r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>)]+",
                lambda m: anonymizer.url(m.group(0)),
                replaced,
            )
            part.set_payload(replaced.encode("utf-8"))
            del part["Content-Transfer-Encoding"]
            part.set_charset("utf-8")

    result.replacements.update(anonymizer._counts)
    result.raw = message.as_bytes()
    return result
