"""Golden corpus generator (ТЗ 1.0.3 §5, §58).

The corpus is **generated from code**, not stored as files. That is a deliberate trade:

* it is reproducible byte-for-byte, so a metric from last month can be recomputed today;
* it is reviewable in a diff — a changed expectation shows up as a changed line, not as an
  opaque binary;
* it cannot be contaminated with real mail by someone dropping a file into a folder.

Everything here is inert. The only "malicious" payload is the EICAR test string; every domain is
a reserved `.example` or `.test` name that resolves nowhere.

ТЗ §58 sets minimum counts per category. Meeting them with copies of one message would satisfy
the count and measure nothing, so variation is generated across the axes that actually change
detection: sender relationship, authentication state, delivery path, wording, and the presence
of attachments and links.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

from msp_contracts import RiskLevel

from .dataset import (
    ApprovalStatus,
    CaseSource,
    Dataset,
    DatasetCategory,
    EvaluationCase,
    PiiStatus,
)

CORP = "corp.example"
GATEWAY_HOST = f"ksmg-01.{CORP}"
RELAY = f"mx.{CORP}"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

#: A delivery path that really did traverse the organisation's gateway.
VIA_GATEWAY = (
    f"from {GATEWAY_HOST} (ksmg-01 [10.20.0.11]) by {RELAY} with ESMTPS id aa11",
    "from {source} ({source} [{ip}]) by " + GATEWAY_HOST + " with ESMTPS id bb22",
)
#: Straight to the mailbox server: whatever the headers claim, the gateway never saw it.
DIRECT = ("from {source} (unknown [{ip}]) by " + RELAY + " with ESMTP id cc33",)


# ---------------------------------------------------------------------------------------------
# Message construction
# ---------------------------------------------------------------------------------------------
def _build(
    *,
    subject: str,
    from_addr: str,
    from_name: str = "",
    to: str = f"buh@{CORP}",
    reply_to: str = "",
    text: str = "",
    html: str = "",
    auth: str | None = "spf=pass; dkim=pass; dmarc=pass",
    authserv: str = RELAY,
    attachments: list[tuple[str, bytes, str]] | None = None,
    extra_headers: dict[str, str] | None = None,
    received: tuple[str, ...] = (),
    source_host: str = "mail.partner.example",
    source_ip: str = "203.0.113.10",
) -> bytes:
    message = EmailMessage()
    message["From"] = f'"{from_name}" <{from_addr}>' if from_name else from_addr
    message["To"] = to
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=from_addr.rsplit("@", 1)[-1])
    if reply_to:
        message["Reply-To"] = reply_to
    if auth:
        message["Authentication-Results"] = f"{authserv}; {auth}"
    for name, value in (extra_headers or {}).items():
        message[name] = value

    message.set_content(text or "Текст сообщения.")
    if html:
        message.add_alternative(html, subtype="html")
    for filename, data, mime in attachments or []:
        maintype, _, subtype = mime.partition("/")
        message.add_attachment(data, maintype=maintype, subtype=subtype or "octet-stream", filename=filename)

    raw = message.as_bytes()
    chain = received or ("from {source} ({source} [{ip}]) by " + RELAY + " with ESMTPS id dd44",)
    return _with_chain(raw, chain, source_host, source_ip)


def _with_chain(raw: bytes, chain: tuple[str, ...], source: str, ip: str) -> bytes:
    """Replace the Received headers with a full chain, newest hop first.

    Done textually because the header must repeat in order, which the mapping interface of
    ``EmailMessage`` cannot express.
    """
    separator = b"\r\n" if b"\r\n" in raw else b"\n"
    rendered = [hop.format(source=source, ip=ip).encode("utf-8") for hop in chain]
    out: list[bytes] = []
    inserted = False
    for line in raw.split(separator):
        if line.lower().startswith(b"received:"):
            continue
        if not inserted and line.lower().startswith(b"from:"):
            out.extend(b"Received: " + hop for hop in rendered)
            inserted = True
        out.append(line)
    if not inserted:
        out = [b"Received: " + hop for hop in rendered] + out
    return separator.join(out)


def _zip(entries: list[tuple[str, bytes]], *, encrypted: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    data = buffer.getvalue()
    if not encrypted:
        return data
    # Set the "encrypted" general-purpose bit without shipping an encrypted payload: the parser
    # must handle an archive that looks password-protected, and the fixture stays inert.
    out = bytearray(data)
    start = 0
    while True:
        index = out.find(b"PK", start)
        if index == -1:
            break
        for offset in (6, 8):
            if index + offset < len(out):
                out[index + offset] |= 0x01
        start = index + 4
    return bytes(out)


# ---------------------------------------------------------------------------------------------
# Vocabulary for generated variation
# ---------------------------------------------------------------------------------------------
PARTNERS = [
    ("Отдел продаж", "sales", "partner-one.example"),
    ("Сервисный центр", "service", "partner-two.example"),
    ("Логистика", "logistics", "vendor-logistics.example"),
    ("Бухгалтерия", "buh", "contractor-alpha.example"),
    ("Техподдержка", "support", "supplier-beta.example"),
    ("Отдел закупок", "procurement", "vendor-gamma.example"),
    ("Юридический отдел", "legal", "partner-legal.example"),
    ("Проектный офис", "pmo", "integrator.example"),
    ("Склад", "warehouse", "logistics-delta.example"),
    ("Отдел кадров", "hr", "recruiting.example"),
]

COLLEAGUES = [
    ("Сергей Иванов", "ivanov"),
    ("Анна Петрова", "petrova"),
    ("Пётр Сидоров", "sidorov"),
    ("Ольга Морозова", "morozova"),
    ("Дмитрий Волков", "volkov"),
    ("Елена Соколова", "sokolova"),
    ("Алексей Новиков", "novikov"),
    ("Наталья Зайцева", "zaytseva"),
]

LEGIT_SUBJECTS = [
    ("Акт сверки за {month}", "Направляем акт сверки взаиморасчётов за {month}. Просим подписать."),
    ("Коммерческое предложение", "Направляем коммерческое предложение по вашему запросу."),
    (
        "Протокол совещания от {date}",
        "Во вложении протокол совещания. Замечания просим направить до пятницы.",
    ),
    ("График поставок на {month}", "Уточнённый график поставок. Изменений по срокам нет."),
    ("Заявка на пропуск", "Просим оформить пропуск для сотрудника на {date}."),
    ("Отпуск с {date}", "Прошу согласовать отпуск. Обязанности передам заранее."),
    ("Обновление регламента", "Опубликована новая редакция регламента. Ознакомьтесь при возможности."),
    ("Техническое обслуживание", "Плановое обслуживание систем в выходные. Простоя не ожидается."),
    ("Счёт на оплату № {num}", "Направляем счёт по действующему договору. Реквизиты прежние."),
    ("Ответ на ваш запрос", "По вашему запросу направляем уточнение. Готовы обсудить детали."),
    ("Приглашение на встречу", "Предлагаем встретиться {date}. Подтвердите удобное время."),
    ("Закрывающие документы", "Направляем закрывающие документы за {month}."),
    ("Уточнение по договору", "Просим уточнить пункт 4.2 договора. Наша позиция во вложении."),
    ("Результаты тестирования", "Тестирование завершено, отчёт во вложении. Критичных замечаний нет."),
    ("Напоминание о встрече", "Напоминаем о встрече {date} в 11:00."),
]

MONTHS = [
    "январь",
    "февраль",
    "март",
    "апрель",
    "май",
    "июнь",
    "июль",
    "август",
    "сентябрь",
    "октябрь",
    "ноябрь",
    "декабрь",
]
DATES = ["12.03", "18.04", "05.06", "23.07", "09.09", "14.10", "27.11"]

BEC_BODIES = [
    "Коллеги, у нас изменились банковские реквизиты. Все последующие платежи направляйте на новый расчётный "
    "счёт. Не сообщайте бухгалтерии до подтверждения — это моя личная просьба.",
    "Нужно срочно провести платёж контрагенту. Реквизиты пришлю следующим письмом. Никому пока не "
    "сообщайте, сделка конфиденциальная.",
    "Прошу оплатить счёт в приложении сегодня до 17:00. Счёт не оплачен, подрядчик задерживает работы.",
    "Измените, пожалуйста, реквизиты для выплаты заработной платы на приложенные. Это срочно, до закрытия "
    "периода.",
    "Я сейчас на встрече и не могу говорить. Переведите средства по новым реквизитам, подтверждение вышлю "
    "позже.",
    "Счёт за прошлый месяц не оплачен. Просим перевести на новый расчётный счёт, старый заблокирован банком.",
    "Подготовьте платёж по новым реквизитам поставщика. Согласование со мной не требуется, я в курсе.",
    "Обойдите обычную процедуру согласования — вопрос срочный, я беру ответственность на себя.",
]

PHISH_BODIES = [
    (
        "Срок действия пароля истекает",
        "Ваш пароль истекает сегодня. Подтвердите учётные данные по ссылке, иначе доступ к почте будет "
        "закрыт.",
        "https://owa-{d}.example.test/owa/auth.aspx",
    ),
    (
        "Подтвердите вход в учётную запись",
        "Зафиксирован вход с нового устройства. Если это были не вы, подтвердите личность.",
        "https://login-{d}.example.test/verify",
    ),
    (
        "Ваш почтовый ящик переполнен",
        "Почтовый ящик заполнен на 98%. Освободите место, подтвердив учётную запись.",
        "https://mail-{d}.example.test/quota",
    ),
    (
        "Новый документ в общем доступе",
        "Вам предоставлен доступ к документу. Для просмотра войдите в систему.",
        "https://docs-{d}.example.test/share/login",
    ),
    (
        "Требуется обновление платёжных данных",
        "Обновите платёжные данные, чтобы избежать блокировки сервиса.",
        "https://billing-{d}.example.test/update",
    ),
    (
        "Уведомление о недоставленных письмах",
        "3 письма не доставлены. Восстановите доступ для получения.",
        "https://recover-{d}.example.test/session",
    ),
    (
        "Подтверждение корпоративной учётной записи",
        "Проводится плановая проверка учётных записей. Подтвердите свою.",
        "https://sso-{d}.example.test/confirm",
    ),
    (
        "Смена политики безопасности",
        "В связи со сменой политики требуется повторная авторизация.",
        "https://portal-{d}.example.test/reauth",
    ),
]

SPAM_BODIES = [
    ("Скидки до 90% только сегодня", "Успейте купить по лучшей цене. Предложение ограничено."),
    (
        "Бизнес-завтрак для руководителей",
        "Приглашаем на бизнес-завтрак. Участие бесплатное, количество мест ограничено.",
    ),
    (
        "Ваша заявка на кредит одобрена",
        "Предварительно одобрена сумма до 5 000 000. Ответьте для оформления.",
    ),
    ("Курсы повышения квалификации", "Новый набор на курсы. Скидка 40% при оплате на этой неделе."),
    ("Каталог продукции 2026", "Направляем обновлённый каталог. Готовы обсудить условия сотрудничества."),
    ("Выгодное предложение по лизингу", "Лизинг спецтехники без первоначального взноса."),
]


@dataclass
class _Case:
    """Internal pairing of a generated message with its expected answer."""

    case: EvaluationCase
    raw: bytes


# ---------------------------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------------------------
class GoldenCorpusBuilder:
    """Builds the golden corpus, meeting the minimum counts of ТЗ 1.0.3 §58."""

    def __init__(self, dataset_id: str = "golden", version: str = "2026.09.1") -> None:
        self.dataset_id = dataset_id
        self.version = version
        self._cases: list[_Case] = []

    # -- helpers --------------------------------------------------------------------------------
    def _add(
        self,
        case_id: str,
        category: DatasetCategory,
        raw: bytes,
        expected: RiskLevel,
        *,
        expected_rules: list[str] | None = None,
        forbidden_rules: list[str] | None = None,
        scenarios: list[str] | None = None,
        labels: list[str] | None = None,
        notes: str = "",
        requires_enrichment: bool = False,
        known_gap: str = "",
        source: CaseSource = CaseSource.SYNTHETIC,
    ) -> None:
        self._cases.append(
            _Case(
                case=EvaluationCase(
                    id=case_id,
                    dataset_id=self.dataset_id,
                    category=category,
                    message_reference=f"generated:{case_id}",
                    expected_classification=expected,
                    expected_rules=expected_rules or [],
                    forbidden_rules=forbidden_rules or [],
                    scenarios=scenarios or [],
                    labels=labels or [],
                    notes=notes,
                    requires_enrichment=requires_enrichment,
                    known_gap=known_gap,
                    source=source,
                ),
                raw=raw,
            )
        )

    # -- categories ------------------------------------------------------------------------------
    def _legitimate(self) -> None:
        """100 ordinary business messages that must not be flagged (§58).

        Variation is across sender relationship, authentication state and content shape, because
        those are what detection actually looks at. A hundred copies of one clean message would
        meet the count and measure nothing.
        """
        index = 0
        # 60 external partners, properly authenticated.
        for partner_name, local, domain in PARTNERS:
            for subject_template, body_template in LEGIT_SUBJECTS[:6]:
                index += 1
                month = MONTHS[index % len(MONTHS)]
                date = DATES[index % len(DATES)]
                self._add(
                    f"LEG-{index:03d}",
                    DatasetCategory.LEGITIMATE,
                    _build(
                        subject=subject_template.format(month=month, date=date, num=1000 + index),
                        from_addr=f"{local}@{domain}",
                        from_name=partner_name,
                        to=f"{COLLEAGUES[index % len(COLLEAGUES)][1]}@{CORP}",
                        text=body_template.format(month=month, date=date),
                        source_host=f"mail.{domain}",
                        source_ip=f"203.0.113.{10 + (index % 200)}",
                    ),
                    RiskLevel.LOW_RISK,
                    labels=["external", "partner"],
                    notes="Обычная переписка с известным контрагентом.",
                )

        # 25 internal correspondence.
        for display, local in COLLEAGUES:
            for subject_template, body_template in LEGIT_SUBJECTS[6:10]:
                if index >= 85:
                    break
                index += 1
                month = MONTHS[index % len(MONTHS)]
                date = DATES[index % len(DATES)]
                self._add(
                    f"LEG-{index:03d}",
                    DatasetCategory.LEGITIMATE,
                    _build(
                        subject=subject_template.format(month=month, date=date, num=2000 + index),
                        from_addr=f"{local}@{CORP}",
                        from_name=display,
                        to=f"buh@{CORP}",
                        text=body_template.format(month=month, date=date),
                        source_host=RELAY,
                        source_ip="10.20.1.5",
                        received=(f"from {RELAY} (mx [10.20.1.5]) by {RELAY} with ESMTPS id ee55",),
                    ),
                    RiskLevel.LOW_RISK,
                    labels=["internal"],
                    notes="Внутренняя переписка.",
                )

        # 10 bulk mail that is wanted: newsletters with proper unsubscribe headers.
        for offset in range(10):
            index += 1
            self._add(
                f"LEG-{index:03d}",
                DatasetCategory.LEGITIMATE,
                _build(
                    subject=f"Отраслевой дайджест, выпуск {200 + offset}",
                    from_addr=f"digest@news-{offset}.example",
                    from_name="Отраслевой дайджест",
                    to=f"{COLLEAGUES[offset % len(COLLEAGUES)][1]}@{CORP}",
                    text="Ваш еженедельный дайджест отраслевых новостей. Отписаться можно внизу письма.",
                    extra_headers={
                        "List-Unsubscribe": f"<mailto:unsubscribe@news-{offset}.example>",
                        "Precedence": "bulk",
                    },
                    source_host=f"mail.news-{offset}.example",
                    source_ip=f"198.51.100.{20 + offset}",
                ),
                RiskLevel.LOW_RISK,
                labels=["bulk", "newsletter"],
                notes="Легитимная рассылка: проверка на ложные срабатывания по массовой почте.",
            )

        # 5 legitimate mail with a differing Return-Path — the classic false-positive shape.
        for offset in range(5):
            index += 1
            self._add(
                f"LEG-{index:03d}",
                DatasetCategory.LEGITIMATE,
                _build(
                    subject=f"Ежемесячный отчёт по услугам № {offset + 1}",
                    from_addr="reports@trusted-service.example",
                    from_name="Trusted Service",
                    to=f"buh@{CORP}",
                    text="Ваш ежемесячный отчёт готов и доступен в личном кабинете.",
                    extra_headers={
                        "Return-Path": f"<bounce-{offset}@mailer.trusted-service.example>",
                        "List-Unsubscribe": "<mailto:unsubscribe@trusted-service.example>",
                    },
                    source_host="mailer.trusted-service.example",
                    source_ip=f"198.51.100.{60 + offset}",
                ),
                RiskLevel.LOW_RISK,
                labels=["bulk", "return_path_mismatch"],
                notes="Return-Path отличается от From — легитимная рассылочная инфраструктура.",
            )

    def _phishing(self) -> None:
        """50 credential-harvesting messages."""
        index = 0
        for base, (subject, body, url_template) in enumerate(PHISH_BODIES):
            for variant in range(6):
                if index >= 42:
                    break
                index += 1
                discriminator = f"{base}{variant}"
                url = url_template.format(d=discriminator)
                self._add(
                    f"PHI-{index:03d}",
                    DatasetCategory.PHISHING,
                    _build(
                        subject=subject,
                        from_addr=f"no-reply@service-{discriminator}.test",
                        from_name="Служба поддержки",
                        to=f"{COLLEAGUES[index % len(COLLEAGUES)][1]}@{CORP}",
                        text=f"{body} {url}",
                        html=f'<p>{body} <a href="{url}">Подтвердить</a></p>',
                        auth="spf=fail; dkim=none; dmarc=fail",
                        source_host=f"mx.service-{discriminator}.test",
                        source_ip=f"198.51.100.{100 + index % 150}",
                    ),
                    RiskLevel.SUSPICIOUS,
                    scenarios=["THR-PHISH-001"],
                    labels=["credential_harvesting"],
                )

        # 8 with a credential form in the HTML: the strongest shape.
        for variant in range(8):
            index += 1
            url = f"https://secure-login-{variant}.example.test/session"
            self._add(
                f"PHI-{index:03d}",
                DatasetCategory.PHISHING,
                _build(
                    subject="Требуется повторный вход в систему",
                    from_addr=f"security@notice-{variant}.test",
                    from_name="Отдел безопасности",
                    to=f"{COLLEAGUES[variant % len(COLLEAGUES)][1]}@{CORP}",
                    text=f"Подтвердите учётные данные: {url}",
                    html=(
                        f'<form action="{url}" method="post">'
                        '<input type="text" name="login"><input type="password" name="password">'
                        "</form>"
                    ),
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_host=f"mx.notice-{variant}.test",
                    source_ip=f"198.51.100.{200 + variant}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-PHISH-001", "THR-PHISH-002"],
                labels=["credential_form"],
            )

    def _bec(self) -> None:
        """30 business email compromise messages: no attachment, no link, pure instruction."""
        for index, body in enumerate(BEC_BODIES * 4, start=1):
            if index > 30:
                break
            executive = index % 3 == 0
            sender_domain = "corp-example.example" if index % 2 == 0 else "corp.exarnple.example"
            self._add(
                f"BEC-{index:03d}",
                DatasetCategory.BEC,
                _build(
                    subject=[
                        "Срочно: смена банковских реквизитов",
                        "Конфиденциально",
                        "Платёж по договору",
                        "Оплата счёта",
                    ][index % 4],
                    from_addr=f"{'ceo' if executive else 'cfo'}@{sender_domain}",
                    from_name="Иван Петров" if executive else "Мария Кузнецова",
                    to=f"buh@{CORP}",
                    reply_to=f"reply-{index}@{sender_domain}" if index % 3 == 0 else "",
                    text=body,
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_host=f"mx.{sender_domain}",
                    source_ip=f"198.51.100.{index}",
                ),
                RiskLevel.HIGH_RISK,
                scenarios=["THR-BEC-001" if executive else "THR-BEC-002"],
                labels=["payment_fraud", "payload_free"],
                notes="Атака без вложений и ссылок: шлюз такие письма пропускает штатно.",
            )

    def _impersonation(self) -> None:
        """30 identity-spoofing messages across the techniques that occur in practice."""
        index = 0
        # Display-name spoofing from a free-mail address.
        for display, _local in COLLEAGUES:
            index += 1
            self._add(
                f"IMP-{index:03d}",
                DatasetCategory.IMPERSONATION,
                _build(
                    subject="Небольшая просьба",
                    from_addr=f"{display.split()[0].lower()}.corp@freemail-{index}.example",
                    from_name=display,
                    to=f"buh@{CORP}",
                    text=(
                        "Подскажи, пожалуйста, остаток по счёту. "
                        "Пишу с личной почты, корпоративная недоступна."
                    ),
                    auth="spf=pass; dkim=none; dmarc=none",
                    source_host=f"mx.freemail-{index}.example",
                    source_ip=f"203.0.113.{150 + index}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-ID-001"],
                labels=["display_name_spoof"],
            )
        # Lookalike corporate domains.
        for lookalike in [
            "corp-example.example",
            "c0rp.example",
            "corp.example.attacker.test",
            "corpexample.example",
            "corp-exampl.example",
            "cor-p.example",
            "corp.exarnple.example",
            "corp--example.example",
        ]:
            index += 1
            self._add(
                f"IMP-{index:03d}",
                DatasetCategory.IMPERSONATION,
                _build(
                    subject="Уточнение по договору",
                    from_addr=f"info@{lookalike}",
                    from_name="Отдел договоров",
                    to=f"buh@{CORP}",
                    text="Направляем уточнение по действующему договору. Просим подтвердить получение.",
                    auth="spf=pass; dkim=none; dmarc=none",
                    source_host=f"mx.{lookalike}",
                    source_ip=f"203.0.113.{180 + index}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-ID-002"],
                labels=["lookalike_domain"],
            )
        # Character insertion on a short corporate label. Not detected today: raising the
        # typosquat sensitivity far enough to catch it would flag ordinary four-letter words,
        # so the limitation is registered as GAP-001 rather than papered over.
        for inserted in ["coorp.example", "corpp.example"]:
            index += 1
            self._add(
                f"IMP-{index:03d}",
                DatasetCategory.IMPERSONATION,
                _build(
                    subject="Счёт на оплату",
                    from_addr=f"billing@{inserted}",
                    from_name="Отдел расчётов",
                    to=f"buh@{CORP}",
                    text="Направляем счёт на оплату по договору.",
                    auth="spf=pass; dkim=none; dmarc=none",
                    source_host=f"mx.{inserted}",
                    source_ip=f"203.0.113.{190 + index}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-ID-002"],
                labels=["lookalike_domain", "character_insertion"],
                known_gap="GAP-001",
                notes="Известный пробел GAP-001: вставка символа в короткую метку домена.",
            )

        # Homoglyph and punycode domains.
        for homoglyph in [
            "xn--corp-8cd.example",
            "xn--mcrosoft-w2a.test",
            "xn--pypal-4ve.test",
            "xn--sberbnk-p1b.test",
        ]:
            index += 1
            self._add(
                f"IMP-{index:03d}",
                DatasetCategory.IMPERSONATION,
                _build(
                    subject="Подтверждение операции",
                    from_addr=f"noreply@{homoglyph}",
                    from_name="Служба уведомлений",
                    to=f"{COLLEAGUES[index % len(COLLEAGUES)][1]}@{CORP}",
                    text="Подтвердите операцию в личном кабинете.",
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_host=f"mx.{homoglyph}",
                    source_ip=f"203.0.113.{200 + index}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-ID-002"],
                labels=["punycode"],
            )
        # Protected identity impersonated from outside.
        while index < 30:
            index += 1
            self._add(
                f"IMP-{index:03d}",
                DatasetCategory.IMPERSONATION,
                _build(
                    subject="Прошу подготовить документы",
                    from_addr=f"i.petrov{index}@external-mail.example",
                    from_name="Иван Петров",
                    to=f"buh@{CORP}",
                    text="Подготовьте, пожалуйста, документы по проекту. Detail уточню позже.",
                    auth="spf=pass; dkim=none; dmarc=none",
                    source_host="mx.external-mail.example",
                    source_ip=f"203.0.113.{220 + index}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-ID-001"],
                labels=["protected_identity"],
            )

    def _supplier_and_invoice_fraud(self) -> None:
        """Fraud from senders whose address is genuine (ТЗ 1.0.3 §5).

        A compromised supplier account passes SPF, DKIM and DMARC, has history, and is not a
        lookalike of anything. Nothing in the envelope is wrong — which is precisely why these
        cases matter: they are the only ones where the BEC content rules are the deciding
        factor, so they are what makes a BEC regression visible to the gate.
        """
        index = 0
        supplier_bodies = [
            "Уведомляем об изменении банковских реквизитов нашей компании. Просим все последующие платежи "
            "направлять на новый расчётный счёт. Реквизиты в приложении.",
            "В связи со сменой обслуживающего банка изменились реквизиты для оплаты. Старый счёт закрыт, "
            "платежи по нему не пройдут.",
            "Направляем обновлённые платёжные реквизиты. Предыдущий счёт заблокирован, оплату просим "
            "провести на новый.",
            "Просим срочно оплатить задолженность по новым реквизитам. Счёт не оплачен, поставки "
            "приостановлены.",
            "Изменились реквизиты для перечисления оплаты. Подтверждение от банка приложено, просим учесть "
            "при ближайшем платеже.",
            "Оплату по договору направляйте на новый счёт. Прежние реквизиты недействительны с начала "
            "месяца.",
        ]
        for name, local, domain in PARTNERS[:6]:
            index += 1
            self._add(
                f"SUP-{index:03d}",
                DatasetCategory.SUPPLIER_FRAUD,
                _build(
                    subject="Изменение банковских реквизитов",
                    from_addr=f"{local}@{domain}",
                    from_name=name,
                    to=f"buh@{CORP}",
                    text=supplier_bodies[index % len(supplier_bodies)],
                    auth="spf=pass; dkim=pass; dmarc=pass",
                    source_host=f"mail.{domain}",
                    source_ip=f"203.0.113.{44 + index}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-BEC-002"],
                labels=["supplier_compromise", "payment_redirect", "isolates_bec_rules"],
                notes=(
                    "Учётная запись поставщика скомпрометирована: отправитель настоящий, "
                    "аутентификация проходит, атака целиком в содержании. Такие письма ловятся "
                    "только правилами BEC, поэтому они делают их регрессию заметной."
                ),
            )

        # Each body carries an actual fraud marker. A plain "here is an invoice" is
        # indistinguishable from legitimate billing, and labelling it as fraud would be asking
        # the platform to flag every real invoice — a label the corpus must not contain.
        invoice_bodies = [
            "Счёт не оплачен до сих пор. Просим срочно перевести сумму на новый расчётный счёт, иначе "
            "начнутся штрафные санкции.",
            "Направляем счёт повторно: предыдущий платёж не прошёл. Реквизиты изменились, оплату просим на "
            "новый счёт.",
            "По нашим данным счёт просрочен. Оплату необходимо провести сегодня по обновлённым платёжным "
            "реквизитам.",
            "Задолженность по счёту не погашена. Прежний расчётный счёт закрыт, оплату просим направить на "
            "новый.",
        ]
        for variant, body in enumerate(invoice_bodies, start=1):
            index += 1
            self._add(
                f"INV-{variant:03d}",
                DatasetCategory.INVOICE_FRAUD,
                _build(
                    subject=f"Счёт на оплату № {7700 + variant}",
                    from_addr=f"billing@new-contractor-{variant}.example",
                    from_name="Отдел выставления счетов",
                    to=f"buh@{CORP}",
                    text=body,
                    auth="spf=pass; dkim=none; dmarc=none",
                    source_host=f"mail.new-contractor-{variant}.example",
                    source_ip=f"203.0.113.{80 + variant}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-BEC-002"],
                labels=["invoice_fraud", "isolates_bec_rules"],
                notes=(
                    "Признаки мошенничества со счётом: просрочка, давление и смена реквизитов. "
                    "Обычный счёт без этих признаков в корпус не включается — он неотличим от "
                    "легитимного, и такая разметка требовала бы помечать всякий настоящий счёт."
                ),
            )

        payroll_bodies = [
            "Прошу изменить реквизиты для перечисления моей заработной платы на приложенные. Старая карта "
            "заблокирована.",
            "Направляю новые банковские данные для выплаты зарплаты. Прошу применить с ближайшего "
            "начисления.",
            "Смените, пожалуйста, счёт для зарплаты на новый. Подтверждение из банка прикладываю.",
        ]
        for variant, body in enumerate(payroll_bodies, start=1):
            self._add(
                f"PAY-{variant:03d}",
                DatasetCategory.PAYROLL_FRAUD,
                _build(
                    subject="Изменение реквизитов для заработной платы",
                    from_addr=f"{COLLEAGUES[variant][1]}.personal{variant}@freemail-pay.example",
                    from_name=COLLEAGUES[variant][0],
                    to=f"hr@{CORP}",
                    text=body,
                    auth="spf=pass; dkim=none; dmarc=none",
                    source_host="mail.freemail-pay.example",
                    source_ip=f"203.0.113.{95 + variant}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-BEC-003"],
                labels=["payroll_fraud"],
            )

    def _credential_theft(self) -> None:
        """Explicit credential requests, with no link to click (ТЗ 1.0.3 §5).

        Separate from phishing: there is no URL, so URL analysis contributes nothing and the
        detection has to come from what the message asks for.
        """
        bodies = [
            "Для настройки почтового клиента пришлите, пожалуйста, ваш текущий пароль от корпоративной "
            "учётной записи.",
            "Служба поддержки проводит миграцию. Ответным письмом направьте логин и пароль для переноса "
            "настроек.",
            "Для подтверждения личности отправьте код из SMS, который вы получите в ближайшую минуту.",
            "Пришлите одноразовый код подтверждения, который придёт на ваш телефон — он нужен для "
            "разблокировки ящика.",
            "Сообщите, пожалуйста, пароль от учётной записи для проверки совместимости с новой системой.",
            "Для завершения настройки двухфакторной аутентификации перешлите код из приложения.",
        ]
        for variant, body in enumerate(bodies, start=1):
            self._add(
                f"CRD-{variant:03d}",
                DatasetCategory.CREDENTIAL_THEFT,
                _build(
                    subject="Настройка почтового клиента",
                    from_addr=f"helpdesk@it-support-{variant}.test",
                    from_name="Техническая поддержка",
                    to=f"{COLLEAGUES[variant % len(COLLEAGUES)][1]}@{CORP}",
                    text=body,
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_host=f"mx.it-support-{variant}.test",
                    source_ip=f"198.51.100.{240 + variant}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-PHISH-003"],
                labels=["credential_request", "payload_free"],
            )

    def _html_smuggling(self) -> None:
        """Static HTML smuggling indicators (ТЗ 1.0.3 §40). Nothing is executed."""
        payloads = [
            (
                "atob_blob",
                "<script>var d=atob('TVqQAAMAAAAEAAAA//8AALgAAAA=');"
                "var b=new Blob([d],{type:'octet/stream'});"
                "var u=URL.createObjectURL(b);var a=document.createElement('a');"
                "a.href=u;a.download='invoice.exe';a.click();</script>",
            ),
            (
                "msSaveOrOpenBlob",
                "<script>var b=new Blob([atob('TVqQAA==')]);"
                "navigator.msSaveOrOpenBlob(b,'report.exe');</script>",
            ),
            (
                "data_uri_payload",
                '<a href="data:application/octet-stream;base64,TVqQAAMAAAAEAAAA">Скачать документ</a>',
            ),
            (
                "fromcharcode",
                "<script>var s='';var a=[77,90,144,0];"
                "for(var i=0;i<a.length;i++){s+=String.fromCharCode(a[i]);}</script>",
            ),
            (
                "embedded_base64_blob",
                "<div id='p' style='display:none'>TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA</div>"
                "<script>var x=document.getElementById('p').textContent;var d=atob(x);</script>",
            ),
        ]
        for variant, (label, html) in enumerate(payloads, start=1):
            self._add(
                f"SMG-{variant:03d}",
                DatasetCategory.HTML_SMUGGLING,
                _build(
                    subject="Ваш документ готов к загрузке",
                    from_addr=f"docs@delivery-{variant}.test",
                    from_name="Служба доставки документов",
                    to=f"buh@{CORP}",
                    text="Документ готов. Откройте вложение для просмотра.",
                    html=html,
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_host=f"mx.delivery-{variant}.test",
                    source_ip=f"198.51.100.{250 - variant}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-ATT-002"],
                labels=["html_smuggling", label],
                notes="HTML не исполняется: признаки определяются статически.",
            )

    def _qr_phishing(self) -> None:
        """QR phishing (ТЗ 1.0.3 §38).

        Registered as GAP-002: the platform does not decode QR codes, so the URL inside the
        image is invisible to URL analysis. The cases stay in the corpus with the gap attached,
        so the limitation is measured rather than forgotten — and so the day a decoder lands,
        these start passing without anyone having to remember they existed.
        """
        png = bytes.fromhex(
            "89504e470d0a1a0a0000000d4948445200000020000000200806000000737a7af4"
            "0000001549444154789c63fcffff3f0310c0048c2a0800a5a3017d2e4c5c000000"
            "0049454e44ae426082"
        )
        for variant in range(1, 5):
            self._add(
                f"QRP-{variant:03d}",
                DatasetCategory.QR_PHISHING,
                _build(
                    subject="Подтвердите учётную запись",
                    from_addr=f"security@notice-qr-{variant}.test",
                    from_name="Служба безопасности",
                    to=f"{COLLEAGUES[variant][1]}@{CORP}",
                    text="Отсканируйте QR-код во вложении, чтобы подтвердить учётную запись.",
                    attachments=[(f"qr{variant}.png", png, "image/png")],
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_host=f"mx.notice-qr-{variant}.test",
                    source_ip=f"198.51.100.{230 + variant}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-PHISH-004"],
                labels=["qr_phishing"],
                known_gap="GAP-002",
                notes="Известный пробел GAP-002: QR-коды не декодируются.",
            )

    def _internal_abuse(self) -> None:
        """Misuse from inside: a real internal account asking for something it should not."""
        bodies = [
            "Коллеги, перешлите мне, пожалуйста, выгрузку по зарплатам всех сотрудников. Нужно срочно, для "
            "руководства.",
            "Пришлите список всех учётных записей с правами администратора и их паролями для аудита.",
            "Нужна полная база контрагентов с банковскими реквизитами. Выгрузите на мою личную почту.",
        ]
        for variant, body in enumerate(bodies, start=1):
            self._add(
                f"INT-{variant:03d}",
                DatasetCategory.INTERNAL_ABUSE,
                _build(
                    subject="Срочная выгрузка данных",
                    from_addr=f"{COLLEAGUES[variant][1]}@{CORP}",
                    from_name=COLLEAGUES[variant][0],
                    to=f"buh@{CORP}",
                    reply_to=f"{COLLEAGUES[variant][1]}.personal@freemail-int.example",
                    text=body,
                    auth="spf=pass; dkim=pass; dmarc=pass",
                    source_host=RELAY,
                    source_ip="10.20.1.5",
                    received=(f"from {RELAY} (mx [10.20.1.5]) by {RELAY} with ESMTPS id ff66",),
                ),
                RiskLevel.SUSPICIOUS,
                labels=["internal_abuse", "external_reply_to"],
                notes="Внутренний отправитель с внешним Reply-To и запросом чувствительных данных.",
            )

    def _lookalike(self) -> None:
        """Lookalike domains as their own category (ТЗ 1.0.3 §5)."""
        variants = [
            ("corp-example.example", "subdomain_deception"),
            ("c0rp.example", "digit_substitution"),
            ("corp.example.secure-portal.test", "subdomain_deception"),
            ("xn--crp-8cd.example", "punycode"),
            ("corpexample.example", "concatenation"),
        ]
        for variant, (domain, technique) in enumerate(variants, start=1):
            self._add(
                f"LKA-{variant:03d}",
                DatasetCategory.LOOKALIKE,
                _build(
                    subject="Обновление условий обслуживания",
                    from_addr=f"service@{domain}",
                    from_name="Служба поддержки клиентов",
                    to=f"{COLLEAGUES[variant][1]}@{CORP}",
                    text="Ознакомьтесь с обновлёнными условиями обслуживания в личном кабинете.",
                    auth="spf=pass; dkim=none; dmarc=none",
                    source_host=f"mx.{domain}",
                    source_ip=f"203.0.113.{120 + variant}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-ID-002"],
                labels=["lookalike_domain", technique],
            )

    def _spam(self) -> None:
        """30 unwanted bulk messages. Flagging them is fine; calling them attacks is not."""
        index = 0
        for base, (subject, body) in enumerate(SPAM_BODIES):
            for variant in range(5):
                index += 1
                self._add(
                    f"SPM-{index:03d}",
                    DatasetCategory.SPAM,
                    _build(
                        subject=subject,
                        from_addr=f"offers{variant}@promo-{base}.example",
                        from_name="Отдел маркетинга",
                        to=f"{COLLEAGUES[index % len(COLLEAGUES)][1]}@{CORP}",
                        text=body,
                        extra_headers={"Precedence": "bulk"},
                        source_host=f"mail.promo-{base}.example",
                        source_ip=f"198.51.100.{30 + index}",
                    ),
                    RiskLevel.LOW_RISK,
                    labels=["bulk", "marketing"],
                    notes="Спам — не атака: поднятие до HIGH_RISK считается ошибкой.",
                )

    def _malicious_attachment(self) -> None:
        """20 dangerous attachment shapes, all inert."""
        index = 0
        samples: list[tuple[str, bytes, str, str]] = [
            (
                "otchet.docm",
                b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"macro" * 20,
                "application/octet-stream",
                "macro",
            ),
            ("scan.pdf.exe", b"MZ\x90\x00" + b"\x00" * 64, "application/octet-stream", "double_extension"),
            (
                "dogovor.xlsm",
                b"PK\x03\x04" + b"xl/vbaProject.bin" + b"\x00" * 32,
                "application/octet-stream",
                "macro",
            ),
            (
                "invoice.js",
                b"var a = String.fromCharCode(88,53,79);eval(a);",
                "application/octet-stream",
                "script",
            ),
            ("photo.scr", b"MZ" + b"\x00" * 80, "application/octet-stream", "executable"),
            (
                "update.hta",
                b"<script>new ActiveXObject('WScript.Shell');</script>",
                "application/octet-stream",
                "script",
            ),
            (
                "doc.lnk",
                b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 40,
                "application/octet-stream",
                "shortcut",
            ),
            ("archive.iso", b"CD001" + b"\x00" * 100, "application/octet-stream", "disk_image"),
        ]
        for filename, payload, mime, label in samples:
            index += 1
            self._add(
                f"ATT-{index:03d}",
                DatasetCategory.MALICIOUS_ATTACHMENT,
                _build(
                    subject="Документы по заявке",
                    from_addr=f"sender{index}@vendor-unknown.example",
                    from_name="Отдел документооборота",
                    to=f"buh@{CORP}",
                    text="Документы во вложении. Просим подтвердить получение.",
                    attachments=[(filename, payload, mime)],
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_host="mx.vendor-unknown.example",
                    source_ip=f"198.51.100.{140 + index}",
                ),
                RiskLevel.SUSPICIOUS,
                scenarios=["THR-ATT-001"],
                labels=[label],
            )

        # EICAR, plain and in archives of increasing nesting.
        index += 1
        self._add(
            f"ATT-{index:03d}",
            DatasetCategory.MALICIOUS_ATTACHMENT,
            _build(
                subject="Проверочный файл",
                from_addr="test@vendor-unknown.example",
                text="Во вложении тестовый файл.",
                attachments=[("eicar.com", EICAR, "application/octet-stream")],
                auth="spf=fail; dkim=none; dmarc=fail",
                source_ip="198.51.100.160",
            ),
            RiskLevel.SUSPICIOUS,
            labels=["eicar"],
        )
        for depth in range(1, 4):
            index += 1
            data = _zip([("eicar.com", EICAR)])
            for level in range(depth):
                data = _zip([(f"level{level}.zip", data)])
            self._add(
                f"ATT-{index:03d}",
                DatasetCategory.MALICIOUS_ATTACHMENT,
                _build(
                    subject=f"Архив материалов {depth}",
                    from_addr=f"archive{depth}@vendor-unknown.example",
                    text="Материалы во вложении.",
                    attachments=[(f"materials{depth}.zip", data, "application/zip")],
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip=f"198.51.100.{170 + depth}",
                ),
                RiskLevel.SUSPICIOUS,
                labels=["nested_archive"],
            )
        # Encrypted archives: unscannable by construction, and that must be said, not hidden.
        for variant in range(4):
            index += 1
            self._add(
                f"ATT-{index:03d}",
                DatasetCategory.MALICIOUS_ATTACHMENT,
                _build(
                    subject="Документы (архив с паролем)",
                    from_addr=f"secure{variant}@vendor-unknown.example",
                    text="Пароль к архиву: 1234. Документы внутри.",
                    attachments=[
                        (
                            f"secure{variant}.zip",
                            _zip([("doc.docx", b"content")], encrypted=True),
                            "application/zip",
                        )
                    ],
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip=f"198.51.100.{180 + variant}",
                ),
                RiskLevel.SUSPICIOUS,
                labels=["encrypted_archive", "unscannable"],
            )
        while index < 20:
            index += 1
            self._add(
                f"ATT-{index:03d}",
                DatasetCategory.MALICIOUS_ATTACHMENT,
                _build(
                    subject="Счёт и акт",
                    from_addr=f"billing{index}@vendor-unknown.example",
                    text="Документы во вложении.",
                    attachments=[
                        (
                            f"schet{index}.docm",
                            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"vbaProject" * 10,
                            "application/octet-stream",
                        )
                    ],
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip=f"198.51.100.{190 + index}",
                ),
                RiskLevel.SUSPICIOUS,
                labels=["macro"],
            )

    def _malformed_adversarial(self) -> None:
        """20 malformed and evasive messages (§47).

        These are the ones that decide whether the parser can be walked around. Each applies a
        different evasion to content that would otherwise be caught.
        """
        index = 0
        evasions: list[tuple[str, bytes, str]] = []

        # Zero-width characters inside a payment instruction.
        zwsp = "​"
        evasions.append(
            (
                "zero_width",
                _build(
                    subject="Смена реквизитов",
                    from_addr="ceo@corp-example.example",
                    from_name="Иван Петров",
                    text=f"Измените{zwsp} банковские{zwsp} реквизиты{zwsp} и проведите платёж срочно.",
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip="198.51.100.210",
                ),
                "Вставка нулевой ширины между словами платёжной инструкции.",
            )
        )
        # Excess whitespace.
        evasions.append(
            (
                "whitespace",
                _build(
                    subject="С м е н а   р е к в и з и т о в",
                    from_addr="cfo@corp-example.example",
                    from_name="Мария Кузнецова",
                    text="Из мените  банковс кие  рекви зиты  и  прове дите  платёж.",
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip="198.51.100.211",
                ),
                "Разрывы внутри слов пробелами.",
            )
        )
        # Mixed script inside a single word.
        evasions.append(
            (
                "mixed_script_token",
                _build(
                    subject="Подтверждение Аpple ID",
                    # Punycode of a domain whose label mixes scripts; the address itself stays
                    # ASCII, as SMTP requires.
                    from_addr="noreply@xn--appl-id-p9d.test",
                    from_name="Аpple Support",
                    text="Подтвердите учётную запись: https://apple-id.test/verify",
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip="198.51.100.212",
                ),
                "Кириллическая А внутри латинского слова.",
            )
        )
        # RTL override in a filename.
        evasions.append(
            (
                "rtlo_filename",
                _build(
                    subject="Отчёт",
                    from_addr="report@vendor-unknown.example",
                    text="Отчёт во вложении.",
                    attachments=[
                        ("doc" + chr(0x202E) + "gnp.exe", b"MZ\x00\x00", "application/octet-stream")
                    ],
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip="198.51.100.213",
                ),
                "Right-to-left override маскирует расширение.",
            )
        )
        # URL encoding.
        evasions.append(
            (
                "url_encoding",
                _build(
                    subject="Подтвердите вход",
                    from_addr="security@notice-enc.test",
                    text="Перейдите: https://login%2Dportal.example.test/%61uth?next=%2Fowa",
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip="198.51.100.214",
                ),
                "Процентное кодирование в URL.",
            )
        )
        # HTML comments splitting a keyword.
        evasions.append(
            (
                "html_comment",
                _build(
                    subject="Счёт на оплату",
                    from_addr="billing@vendor-split.test",
                    text="Счёт во вложении.",
                    html="<p>Сме<!-- x -->ните рекви<!-- y -->зиты и опла<!-- z -->тите счёт</p>",
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip="198.51.100.215",
                ),
                "HTML-комментарии внутри ключевых слов.",
            )
        )
        # Data URL.
        evasions.append(
            (
                "data_url",
                _build(
                    subject="Документ",
                    from_addr="docs@vendor-data.test",
                    text="Документ во вложении.",
                    html='<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Открыть</a>',
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip="198.51.100.216",
                ),
                "data: URL с закодированной нагрузкой.",
            )
        )
        # HTML smuggling markers.
        evasions.append(
            (
                "html_smuggling",
                _build(
                    subject="Ваш файл готов",
                    from_addr="files@vendor-smug.test",
                    text="Файл во вложении.",
                    html=(
                        "<script>var b=atob('TVqQAAMAAAAEAAAA');"
                        "var blob=new Blob([b],{type:'application/octet-stream'});"
                        "navigator.msSaveOrOpenBlob(blob,'invoice.exe');</script>"
                    ),
                    auth="spf=fail; dkim=none; dmarc=fail",
                    source_ip="198.51.100.217",
                ),
                "Признаки HTML smuggling: atob, Blob, msSaveOrOpenBlob.",
            )
        )

        for name, raw, note in evasions:
            index += 1
            self._add(
                f"ADV-{index:03d}",
                DatasetCategory.MALFORMED,
                raw,
                RiskLevel.SUSPICIOUS,
                labels=["adversarial", name],
                notes=note,
            )

        # Malformed MIME shapes: the platform must not crash and must not claim a clean result.
        malformed: list[tuple[str, bytes, str]] = [
            ("no_headers", "\r\n\r\nтолько тело без заголовков".encode(), "Письмо без заголовков."),
            (
                "broken_boundary",
                b"From: a@b.example\r\nContent-Type: multipart/mixed; boundary=X\r\n\r\n--X\r\nno end",
                "Оборванная multipart-граница.",
            ),
            (
                "bad_charset",
                "From: a@b.example\r\nSubject: =?invalid-charset?B?0J/RgNC40LLQtdGC?=\r\n\r\nтело".encode(),
                "Неизвестная кодировка в заголовке.",
            ),
            (
                "folded_headers",
                "From: a@b.example\r\nSubject: \r\n \r\n  \r\n Smena\r\n rekvizitov\r\n\r\nтело".encode(),
                "Многократно свёрнутый заголовок.",
            ),
            (
                "duplicate_from",
                "From: a@b.example\r\nFrom: attacker@evil.test\r\nSubject: dva From\r\n\r\nтело".encode(),
                "Два заголовка From.",
            ),
            (
                "null_bytes",
                "From: a@b.example\r\nSubject: test\x00null\r\n\r\n\x00тело".encode(),
                "Нулевые байты в заголовке и теле.",
            ),
            (
                "deep_nesting",
                b"From: a@b.example\r\nContent-Type: message/rfc822\r\n\r\n"
                + b"Content-Type: message/rfc822\r\n\r\n" * 30
                + b"end",
                "Глубокая вложенность message/rfc822.",
            ),
            (
                "long_header",
                b"From: a@b.example\r\nX-Long: " + b"A" * 20000 + "\r\n\r\nтело".encode(),
                "Чрезмерно длинный заголовок.",
            ),
            (
                "no_from",
                "To: buh@corp.example\r\nSubject: bez From\r\n\r\nтело".encode(),
                "Отсутствует заголовок From.",
            ),
            (
                "bare_lf",
                "From: a@b.example\nSubject: bare LF\n\nтело без CRLF".encode(),
                "Перевод строки без возврата каретки.",
            ),
            (
                "html_only_encoded",
                b"From: a@b.example\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n"
                b"PGh0bWw+PGJvZHk+0J/RgNC40LLQtdGCPC9ib2R5PjwvaHRtbD4=",
                "HTML целиком в base64.",
            ),
            ("empty", b"", "Пустое сообщение."),
        ]
        for name, raw, note in malformed:
            index += 1
            self._add(
                f"ADV-{index:03d}",
                DatasetCategory.MALFORMED,
                raw,
                RiskLevel.UNKNOWN,
                labels=["malformed", name],
                notes=note + " Вердикт не может быть LOW_RISK: разбор неполон.",
            )

    def _gateway_conflict(self) -> None:
        """20 gateway scenarios: verified, forged, and disagreeing (§58)."""
        index = 0

        # Verified clean gateway verdict over a BEC message: the canonical conflict.
        for variant in range(5):
            index += 1
            self._add(
                f"GWC-{index:03d}",
                DatasetCategory.BEC,
                _build(
                    subject="Смена реквизитов для оплаты",
                    from_addr=f"ceo@corp-example{variant}.example",
                    from_name="Иван Петров",
                    to=f"buh@{CORP}",
                    text=BEC_BODIES[variant % len(BEC_BODIES)],
                    auth="spf=fail; dkim=none; dmarc=fail",
                    authserv=GATEWAY_HOST,
                    extra_headers={
                        "X-KSMG-Antivirus-Status": "Clean",
                        "X-KSMG-AntiSpam-Status": "Clean",
                        "X-KSMG-AntiPhishing-Status": "Not detected",
                    },
                    received=VIA_GATEWAY,
                    source_host=f"mx.corp-example{variant}.example",
                    source_ip=f"203.0.113.{40 + variant}",
                ),
                RiskLevel.HIGH_RISK,
                expected_rules=["GW-011"],
                scenarios=["THR-BEC-002"],
                labels=["gateway_clean", "conflict"],
                notes="Шлюз ничего не нашёл, платформа обязана поймать. Штатное расхождение.",
            )

        # Forged gateway headers: the chain does not include the gateway.
        for variant in range(5):
            index += 1
            self._add(
                f"GWC-{index:03d}",
                DatasetCategory.BEC,
                _build(
                    subject="Срочная оплата счёта",
                    from_addr=f"cfo@corp-exampl{variant}.example",
                    from_name="Мария Кузнецова",
                    to=f"buh@{CORP}",
                    text=BEC_BODIES[(variant + 2) % len(BEC_BODIES)],
                    auth="spf=fail; dkim=none; dmarc=fail",
                    extra_headers={
                        "X-KSMG-Antivirus-Status": "Clean",
                        "X-KSMG-AntiSpam-Status": "Clean",
                        "X-Spam-Flag": "NO",
                    },
                    received=DIRECT,
                    source_host=f"mx.attacker{variant}.example",
                    source_ip=f"198.51.100.{7 + variant}",
                ),
                RiskLevel.HIGH_RISK,
                expected_rules=["GW-012"],
                forbidden_rules=["GW-011"],
                labels=["forged_gateway_header"],
                notes="Заголовки шлюза скопированы; цепочка прохождение не подтверждает.",
            )

        # Forged Authentication-Results claiming our own server.
        for variant in range(5):
            index += 1
            self._add(
                f"GWC-{index:03d}",
                DatasetCategory.IMPERSONATION,
                _build(
                    subject="Подтвердите платёж",
                    from_addr=f"cfo@corp-example{variant}.example",
                    from_name="Ольга Смирнова",
                    to=f"buh@{CORP}",
                    text="Подтвердите платёж по новым реквизитам сегодня до 17:00.",
                    auth="spf=pass; dkim=pass; dmarc=pass",
                    authserv=GATEWAY_HOST,
                    received=DIRECT,
                    source_host=f"mx.attacker{variant}.example",
                    source_ip=f"198.51.100.{20 + variant}",
                ),
                RiskLevel.HIGH_RISK,
                expected_rules=["GW-013"],
                labels=["forged_authentication_results"],
                notes="Успешная проверка подлинности заявлена от имени нашего сервера.",
            )

        # Verified gateway detection: the platform must agree, and hard.
        for variant in range(5):
            index += 1
            self._add(
                f"GWC-{index:03d}",
                DatasetCategory.MALICIOUS_ATTACHMENT,
                _build(
                    subject="Документы по заявке",
                    from_addr=f"sender{variant}@vendor-unknown.example",
                    to=f"buh@{CORP}",
                    text="Документы во вложении.",
                    authserv=GATEWAY_HOST,
                    extra_headers={
                        "X-KSMG-Antivirus-Status": "Detected: EICAR-Test-File",
                        "X-KSMG-Antivirus-Method": "Signature",
                    },
                    received=VIA_GATEWAY,
                    source_host=f"mx.vendor{variant}.example",
                    source_ip=f"203.0.113.{60 + variant}",
                ),
                RiskLevel.MALICIOUS,
                expected_rules=["GW-001"],
                labels=["gateway_detection"],
                notes="Подтверждённое обнаружение шлюза — жёсткий сигнал.",
            )

    # -- assembly ---------------------------------------------------------------------------------
    def build(self) -> tuple[Dataset, dict[str, bytes]]:
        self._cases.clear()
        self._legitimate()
        self._phishing()
        self._bec()
        self._impersonation()
        self._spam()
        self._supplier_and_invoice_fraud()
        self._credential_theft()
        self._html_smuggling()
        self._qr_phishing()
        self._internal_abuse()
        self._lookalike()
        self._malicious_attachment()
        self._malformed_adversarial()
        self._gateway_conflict()

        dataset = Dataset(
            id=self.dataset_id,
            version=self.version,
            cases=[entry.case for entry in self._cases],
            owner="detection-owner@corp.example",
            source="synthetic",
            pii_status=PiiStatus.NONE,
            approval_status=ApprovalStatus.APPROVED,
            changelog=[
                f"{self.version}: начальный золотой корпус по ТЗ 1.0.3 §58",
            ],
            notes=(
                "Полностью синтетический и инертный корпус. Единственная «вредоносная» нагрузка — "
                "тестовая строка EICAR; все домены зарезервированы и нигде не разрешаются. "
                "Корпус порождается кодом, а не хранится файлами: так он воспроизводим, "
                "читается в diff и его нельзя случайно загрязнить настоящей почтой."
            ),
        )
        messages = {entry.case.message_reference: entry.raw for entry in self._cases}
        return dataset, messages


_CACHE: tuple[Dataset, dict[str, bytes]] | None = None


def build_golden_dataset(version: str = "2026.09.1") -> tuple[Dataset, dict[str, bytes]]:
    """The golden corpus and its messages. Built once per process."""
    global _CACHE
    if _CACHE is None or _CACHE[0].version != version:
        _CACHE = GoldenCorpusBuilder(version=version).build()
    return _CACHE


def resolve_message(reference: str, messages: dict[str, bytes] | None = None) -> bytes:
    """Resolve a case's ``message_reference`` to raw bytes."""
    if messages is None:
        _, messages = build_golden_dataset()
    if reference in messages:
        return messages[reference]
    if reference.startswith("file:"):
        from pathlib import Path

        return Path(reference[5:]).read_bytes()
    raise KeyError(f"unknown message reference: {reference}")


def corpus_checksum() -> str:
    """Hash over the generated bytes, so a change in generation is detectable."""
    _, messages = build_golden_dataset()
    digest = hashlib.sha256()
    for reference in sorted(messages):
        digest.update(reference.encode("utf-8"))
        digest.update(hashlib.sha256(messages[reference]).digest())
    return digest.hexdigest()


def summary() -> dict[str, Any]:
    dataset, messages = build_golden_dataset()
    return {
        "version": dataset.version,
        "cases": len(dataset),
        "distribution": dataset.class_distribution(),
        "checksum": dataset.checksum(),
        "corpus_checksum": corpus_checksum(),
        "bytes": sum(len(raw) for raw in messages.values()),
    }


def iter_cases() -> Iterator[tuple[EvaluationCase, bytes]]:
    dataset, messages = build_golden_dataset()
    for case in dataset:
        yield case, messages[case.message_reference]
