"""Синтетический корпус спама и оценка качества (ТЗ 1.2 §39).

Корпус создаётся программой и поэтому воспроизводим, но он **синтетический**: числа точности и полноты на
нём — это проверка того, что конфигурация и политика не ухудшились (регрессия), а не оценка качества на
реальной почте. Качество на реальном потоке измеряется отдельно (``docs/SPAM_REAL_FLOW_VALIDATION.md``).

Категории (ТЗ §39): транзакционные письма, рассылки, маркетинговые рассылки, классический спам,
фишинг, BEC, имитация вредоносного ПО, пересылка, списки рассылки, легитимные письма со сломанной
аутентификацией. GTUBE входит только как проверка работоспособности и в метрики качества не попадает.

Каждый пример описывает письмо, окружение DNS (SPF/DKIM/DMARC), источник и ожидаемую метку. Прогон
через настоящий Rspamd делает ``scripts/record_spam_corpus.py``; оценка по записям — чистая функция
(``evaluate``), не требующая Docker и пригодная для CI.
"""

from __future__ import annotations

import hashlib
import random
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from email import message_from_string
from typing import Any

from .analysis import analyze
from .policy import SpamPolicy

HAM, SPAM, BULK, ATTACK = "HAM", "SPAM", "BULK", "ATTACK"
SMOKE = "SMOKE"

GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"

CATEGORIES = (
    "transactional",
    "newsletter",
    "marketing_bulk",
    "classic_spam",
    "phishing",
    "bec",
    "malware_simulation",
    "forwarding",
    "mailing_list",
    "broken_auth_legit",
)


@dataclass(frozen=True)
class Context:
    """Окружение DNS и источника для одного письма."""

    spf: str = "pass"  # pass | fail | softfail | none
    dkim: str = "valid"  # valid | none | broken
    dmarc: str | None = "reject"  # None | none | quarantine | reject
    client: str = "authorized"  # authorized (в SPF) | other
    ptr: bool = True
    helo: str = "mail"  # mail -> mail.<domain>; ip -> [IP]; mismatch -> evil.example
    upstream_ar: str = ""  # Authentication-Results вышестоящего шлюза, если есть
    arc: bool = False


@dataclass(frozen=True)
class Case:
    id: str
    category: str
    label: str
    subject: str
    body: str
    extra_headers: tuple[tuple[str, str], ...] = ()
    context: Context = field(default_factory=Context)
    recipients: int = 1
    note: str = ""

    def eml(self, *, domain: str, rcpt: str = "ivan@corp.example") -> str:
        lines = [
            f"From: sender@{domain}",
            f"To: {rcpt}",
            f"Subject: {self.subject}",
            f"Message-ID: <{self.id.lower()}@corpus.example>",
            "Date: Mon, 12 Oct 2026 10:00:00 +0000",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=utf-8",
        ]
        for name, value in self.extra_headers:
            lines.append(f"{name}: {value}")
        if self.context.upstream_ar:
            lines.append(f"Authentication-Results: {self.context.upstream_ar}")
        return "\r\n".join(lines) + "\r\n\r\n" + self.body + "\r\n"


# ---------------------------------------------------------------------------------------------
# Шаблоны содержимого. Тексты нарочито разнообразны, но детерминированы по номеру примера.
# ---------------------------------------------------------------------------------------------
_TRANSACTIONAL = [
    (
        "Заказ № {n} подтверждён",
        "Здравствуйте! Ваш заказ № {n} принят и будет отправлен в течение двух рабочих дней. Состав заказа и сроки доставки доступны в личном кабинете.",
    ),
    (
        "Сброс пароля для вашей учётной записи",
        "Вы запросили сброс пароля. Если это были вы, перейдите по ссылке в личном кабинете в течение часа. Если нет, просто проигнорируйте письмо.",
    ),
    (
        "Счёт {n} за октябрь",
        "Во вложении счёт № {n} за услуги связи за октябрь. Оплатите его до конца месяца. По вопросам обращайтесь в бухгалтерию.",
    ),
    (
        "Ваша заявка № {n} зарегистрирована",
        "Мы получили вашу заявку № {n} в службу поддержки. Ответим в течение одного рабочего дня.",
    ),
]
_NEWSLETTER = [
    (
        "Дайджест недели № {n}",
        "Главное за неделю: новые статьи, обзор релизов и анонс вебинара. Чтобы отписаться, воспользуйтесь ссылкой в конце письма.",
    ),
    (
        "Бюллетень компании, выпуск {n}",
        "В этом выпуске: итоги квартала, новые сотрудники, расписание мероприятий. Вы получили письмо, потому что подписались на рассылку.",
    ),
]
_MARKETING = [
    (
        "Осенняя распродажа: скидки до 30%",
        "Только до конца недели скидки на выбранные товары. Подробности на сайте. Отписаться от акций можно в настройках профиля.",
    ),
    (
        "Новая коллекция уже в магазине",
        "Познакомьтесь с новинками сезона. Скидка 10% по промокоду для подписчиков. Отписаться можно по ссылке ниже.",
    ),
]
_SPAM = [
    (
        "ВЫ ВЫИГРАЛИ ПРИЗ!!! Получите деньги СЕЙЧАС",
        "ПОЗДРАВЛЯЕМ!!! Вы выиграли 1 000 000 в лотерее! Для получения выигрыша срочно отправьте данные карты. Только сегодня! http://prize-{n}.example.top/claim",
    ),
    (
        "Дешёвые таблетки без рецепта",
        "Купите виагру и другие препараты со скидкой 90%! Без рецепта, доставка по всему миру. Заходите http://pharma-{n}.example.xyz/buy",
    ),
    (
        "Заработок от 5000 в день без вложений",
        "Работа на дому! Зарабатывайте 5000 в день, ничего не вкладывая. Пишите прямо сейчас, количество мест ограничено! http://cash-{n}.example.click",
    ),
    (
        "Replica watches cheap!!! best price",
        "BUY NOW cheap replica watches and bags, 80% OFF, limited offer, click here http://watch-{n}.example.top/ now!!!",
    ),
]
_PHISHING = [
    (
        "Срочно: подтвердите пароль учётной записи",
        "Ваш пароль истекает сегодня. Подтвердите его, чтобы не потерять доступ к почте: http://login-secure-{n}.example.top/verify",
    ),
    (
        "Вход в банк заблокирован",
        "Мы заметили подозрительную активность. Чтобы разблокировать доступ, введите данные карты: http://bank-verify-{n}.example.xyz/unlock",
    ),
]
_BEC = [
    (
        "Срочная просьба",
        "Добрый день. Нужно срочно оплатить счёт поставщику, реквизиты ниже. Я на совещании и не отвечу на звонки. Подтвердите, что оплатите сегодня.",
    ),
    (
        "Конфиденциально: смена реквизитов",
        "Коллеги, у поставщика поменялись банковские реквизиты. Все платежи с понедельника переводите на новый счёт. Это распоряжение руководства.",
    ),
]
_MALWARE = [
    (
        "Документ для подписи",
        "Откройте вложенный документ и включите макросы для просмотра. Контрольная строка для проверки антивируса (безвредна): X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    ),
]
_FORWARD = [
    (
        "Fwd: условия поставки № {n}",
        "Пересылаю письмо поставщика с условиями поставки № {n}. Посмотрите, пожалуйста, до пятницы.",
    ),
]
_LIST = [
    (
        "[dev-list] Вопрос по релизу {n}",
        "Коллеги, подскажите, как правильно настроить сборку для релиза {n}? Заранее спасибо.\r\n\r\n-- \r\nСписок рассылки dev-list. Отписаться: см. List-Unsubscribe",
    ),
]
_LEGIT_BROKEN = [
    (
        "Коммерческое предложение",
        "Добрый день! Направляем коммерческое предложение на поставку канцтоваров. Условия обсудим по телефону, звоните в любое время.",
    ),
    (
        "Согласование встречи",
        "Здравствуйте, предлагаю встретиться в четверг в 15:00 в вашем офисе для обсуждения договора. Подтвердите, пожалуйста.",
    ),
]


def _pick(templates: list[tuple[str, str]], n: int) -> tuple[str, str]:
    subject, body = templates[n % len(templates)]
    return subject.replace("{n}", str(1000 + n)), body.replace("{n}", str(1000 + n))


def generate_cases(per_category: int = 12) -> list[Case]:
    """Детерминированный набор. Один и тот же вызов всегда даёт те же письма."""
    rng = random.Random(20261018)
    cases: list[Case] = []

    def add(category: str, label: str, templates: list[tuple[str, str]], n: int, **kwargs: Any) -> None:
        subject, body = _pick(templates, n + rng.randint(0, 3))
        cases.append(
            Case(
                id=f"SPC-{category[:4].upper()}-{n + 1:03d}",
                category=category,
                label=label,
                subject=subject,
                body=body,
                **kwargs,
            )
        )

    for n in range(per_category):
        add("transactional", HAM, _TRANSACTIONAL, n)
        add(
            "newsletter",
            BULK,
            _NEWSLETTER,
            n,
            extra_headers=(
                ("List-Unsubscribe", "<mailto:unsubscribe@corpus.example>"),
                ("Precedence", "bulk"),
            ),
        )
        add(
            "marketing_bulk",
            BULK,
            _MARKETING,
            n,
            extra_headers=(("List-Unsubscribe", "<https://corpus.example/unsub>"),),
            recipients=120,
        )
        add(
            "classic_spam",
            SPAM,
            _SPAM,
            n,
            context=Context(
                spf="none" if n % 2 else "fail",
                dkim="none",
                dmarc=None,
                client="other",
                ptr=n % 3 == 0,
                helo="ip" if n % 4 == 0 else "mail",
            ),
        )
        add(
            "phishing",
            ATTACK,
            _PHISHING,
            n,
            context=Context(spf="fail", dkim="none", dmarc="reject", client="other", ptr=False),
        )
        add(
            "bec",
            ATTACK,
            _BEC,
            n,
            context=Context(
                spf="fail", dkim="none", dmarc="reject" if n % 2 == 0 else "none", client="other"
            ),
        )
        add(
            "malware_simulation",
            ATTACK,
            _MALWARE,
            n,
            context=Context(spf="softfail", dkim="none", dmarc="quarantine", client="other"),
        )
        add(
            "forwarding",
            HAM,
            _FORWARD,
            n,
            context=Context(spf="fail", dkim="valid", dmarc="reject", client="other"),
            note="пересылка: SPF не проходит, подпись автора цела",
        )
        add(
            "mailing_list",
            BULK,
            _LIST,
            n,
            extra_headers=(
                ("List-Id", "<dev-list.corpus.example>"),
                ("List-Unsubscribe", "<mailto:dev-list-leave@corpus.example>"),
            ),
            context=Context(spf="fail", dkim="broken", dmarc="none", client="other", arc=True),
            note="список изменил тело письма: подпись автора нарушена, ARC цел",
        )
        add(
            "broken_auth_legit",
            HAM,
            _LEGIT_BROKEN,
            n,
            context=Context(spf="none", dkim="none", dmarc=None, client="authorized"),
            note="небольшая организация без SPF и DKIM",
        )
    # Расхождения с вышестоящим шлюзом: он видел другого отправителя и сообщил pass.
    for index in range(per_category // 2):
        base = cases[index * len(CATEGORIES) + 4]  # фишинг
        cases.append(
            Case(
                id=f"SPC-UPST-{index + 1:03d}",
                category="upstream_conflict",
                label=ATTACK,
                subject=base.subject,
                body=base.body,
                context=Context(
                    spf="fail",
                    dkim="none",
                    dmarc="reject",
                    client="other",
                    ptr=False,
                    upstream_ar="ksmg.corp.example; spf=pass; dkim=pass; dmarc=pass",
                ),
                note="вышестоящий шлюз сообщил pass, MSP видит провал",
            )
        )
    cases.append(
        Case(
            id="SPC-SMOKE-001",
            category="gtube_smoke",
            label=SMOKE,
            subject="GTUBE smoke",
            body=GTUBE,
            context=Context(spf="none", dkim="none", dmarc=None, client="other"),
            note="проверка работоспособности; в метрики качества не входит",
        )
    )
    return cases


def case_to_dict(case: Case) -> dict[str, Any]:
    return {
        "id": case.id,
        "category": case.category,
        "label": case.label,
        "subject": case.subject,
        "body": case.body,
        "extra_headers": [list(h) for h in case.extra_headers],
        "context": case.context.__dict__,
        "recipients": case.recipients,
        "note": case.note,
    }


def case_from_dict(data: Mapping[str, Any]) -> Case:
    return Case(
        id=str(data["id"]),
        category=str(data["category"]),
        label=str(data["label"]),
        subject=str(data["subject"]),
        body=str(data["body"]),
        extra_headers=tuple((str(a), str(b)) for a, b in data.get("extra_headers", [])),
        context=Context(**dict(data.get("context", {}))),
        recipients=int(data.get("recipients", 1)),
        note=str(data.get("note", "")),
    )


def corpus_checksum(cases: Iterable[Case]) -> str:
    digest = hashlib.sha256()
    for case in cases:
        digest.update(repr(case_to_dict(case)).encode())
    return digest.hexdigest()


# ---------------------------------------------------------------------------------------------
# Оценка
# ---------------------------------------------------------------------------------------------
@dataclass
class EvalReport:
    total: int
    scored: int
    categories: dict[str, int]
    spam_precision: float | None
    spam_recall: float | None
    bulk_precision: float | None
    suggested_reject_precision: float | None
    suggested_reject_count: int
    authentication_conflict_rate: float | None
    upstream_cases: int
    ham_flagged_as_spam: list[str]
    spam_missed: list[str]
    class_by_category: dict[str, dict[str, int]]
    smoke_ok: bool
    missing_records: list[str]


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evaluate(
    cases: Iterable[Case], records: Mapping[str, Mapping[str, Any]], policy: SpamPolicy | None = None
) -> EvalReport:
    """Метрики по записям настоящего сканера. Нет записи — пример учитывается как отсутствующий, а не «чистый»."""
    policy = policy or SpamPolicy()
    tp = fp = fn = 0
    bulk_pred = bulk_true = 0
    reject_total = reject_good = 0
    conflicts_found = upstream = 0
    ham_flagged: list[str] = []
    spam_missed: list[str] = []
    by_cat: dict[str, Counter[str]] = {}
    cat_counter: Counter[str] = Counter()
    missing: list[str] = []
    smoke_ok = False
    scored = 0
    all_cases = list(cases)
    for case in all_cases:
        cat_counter[case.category] += 1
        record = records.get(case.id)
        if record is None:
            missing.append(case.id)
            continue
        message = message_from_string(case.eml(domain="corpus.example"))
        headers: dict[str, list[str]] = {}
        for name, value in message.items():
            headers.setdefault(name.lower(), []).append(str(value))
        analysis = analyze(
            record,
            policy,
            headers=headers,
            recipient_count=case.recipients,
            received_headers=[],
        )
        spam_class = analysis.spam_class.value
        by_cat.setdefault(case.category, Counter())[spam_class] += 1
        if case.label == SMOKE:
            # GTUBE при выключенных тестовых шаблонах — обычное письмо: оно должно быть принято и просканировано
            # (запись есть), а применённое действие — только наблюдение. Отказ по GTUBE был бы принуждением.
            smoke_ok = analysis.applied_action.value == "OBSERVE_ONLY"
            continue
        scored += 1
        predicted_spam = spam_class in ("SPAM", "HIGH_CONFIDENCE_SPAM")
        if case.label == SPAM:
            if predicted_spam:
                tp += 1
            else:
                fn += 1
                spam_missed.append(case.id)
        elif case.label in (HAM, BULK) and predicted_spam:
            fp += 1
            ham_flagged.append(case.id)
        if spam_class == "BULK":
            bulk_pred += 1
            bulk_true += 1 if case.label == BULK else 0
        if analysis.suggested_action.value == "REJECT":
            reject_total += 1
            reject_good += 1 if case.label in (SPAM, ATTACK) else 0
        if case.context.upstream_ar:
            upstream += 1
            from .authres import parse_authentication_results
            from .conflicts import compare

            parsed = parse_authentication_results(case.context.upstream_ar)
            if analysis.auth is not None and compare(parsed, analysis.auth).any:
                conflicts_found += 1
    return EvalReport(
        total=len(all_cases),
        scored=scored,
        categories=dict(cat_counter),
        spam_precision=_ratio(tp, tp + fp),
        spam_recall=_ratio(tp, tp + fn),
        bulk_precision=_ratio(bulk_true, bulk_pred),
        suggested_reject_precision=_ratio(reject_good, reject_total),
        suggested_reject_count=reject_total,
        authentication_conflict_rate=_ratio(conflicts_found, upstream),
        upstream_cases=upstream,
        ham_flagged_as_spam=ham_flagged,
        spam_missed=spam_missed,
        class_by_category={k: dict(v) for k, v in by_cat.items()},
        smoke_ok=smoke_ok,
        missing_records=missing,
    )
