"""BEC and social-engineering intent detection (ТЗ 16).

Pattern-based, bilingual (RU/EN), and deliberately conservative: intent alone is never a verdict —
it becomes one only in combination with sender/identity facts, which is decided by the rule set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from msp_mail_parser import ParsedMessage

from .context import AnalysisContext


@dataclass(frozen=True)
class IntentPattern:
    fact: str
    label: str
    patterns: tuple[str, ...]
    min_hits: int = 1


def _p(*patterns: str) -> tuple[str, ...]:
    return patterns


_INTENTS: tuple[IntentPattern, ...] = (
    IntentPattern(
        "intent_bank_details_change",
        "request to change bank/payment details",
        _p(
            r"(?i)(?:изменил|поменял|новы[йе]|обновл[её]нны[йе]|друг(?:ие|ой))\s+(?:наш[иие]\s+)?"
            r"(?:банковск\w+|платежн\w+|реквизит\w+|расч[её]тн\w+\s+сч[её]т\w*)",
            r"(?i)(?:реквизит\w*|сч[её]т\w*)\s+(?:измен|помен|обнов|друг)",
            # Verb-first word order, which Russian uses at least as often as noun-first:
            # "изменились реквизиты", "сменились платёжные данные". Missing it left the
            # most natural phrasing of a bank-details change undetected.
            r"(?i)(?:измен|помен|смен|обнов)\w*\s+(?:наш\w+\s+)?"
            r"(?:банковск\w+|платежн\w+|реквизит\w+|расч[её]тн\w+\s+сч[её]т\w*)",
            r"(?i)(?:измен|помен|смен|обнов)\w*[^.]{0,30}"
            r"(?:реквизит\w+|данн\w+)\s+(?:для\s+)?(?:оплат\w+|перечислен\w+|платеж\w+)",
            # The previous account is closed or blocked: a pretext with no legitimate use
            # in a payment instruction.
            r"(?i)(?:стар\w+|прежн\w+|предыдущ\w+)\s+(?:сч[её]т\w*|реквизит\w*)[^.]{0,40}"
            r"(?:закрыт|заблокирован|недействительн|не\s+действ|не\s+пройд)",
            r"(?i)(?:перевед|оплат\w+|направ\w+)\w*\s+(?:на\s+)?(?:нов\w+|друг\w+)\s+(?:сч[её]т|реквизит)",
            r"(?i)\b(?:change|update|updated|new|different|amend|revise)\b[^.\n]{0,40}\b"
            r"(?:bank(?:ing)?\s+(?:details|account|information|info)|account\s+(?:number|details)|"
            r"payment\s+(?:details|instructions|information)|wire\s+(?:details|instructions)|iban|"
            r"remittance\s+(?:details|advice)|beneficiary)",
            r"(?i)\b(?:bank(?:ing)?\s+details|payment\s+instructions|wire\s+instructions)\b[^.\n]{0,30}"
            r"\b(?:changed|updated|revised|new)\b",
        ),
    ),
    IntentPattern(
        "intent_urgent_payment",
        "urgent payment request",
        _p(
            r"(?i)(?:сроч\w+|неотлож\w+|как\s+можно\s+быстрее|до\s+конца\s+дня|сегодня\s+же)"
            r"[^.\n]{0,60}(?:оплат\w+|перевед\w+|плат[её]ж\w*|счет\w*|сч[её]т\w*|транзакц\w+)",
            r"(?i)(?:оплат\w+|перевед\w+|плат[её]ж\w*)[^.\n]{0,60}(?:сроч\w+|сегодня|до\s+\d{1,2}[:.]\d{2})",
            r"(?i)\b(?:urgent(?:ly)?|asap|immediate(?:ly)?|today|right away|before end of day|eod)\b"
            r"[^.\n]{0,60}\b(?:payment|pay|transfer|wire|invoice|settle|remit)\b",
            r"(?i)\b(?:payment|transfer|wire)\b[^.\n]{0,40}\b(?:urgent|asap|immediately|today)\b",
        ),
    ),
    IntentPattern(
        "intent_gift_cards",
        "gift card purchase request",
        _p(
            r"(?i)(?:подарочн\w+\s+(?:карт|сертификат)\w*|gift\s*cards?|itunes\s+card|steam\s+(?:card|wallet)|"
            r"google\s+play\s+card|amazon\s+(?:gift\s*)?card|apple\s+gift)",
            r"(?i)(?:куп\w+|приобрет\w+|purchase|buy)\w*[^.\n]{0,40}(?:карт\w+\s+оплат|prepaid|voucher)",
        ),
    ),
    IntentPattern(
        "intent_mfa_code_request",
        "request to share an MFA/one-time code",
        _p(
            r"(?i)(?:код\w*|пароль\w*)\s+(?:из\s+)?(?:смс|sms|подтвержден\w+|аутентификац\w+|двухфакторн\w+)",
            r"(?i)(?:перешл\w+|отправ\w+|сообщ\w+|продиктуй\w*|скинь\w*)[^.\n]{0,40}"
            r"(?:код|одноразов\w+\s+пароль|otp)",
            r"(?i)\b(?:send|share|forward|provide|give|tell)\b[^.\n]{0,40}"
            r"\b(?:(?:2fa|mfa|otp|verification|authentication|security|one[- ]time)\s*code|token from)\b",
            r"(?i)\b(?:approve|confirm|accept)\b[^.\n]{0,30}\b(?:mfa|2fa|push|authenticator)\s*"
            r"(?:request|prompt|notification)\b",
        ),
    ),
    IntentPattern(
        "intent_credential_request",
        "request for credentials or login",
        _p(
            r"(?i)(?:введите|укажите|подтвердите|обновите)[^.\n]{0,40}(?:пароль|логин|учетн\w+\s+данн\w+)",
            r"(?i)(?:пароль|учетн\w+\s+запис\w+)[^.\n]{0,40}(?:истека\w+|истек\w+|будет\s+заблокирован)",
            r"(?i)\b(?:enter|verify|confirm|update|re-?enter|provide)\b[^.\n]{0,40}"
            r"\b(?:password|credentials|login details|sign-?in details|user\s*name and password)\b",
            r"(?i)\b(?:password|account)\b[^.\n]{0,30}\b(?:expir\w+|will be (?:locked|suspended|disabled))\b",
        ),
    ),
    IntentPattern(
        "intent_confidential_files",
        "request for confidential documents or data",
        _p(
            r"(?i)(?:пришл\w+|отправ\w+|подготов\w+|вышли)\w*[^.\n]{0,50}"
            r"(?:конфиденциальн\w+|список\s+сотрудник\w+|персональн\w+\s+данн\w+|"
            r"справк\w+\s+2-?ндфл|копи\w+\s+паспорт\w*|скан\w*\s+паспорт\w*|ведомост\w+)",
            r"(?i)\b(?:send|share|forward|provide|email)\b[^.\n]{0,50}"
            r"\b(?:employee (?:list|data|records)|payroll (?:data|report)|w-?2|tax forms?|"
            r"confidential (?:file|document|report)s?|personal data|passport (?:scan|copy))\b",
        ),
    ),
    IntentPattern(
        "intent_bypass_process",
        "request to bypass the normal approval process",
        _p(
            r"(?i)(?:не\s+(?:сообщ\w+|говор\w+|обсужда\w+)|минуя|в\s+обход|без\s+(?:согласован\w+|"
            r"уведомлен\w+)|никому\s+не\s+говор\w+)[^.\n]{0,60}"
            r"(?:бухгалтер\w*|отдел\w*|процедур\w*|согласован\w*|руководств\w*|коллег\w*)",
            r"(?i)\b(?:don'?t|do not|no need to)\b[^.\n]{0,40}"
            r"\b(?:tell|inform|notify|contact|involve|cc)\b[^.\n]{0,40}"
            r"\b(?:anyone|accounting|finance|team|colleagues|hr)\b",
            r"(?i)\b(?:bypass|skip|without|circumvent|outside)\b[^.\n]{0,30}"
            r"\b(?:the )?(?:normal|usual|standard)?\s*(?:approval|procedure|process|authorization)\b",
            r"(?i)\b(?:keep this|handle this)\b[^.\n]{0,30}\b(?:confidential|between us|discreet|quiet)\b",
        ),
    ),
    IntentPattern(
        "intent_executive_urgency",
        "executive pressure and urgency",
        _p(
            r"(?i)(?:я\s+(?:сейчас\s+)?(?:на\s+(?:совещан\w+|встреч\w+)|в\s+самол[её]те|"
            r"не\s+могу\s+говорить))[^.\n]{0,80}(?:сроч\w+|нужно|треб\w+|сдела\w+)",
            r"(?i)(?:рассчитыва\w+\s+на\s+(?:вас|теб\w+)|под\s+мою\s+ответственность|"
            r"это\s+мо[её]\s+личн\w+\s+просьб\w+)",
            r"(?i)\b(?:i'?m|i am)\b[^.\n]{0,30}\b(?:in a meeting|travelling|traveling|on a (?:call|flight)|"
            r"unavailable|unable to talk)\b[^.\n]{0,60}\b(?:need|urgent|asap|please)\b",
            r"(?i)\b(?:count on you|trust you with this|discreet(?:ly)?|my personal request)\b",
        ),
    ),
    IntentPattern(
        "intent_invoice_fraud",
        "invoice or supplier payment fraud pattern",
        _p(
            r"(?i)(?:вложени\w+|прикрепл\w+|прилага\w+)[^.\n]{0,40}(?:сч[её]т\w*\s+(?:на\s+оплату|"
            r"фактур\w*)|инвойс\w*|акт\w*\s+сверк\w*)",
            r"(?i)(?:просроч\w+|неоплаченн\w+|задолженност\w+)[^.\n]{0,50}(?:сч[её]т|оплат|плат[её]ж)",
            # "счёт №… до сих пор не оплачен" — the most common invoice-pressure phrasing
            r"(?i)(?:сч[её]т\w*|инвойс\w*|плат[её]ж\w*)[^.\n]{0,40}(?:не\s+оплачен|"
            r"до\s+сих\s+пор\s+не\s+оплач)",
            r"(?i)(?:не\s+оплачен\w*|ожида\w+\s+оплат\w+)[^.\n]{0,40}(?:сч[её]т|инвойс|№\s*\d)",
            r"(?i)\b(?:attached|enclosed|please find)\b[^.\n]{0,40}\b(?:invoice|statement|remittance|"
            r"purchase order|proforma)\b",
            r"(?i)\b(?:overdue|outstanding|unpaid|past due)\b[^.\n]{0,40}"
            r"\b(?:invoice|balance|payment|account)\b",
        ),
    ),
    IntentPattern(
        "intent_payroll_change",
        "payroll or salary destination change",
        _p(
            r"(?i)(?:зарплат\w+|заработн\w+\s+плат\w+|выплат\w+)[^.\n]{0,60}"
            r"(?:на\s+(?:нов\w+|друг\w+)\s+(?:карт\w+|сч[её]т)|измен\w+\s+реквизит\w+)",
            r"(?i)(?:смен\w+|измен\w+)\w*[^.\n]{0,30}(?:карт\w+\s+для\s+зарплат|зарплатн\w+\s+"
            r"(?:карт\w+|сч[её]т|проект))",
            r"(?i)\b(?:change|update|switch)\b[^.\n]{0,40}\b(?:payroll|salary|direct deposit)\b"
            r"[^.\n]{0,30}\b(?:account|details|bank)\b",
        ),
    ),
    IntentPattern(
        "intent_fake_document_share",
        "fake shared document / cloud notification",
        _p(
            r"(?i)(?:подел\w+с[яь]?\s+с\s+вами|предостав\w+\s+доступ|открыт\s+доступ)[^.\n]{0,50}"
            r"(?:документ\w*|файл\w*|папк\w*)",
            r"(?i)\b(?:shared (?:a )?(?:document|file|folder|link)|has shared|invites? you to view|"
            r"you have a new (?:document|file)|view (?:document|file) in (?:onedrive|sharepoint|drive))\b",
            r"(?i)\b(?:docusign|adobe sign|dropbox|wetransfer|sharepoint|onedrive)\b[^.\n]{0,40}"
            r"\b(?:review|sign|download|view)\b",
        ),
    ),
    IntentPattern(
        "intent_fake_quota_or_expiry",
        "fake mailbox quota / account expiry notice",
        _p(
            r"(?i)(?:почтов\w+\s+ящик\w*|mailbox)[^.\n]{0,40}(?:заполнен|перепол\w+|превыш\w+\s+квот|"
            r"будет\s+заблокирован|отключ\w+)",
            r"(?i)\b(?:mailbox|storage|quota)\b[^.\n]{0,40}\b(?:full|exceeded|limit reached|almost full)\b",
            r"(?i)\b(?:account|subscription|licen[cs]e)\b[^.\n]{0,40}"
            r"\b(?:expir\w+|suspend\w+|deactivat\w+|terminat\w+)\b[^.\n]{0,40}"
            r"\b(?:24 hours|today|immediately|48 hours)\b",
            r"(?i)(?:подтвердите\s+(?:учетн\w+\s+запис\w+|адрес)|повторн\w+\s+(?:активац\w+|вход))"
            r"[^.\n]{0,40}(?:в\s+течение|иначе|будет)",
        ),
    ),
    IntentPattern(
        "intent_delivery_scam",
        "delivery / customs scam",
        _p(
            r"(?i)(?:посылк\w+|отправлен\w+|доставк\w+)[^.\n]{0,50}(?:задержан\w+|таможн\w+|"
            r"не\s+доставлен\w+|оплат\w+\s+(?:доставк|пошлин))",
            r"(?i)\b(?:parcel|package|shipment|delivery)\b[^.\n]{0,50}"
            r"\b(?:held|failed|pending|customs|unpaid (?:fee|duty)|reschedule)\b",
        ),
    ),
    IntentPattern(
        "intent_hr_scam",
        "HR-themed lure",
        _p(
            r"(?i)(?:новы\w+\s+(?:политик\w+|регламент\w+)|ознаком\w+\w*\s+с\s+приказ\w+|"
            r"измен\w+\s+в\s+(?:штатн\w+|услови\w+\s+труд))[^.\n]{0,60}(?:подтверд\w+|подпис\w+|войд\w+)",
            r"(?i)\b(?:new (?:hr )?policy|employee handbook|performance review|salary review|"
            r"bonus (?:letter|statement)|disciplinary)\b[^.\n]{0,50}\b(?:sign|acknowledge|review|login)\b",
        ),
    ),
    IntentPattern(
        "intent_thread_hijack_pretext",
        "reply pretext without a real thread",
        _p(
            r"(?i)^\s*(?:re|fwd|fw|ответ|пересылка)\s*:",
        ),
    ),
)

_URGENCY_WORDS = re.compile(
    r"(?i)\b(?:сроч\w+|немедленн\w+|незамедлительн\w+|срочность|критичн\w+|важно|"
    r"urgent|asap|immediately|right now|critical|time[- ]sensitive|deadline|last warning|final notice)\b"
)
_SECRECY_WORDS = re.compile(
    r"(?i)\b(?:конфиденциальн\w+|никому|между\s+нами|не\s+распростран\w+|"
    r"confidential(?:ly)?|discreet(?:ly)?|between us|private matter|do not share)\b"
)
_THREAT_WORDS = re.compile(
    r"(?i)\b(?:будет\s+заблокирован\w*|будет\s+удал[её]н\w*|потеря\w+\s+доступ|штраф\w*|"
    r"юридическ\w+\s+последств\w+|will be (?:blocked|deleted|suspended|terminated|closed)|"
    r"legal action|penalty|fine|lose access)\b"
)
_FINANCIAL_WORDS = re.compile(
    r"(?i)\b(?:оплат\w+|плат[её]ж\w*|перевод\w*|сч[её]т\w*|инвойс\w*|реквизит\w*|iban|swift|"
    r"payment|invoice|transfer|wire|remittance|bank account|beneficiary|usd|eur|rub|"
    r"\d[\d\s.,]{3,}\s*(?:руб|₽|\$|€|usd|eur))\b"
)


def bec_facts(
    msg: ParsedMessage, ctx: AnalysisContext, existing: dict[str, Any]
) -> list[tuple[str, Any, dict[str, Any]]]:
    text = f"{msg.subject}\n{msg.normalized_text}"[:100_000]
    out: list[tuple[str, Any, dict[str, Any]]] = []
    subject_only = msg.subject or ""

    for intent in _INTENTS:
        hits: list[str] = []
        for pattern in intent.patterns:
            source = subject_only if intent.fact == "intent_thread_hijack_pretext" else text
            m = re.search(pattern, source)
            if m:
                snippet = re.sub(r"\s+", " ", m.group(0))[:200]
                hits.append(snippet)
        if len(hits) >= intent.min_hits:
            out.append((intent.fact, True, {"label": intent.label, "matches": hits[:3]}))

    urgency = _URGENCY_WORDS.findall(text)
    if urgency:
        out.append(("tone_urgency", True, {"terms": sorted({u.lower() for u in urgency})[:6]}))
    secrecy = _SECRECY_WORDS.findall(text)
    if secrecy:
        out.append(("tone_secrecy", True, {"terms": sorted({s.lower() for s in secrecy})[:6]}))
    threat = _THREAT_WORDS.findall(text)
    if threat:
        out.append(("tone_threat", True, {"terms": sorted({t.lower() for t in threat})[:6]}))
    financial = _FINANCIAL_WORDS.findall(text)
    if financial:
        out.append(("financial_context", True, {"terms": sorted({f.lower() for f in financial})[:6]}))

    # A reply pretext with no References/In-Reply-To is a thread-hijack tell.
    if (
        any(f == "intent_thread_hijack_pretext" for f, _, _ in out)
        and not msg.header("In-Reply-To")
        and not msg.header("References")
    ):
        out.append(("reply_pretext_without_thread", True, {"subject": subject_only[:200]}))

    no_links = not msg.urls
    no_attachments = not msg.attachments
    intent_keys = {f for f, _, _ in out if f.startswith("intent_")}
    financial_intents = intent_keys & {
        "intent_bank_details_change",
        "intent_urgent_payment",
        "intent_invoice_fraud",
        "intent_payroll_change",
        "intent_gift_cards",
    }
    credential_intents = intent_keys & {
        "intent_credential_request",
        "intent_mfa_code_request",
    }
    if financial_intents:
        out.append(("financial_intent", True, {"intents": sorted(financial_intents)}))
    if credential_intents:
        out.append(("credential_intent", True, {"intents": sorted(credential_intents)}))
    if (financial_intents or credential_intents or intent_keys & {"intent_confidential_files"}) and (
        no_links and no_attachments
    ):
        out.append(("payload_free_request", True, {"intents": sorted(intent_keys)}))

    dept = (ctx.recipient_department or "").lower()
    if (
        dept
        and financial_intents
        and any(k in dept for k in ("financ", "бухгал", "финанс", "account", "treasur"))
    ):
        out.append(
            ("financial_request_to_finance_department", True, {"department": ctx.recipient_department})
        )
    if (
        dept
        and credential_intents
        and any(k in dept for k in ("it", "helpdesk", "support", "секьюр", "безопас"))
    ):
        out.append(("credential_request_to_it_department", True, {"department": ctx.recipient_department}))
    return out
