"""Synthetic test mail corpus (ТЗ 39).

Twenty safe, deterministic fixtures covering the required scenarios. Nothing here is live
malware: the only "malicious" payload is the EICAR test string, and known-bad indicators use
reserved .test domains that resolve nowhere.
"""

from __future__ import annotations

import base64
import io
import zipfile
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

CORP_DOMAIN = "corp.example"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@dataclass
class Fixture:
    name: str
    description: str
    raw: bytes
    expect_min_level: str = "LOW_RISK"
    expect_rules: tuple[str, ...] = ()
    expect_facts: tuple[str, ...] = ()
    tags: tuple[str, ...] = field(default_factory=tuple)
    #: Validation-corpus category (ТЗ 1.0.1 §10). Drives the export layout under ``corpus/``.
    category: str = "legitimate"
    # True when the expected level is only reachable after Threat Intelligence or a local
    # scanner has run: local analysis alone must report UNKNOWN rather than a clean result.
    requires_enrichment: bool = False


def _build(
    *,
    subject: str,
    from_addr: str,
    from_name: str = "",
    to: str = f"buh@{CORP_DOMAIN}",
    reply_to: str = "",
    text: str = "",
    html: str = "",
    auth: str = "spf=pass; dkim=pass; dmarc=pass",
    attachments: list[tuple[str, bytes, str]] | None = None,
    extra_headers: dict[str, str] | None = None,
    message_id_domain: str = "",
) -> bytes:
    msg = EmailMessage()
    msg["From"] = f'"{from_name}" <{from_addr}>' if from_name else from_addr
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    domain = message_id_domain or from_addr.rsplit("@", 1)[-1]
    msg["Message-ID"] = make_msgid(domain=domain)
    if reply_to:
        msg["Reply-To"] = reply_to
    if auth:
        msg["Authentication-Results"] = f"mx.{CORP_DOMAIN}; {auth}"
    msg["Received"] = f"from mail.{domain} (mail.{domain} [203.0.113.10]) by mx.{CORP_DOMAIN}"
    for key, value in (extra_headers or {}).items():
        msg[key] = value

    msg.set_content(text or "Текст сообщения.")
    if html:
        msg.add_alternative(html, subtype="html")
    for filename, data, mime in attachments or []:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype or "octet-stream", filename=filename)
    return msg.as_bytes()


#: A delivery chain that genuinely passes the organisation's gateway, newest hop first.
KSMG_HOST = f"ksmg-01.{CORP_DOMAIN}"
#: The relay that writes Authentication-Results in this corpus. Every chain ends here, so the
#: fixtures describe one topology rather than two.
EXCHANGE_HOST = f"mx.{CORP_DOMAIN}"
VIA_KSMG = (
    f"from {KSMG_HOST} (ksmg-01 [10.20.0.11]) by {EXCHANGE_HOST} with ESMTPS id aa11",
    f"from mx.vendor.example (mx.vendor.example [203.0.113.9]) by {KSMG_HOST} with ESMTPS id bb22",
)
#: The same message delivered straight to Exchange: whatever it claims, it never met the gateway.
DIRECT_TO_EXCHANGE = (
    f"from mx.attacker.example (unknown [198.51.100.7]) by {EXCHANGE_HOST} with ESMTP id cc33",
)


def _zip(entries: list[tuple[str, bytes]], *, password_protected: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    data = buffer.getvalue()
    return set_encrypted_flag(data) if password_protected else data


def set_encrypted_flag(data: bytes) -> bytes:
    """Set the ZIP "encrypted" general-purpose bit without shipping an encrypted payload.

    ``zipfile`` resets flag bits when writing, so the bit is patched afterwards in both the local
    file headers and the central directory. The archive then looks password-protected to any
    reader, which is what the parser must handle, while the fixture stays inert.
    """
    out = bytearray(data)
    for signature, flag_offset in ((b"PK", 6), (b"PK", 8)):
        start = 0
        while True:
            index = out.find(signature, start)
            if index == -1:
                break
            position = index + flag_offset
            if position + 1 < len(out):
                out[position] |= 0x01
            start = index + 4
    return bytes(out)


def _nested_zip(depth: int) -> bytes:
    payload = b"inner payload"
    data = _zip([("payload.txt", payload)])
    for level in range(depth):
        data = _zip([(f"level{level}.zip", data)])
    return data


def build_corpus() -> list[Fixture]:
    fixtures: list[Fixture] = []

    # 1. normal internal
    fixtures.append(
        Fixture(
            "01_normal_internal",
            "Обычное внутреннее письмо",
            _build(
                subject="Протокол совещания",
                from_addr=f"ivanov@{CORP_DOMAIN}",
                from_name="Сергей Иванов",
                text="Коллеги, направляю протокол вчерашнего совещания. С уважением, Сергей.",
            ),
            expect_min_level="LOW_RISK",
            tags=("benign",),
        )
    )

    # 2. normal external
    fixtures.append(
        Fixture(
            "02_normal_external",
            "Обычное внешнее письмо от известного контрагента",
            _build(
                subject="Коммерческое предложение",
                from_addr="sales@partner.example",
                from_name="Отдел продаж Partner",
                text="Добрый день! Направляем наше коммерческое предложение во вложении к договору.",
            ),
            expect_min_level="LOW_RISK",
            tags=("benign",),
        )
    )

    # 3. display-name impersonation
    fixtures.append(
        Fixture(
            "03_display_name_impersonation",
            "Подмена отображаемого имени руководителя",
            _build(
                subject="Нужна помощь",
                from_addr="ceo.corp@freemail.example",
                from_name="Иван Петров",
                text="Вы на месте? Нужно срочно решить один вопрос. Иван Петров",
                auth="spf=pass; dkim=none; dmarc=none",
            ),
            expect_min_level="HIGH_RISK",
            expect_rules=("SND-030", "SND-031"),
            expect_facts=("protected_identity_impersonation",),
            tags=("impersonation",),
        )
    )

    # 4. lookalike corporate domain
    fixtures.append(
        Fixture(
            "04_lookalike_domain",
            "Домен, визуально похожий на корпоративный",
            _build(
                subject="Обновление договора",
                from_addr="info@corp-example.test",
                from_name="Корпоративная служба",
                text="Направляем обновлённую версию договора для подписания.",
                auth="spf=pass; dkim=none; dmarc=fail",
            ),
            expect_min_level="SUSPICIOUS",
            expect_facts=("from_domain_lookalike_corporate",),
            tags=("lookalike",),
        )
    )

    # 5. punycode / homoglyph
    fixtures.append(
        Fixture(
            "05_punycode_homoglyph",
            "Домен с омоглифами в Punycode",
            _build(
                subject="Подтверждение учётной записи",
                from_addr="support@xn--micrsoft-o4a.test",
                from_name="Microsoft Support",
                html=(
                    '<html><body><p>Подтвердите учётную запись.</p>'
                    '<a href="http://xn--micrsoft-o4a.test/login">https://login.microsoft.com</a>'
                    "</body></html>"
                ),
                auth="spf=fail; dkim=none; dmarc=fail",
            ),
            expect_min_level="HIGH_RISK",
            expect_facts=("from_domain_punycode", "url_visible_href_mismatch"),
            tags=("lookalike", "phishing"),
        )
    )

    # 6. reply-to mismatch
    fixtures.append(
        Fixture(
            "06_reply_to_mismatch",
            "Reply-To на постороннем домене",
            _build(
                subject="Согласование оплаты",
                from_addr="finance@partner.example",
                from_name="Partner Finance",
                reply_to="finance.partner@mailbox.test",
                text="Просим согласовать оплату по прилагаемому счёту.",
            ),
            expect_min_level="SUSPICIOUS",
            expect_facts=("reply_to_domain_mismatch",),
            tags=("spoofing",),
        )
    )

    # 7. fake Microsoft login
    fixtures.append(
        Fixture(
            "07_fake_microsoft_login",
            "Поддельная страница входа Microsoft 365",
            _build(
                subject="Срок действия пароля истекает сегодня",
                from_addr="no-reply@account-security.test",
                from_name="Microsoft 365",
                html=(
                    "<html><body><p>Срок действия вашего пароля истекает сегодня. "
                    "Подтвердите учётную запись, иначе доступ будет заблокирован.</p>"
                    '<a href="http://account-security.test/owa/login?id=abc123456789012345">'
                    "https://login.microsoftonline.com</a>"
                    '<form action="http://account-security.test/collect">'
                    '<input type="password" name="p"></form></body></html>'
                ),
                auth="spf=fail; dkim=none; dmarc=fail",
            ),
            expect_min_level="HIGH_RISK",
            expect_facts=("html_password_input", "url_credential_path"),
            tags=("phishing", "credential"),
        )
    )

    # 8. invoice BEC
    fixtures.append(
        Fixture(
            "08_invoice_bec",
            "BEC: срочная оплата счёта",
            _build(
                subject="Re: Оплата счёта №4417",
                from_addr="a.smirnov@supplier-invoices.test",
                from_name="Андрей Смирнов",
                text=(
                    "Добрый день! Счёт №4417 до сих пор не оплачен. Просим оплатить срочно, "
                    "сегодня же, сумма 1 250 000 руб. Реквизиты во вложении."
                ),
                auth="spf=pass; dkim=none; dmarc=none",
            ),
            expect_min_level="SUSPICIOUS",
            expect_facts=("intent_invoice_fraud", "intent_urgent_payment"),
            tags=("bec",),
        )
    )

    # 9. bank details change
    fixtures.append(
        Fixture(
            "09_bank_details_change",
            "BEC: смена банковских реквизитов",
            _build(
                subject="Изменение реквизитов",
                from_addr="director@partner-payments.test",
                from_name="Мария Кузнецова",
                text=(
                    "Уважаемые коллеги! Мы изменили банковские реквизиты. Все последующие платежи "
                    "просим направлять на новый расчётный счёт. Не сообщайте бухгалтерии до "
                    "подтверждения — это моя личная просьба."
                ),
                auth="spf=fail; dkim=none; dmarc=fail",
            ),
            expect_min_level="HIGH_RISK",
            expect_facts=("intent_bank_details_change", "intent_bypass_process"),
            tags=("bec",),
        )
    )

    # 10. MFA code request
    fixtures.append(
        Fixture(
            "10_mfa_request",
            "Запрос кода подтверждения MFA",
            _build(
                subject="Служба поддержки: подтверждение доступа",
                from_addr="helpdesk@it-support.test",
                from_name="Служба ИТ-поддержки",
                text=(
                    "Для восстановления доступа перешлите нам код из СМС, который придёт в "
                    "течение минуты. Также подтвердите push-запрос в приложении аутентификации."
                ),
                auth="spf=fail; dkim=none; dmarc=fail",
            ),
            expect_min_level="HIGH_RISK",
            expect_facts=("intent_mfa_code_request",),
            tags=("bec", "credential"),
        )
    )

    # 11. macro-enabled attachment
    ole_macro = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + b"_VBA_PROJECT" + b"\x00" * 256
    fixtures.append(
        Fixture(
            "11_macro_attachment",
            "Документ с макросами от внешнего отправителя",
            _build(
                subject="Акт сверки",
                from_addr="buh@contractor.test",
                from_name="Бухгалтерия",
                text="Во вложении акт сверки. Включите макросы для просмотра.",
                attachments=[("akt.doc", ole_macro, "application/msword")],
            ),
            expect_min_level="SUSPICIOUS",
            expect_facts=("attachment_macro_enabled",),
            tags=("attachment",),
        )
    )

    # 12. double extension
    fixtures.append(
        Fixture(
            "12_double_extension",
            "Двойное расширение файла",
            _build(
                subject="Документы по заявке",
                from_addr="noreply@delivery-notice.test",
                text="Документы во вложении.",
                attachments=[("документ.pdf.exe", b"MZ" + b"\x00" * 128, "application/octet-stream")],
            ),
            expect_min_level="HIGH_RISK",
            expect_facts=("attachment_double_extension", "attachment_executable"),
            tags=("attachment",),
        )
    )

    # 13. encrypted ZIP
    fixtures.append(
        Fixture(
            "13_encrypted_zip",
            "Запароленный архив",
            _build(
                subject="Архив с документами (пароль 1234)",
                from_addr="sender@archive-mail.test",
                text="Пароль от архива: 1234",
                attachments=[
                    ("docs.zip", _zip([("secret.bin", b"x" * 100)], password_protected=True), "application/zip")
                ],
            ),
            expect_min_level="SUSPICIOUS",
            expect_facts=("attachment_encrypted_archive",),
            tags=("attachment",),
        )
    )

    # 14. nested archives with an executable inside
    fixtures.append(
        Fixture(
            "14_nested_archive",
            "Вложенные архивы с исполняемым файлом",
            _build(
                subject="Обновление ПО",
                from_addr="update@software-update.test",
                text="Распакуйте и запустите установщик.",
                attachments=[
                    (
                        "update.zip",
                        _zip([("inner.zip", _zip([("setup.exe", b"MZ" + b"\x00" * 200)]))]),
                        "application/zip",
                    )
                ],
            ),
            expect_min_level="HIGH_RISK",
            expect_facts=("attachment_nested_archive", "archive_contains_dangerous_file"),
            tags=("attachment",),
        )
    )

    # 15. malformed MIME
    malformed = (
        b"From: broken@malformed.test\r\n"
        b"To: buh@corp.example\r\n"
        b"Subject: =?utf-8?B?INEB0YDQvtGH0L3Qvg?=\r\n"
        b"Content-Type: multipart/mixed; boundary=\r\n"
        b"MIME-Version: 1.0\r\n"
        b"\r\n"
        + "--\r\nContent-Type: text/plain\r\n\r\nтело без корректной границы\r\n".encode()
        + b"--broken--\r\n"
    )
    fixtures.append(
        Fixture(
            "15_malformed_mime",
            "Некорректный MIME",
            malformed,
            expect_min_level="UNKNOWN",
            tags=("parser",),
        )
    )

    # 16. same campaign to multiple users
    for index, recipient in enumerate(("buh@corp.example", "finance@corp.example", "ceo@corp.example")):
        fixtures.append(
            Fixture(
                f"16_campaign_{index + 1}",
                "Кампания: одно письмо нескольким получателям",
                _build(
                    subject="Уведомление о задолженности",
                    from_addr="billing@debt-notice.test",
                    from_name="Отдел взысканий",
                    to=recipient,
                    html=(
                        "<html><body><p>У вас имеется задолженность. "
                        'Оплатите по <a href="http://debt-notice.test/pay">ссылке</a>.</p></body></html>'
                    ),
                    auth="spf=pass; dkim=none; dmarc=none",
                ),
                expect_min_level="LOW_RISK",
                tags=("campaign",),
            )
        )

    # 17. S/MIME encrypted content (unsupported)
    fixtures.append(
        Fixture(
            "17_encrypted_smime",
            "Зашифрованное содержимое S/MIME",
            _build(
                subject="Зашифрованное сообщение",
                from_addr="secure@partner.example",
                text="",
                attachments=[
                    ("smime.p7m", base64.b64encode(b"encrypted-content-placeholder"), "application/pkcs7-mime")
                ],
            ),
            expect_min_level="UNKNOWN",
            tags=("parser", "unknown"),
        )
    )

    # 18. provider unavailable (analysis must still complete)
    fixtures.append(
        Fixture(
            "18_provider_unavailable",
            "Письмо для проверки недоступности TI",
            _build(
                subject="Проверка доступности провайдера",
                from_addr="test@provider-outage.test",
                html='<html><body><a href="http://provider-outage.test/x">ссылка</a></body></html>',
            ),
            expect_min_level="LOW_RISK",
            tags=("resilience",),
        )
    )

    # 19. known-bad indicator, represented safely
    fixtures.append(
        Fixture(
            "19_known_bad_indicator",
            "Известный вредоносный индикатор (тестовый)",
            _build(
                subject="Важный документ",
                from_addr="sender@known-bad.test",
                html='<html><body><a href="http://known-bad.test/malware-test">Открыть</a></body></html>',
                attachments=[("test.txt", EICAR, "text/plain")],
            ),
            expect_min_level="SUSPICIOUS",
            requires_enrichment=True,
            tags=("ti", "malware"),
        )
    )

    # 20. false-positive fixture: legitimate bulk sender with differing Return-Path
    fixtures.append(
        Fixture(
            "20_false_positive_bulk",
            "Легитимная рассылка: Return-Path отличается",
            _build(
                subject="Ежемесячный отчёт по услугам",
                from_addr="news@trusted-service.example",
                from_name="Trusted Service",
                text="Ваш ежемесячный отчёт готов. Спасибо, что вы с нами.",
                auth="spf=pass; dkim=pass; dmarc=pass",
                extra_headers={
                    "Return-Path": "<bounce-12345@mailer.trusted-service.example>",
                    "List-Unsubscribe": "<mailto:unsubscribe@trusted-service.example>",
                },
            ),
            expect_min_level="LOW_RISK",
            tags=("false_positive",),
        )
    )

    fixtures.extend(_pilot_scenarios())
    _assign_categories(fixtures)
    return fixtures


def _received(chain: tuple[str, ...]) -> dict[str, str]:
    """A Received chain as extra headers.

    ``EmailMessage`` keeps repeated headers in insertion order, and the platform reads the
    chain newest-first, so the tuple is written in that order and inserted as given.
    """
    return {f"Received-{index}": value for index, value in enumerate(chain)}


def _with_chain(raw: bytes, chain: tuple[str, ...]) -> bytes:
    """Replace the fixture's placeholder Received header with a full chain.

    Done textually rather than through ``EmailMessage`` because the header must appear several
    times, in order, which the mapping interface cannot express.
    """
    lines = raw.split(b"\r\n") if b"\r\n" in raw else raw.split(b"\n")
    separator = b"\r\n" if b"\r\n" in raw else b"\n"
    out: list[bytes] = []
    replaced = False
    for line in lines:
        if line.lower().startswith(b"received:") and not replaced:
            out.extend(b"Received: " + hop.encode("utf-8") for hop in chain)
            replaced = True
            continue
        out.append(line)
    if not replaced:
        out = [b"Received: " + hop.encode("utf-8") for hop in chain] + out
    return separator.join(out)


def _pilot_scenarios() -> list[Fixture]:
    """Scenarios added for the shadow pilot (ТЗ 1.0.1 §9).

    The three gateway fixtures are the important ones: they differ only in the delivery chain,
    so they show that the same headers are evidence in one case and a forgery in another.

    Limits themselves are deliberately *not* exercised here. A fixture large enough to exceed the
    real message limit would add tens of megabytes to every test run to prove something a
    tightened ``ParserLimits`` proves in a few hundred bytes — see
    ``tests/integration/test_durable_intake.py::TestParserLimitSignals``.
    """
    out: list[Fixture] = []

    out.append(
        Fixture(
            "21_gateway_clean_verified",
            "KSMG проверил письмо и ничего не нашёл; прохождение подтверждено цепочкой",
            _with_chain(
                _build(
                    subject="Счёт на оплату по договору",
                    from_addr="billing@vendor.example",
                    from_name="Vendor Billing",
                    text="Направляем счёт по договору. Реквизиты прежние.",
                    extra_headers={
                        "X-KSMG-Antivirus-Status": "Clean",
                        "X-KSMG-AntiSpam-Status": "Clean",
                    },
                ),
                VIA_KSMG,
            ),
            expect_min_level="LOW_RISK",
            expect_facts=("upstream_gateway_clean_observed",),
            tags=("gateway",),
            category="gateway-headers",
        )
    )
    out.append(
        Fixture(
            "22_gateway_malware_verified",
            "KSMG обнаружил вредоносное вложение; прохождение подтверждено",
            _with_chain(
                _build(
                    subject="Документы по заявке",
                    from_addr="sender@vendor.example",
                    text="Документы во вложении.",
                    extra_headers={
                        "X-KSMG-Antivirus-Status": "Detected: EICAR-Test-File",
                        "X-KSMG-Antivirus-Method": "Signature",
                    },
                ),
                VIA_KSMG,
            ),
            expect_min_level="MALICIOUS",
            expect_rules=("GW-001",),
            expect_facts=("upstream_malware_detection",),
            tags=("gateway", "malware"),
            category="gateway-headers",
        )
    )
    out.append(
        Fixture(
            "23_spoofed_ksmg_header",
            "Подделанные заголовки KSMG: цепочка доставки шлюз не подтверждает",
            _with_chain(
                _build(
                    subject="Срочно: смена банковских реквизитов",
                    from_addr="ceo@corp-example.example",
                    from_name="Иван Петров",
                    text=(
                        "Коллеги, оплату по договору переведите на новый счёт. "
                        "Реквизиты во вложении, счёт не оплачен, вопрос срочный."
                    ),
                    extra_headers={
                        "X-KSMG-Antivirus-Status": "Clean",
                        "X-KSMG-AntiSpam-Status": "Clean",
                        "X-Spam-Flag": "NO",
                    },
                ),
                DIRECT_TO_EXCHANGE,
            ),
            expect_min_level="HIGH_RISK",
            expect_facts=("unverified_gateway_header",),
            tags=("gateway", "spoofing"),
            category="gateway-headers",
        )
    )
    out.append(
        Fixture(
            "24_spoofed_authentication_results",
            "Подделанный Authentication-Results от недоверенного сервера",
            _with_chain(
                _build(
                    subject="Подтвердите платёж",
                    from_addr="cfo@corp-example.example",
                    from_name="Ольга Смирнова",
                    text="Подтвердите платёж по новым реквизитам сегодня до 17:00.",
                    auth="",
                    extra_headers={
                        "Authentication-Results": f"{KSMG_HOST}; spf=pass; dkim=pass; dmarc=pass",
                    },
                ),
                DIRECT_TO_EXCHANGE,
            ),
            expect_min_level="SUSPICIOUS",
            expect_facts=("authentication_results_forged",),
            tags=("gateway", "spoofing"),
            category="gateway-headers",
        )
    )
    out.append(
        Fixture(
            "25_fake_owa_login",
            "Поддельная страница входа OWA",
            _build(
                subject="Срок действия пароля истекает сегодня",
                from_addr="it-support@corp-example.example",
                from_name="IT Support",
                text="Подтвердите пароль по ссылке, иначе доступ к почте будет закрыт.",
                html=(
                    '<p>Ваш пароль истекает. <a href="https://owa-corp.example.test/owa/auth.aspx">'
                    "Продлите доступ</a></p>"
                ),
            ),
            expect_min_level="SUSPICIOUS",
            tags=("phishing", "credential"),
            category="phishing",
        )
    )
    out.append(
        Fixture(
            "26_fake_hr_document",
            "Поддельный документ от отдела кадров",
            _build(
                subject="Ознакомьтесь с приказом об изменении графика",
                from_addr="hr@corp-example.example",
                from_name="Отдел кадров",
                text="Ознакомьтесь с приказом и подтвердите получение во вложении.",
                attachments=[("prikaz.docm", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1macro", "application/octet-stream")],
            ),
            expect_min_level="SUSPICIOUS",
            tags=("impersonation", "attachment"),
            category="impersonation",
        )
    )
    out.append(
        Fixture(
            "27_ceo_fraud",
            "CEO fraud: срочная просьба руководителя без вложений и ссылок",
            _build(
                subject="Конфиденциально",
                from_addr="i.petrov@corp-example.example",
                from_name="Иван Петров",
                reply_to="reply@corp-example.example",
                text=(
                    "Я сейчас на встрече и не могу говорить. Нужно срочно провести платёж "
                    "контрагенту, реквизиты пришлю следующим письмом. Никому пока не сообщайте."
                ),
            ),
            expect_min_level="HIGH_RISK",
            tags=("bec", "impersonation"),
            category="bec",
        )
    )
    out.append(
        Fixture(
            "28_newsletter",
            "Обычная рассылка: не спам и не атака",
            _build(
                subject="Дайджест отраслевых новостей за неделю",
                from_addr="digest@industry-news.example",
                from_name="Industry Digest",
                text="Ваш еженедельный дайджест. Отписаться можно по ссылке внизу письма.",
                extra_headers={
                    "List-Unsubscribe": "<mailto:unsubscribe@industry-news.example>",
                    "Precedence": "bulk",
                },
            ),
            expect_min_level="LOW_RISK",
            tags=("benign", "false_positive"),
            category="legitimate",
        )
    )
    out.append(
        Fixture(
            "29_spam_marked_by_gateway",
            "Шлюз отнёс письмо к спаму; прохождение подтверждено",
            _with_chain(
                _build(
                    subject="Выгодное предложение только сегодня",
                    from_addr="offers@promo.example",
                    text="Скидки до 90% только сегодня. Успейте купить.",
                    extra_headers={
                        "X-KSMG-AntiSpam-Status": "Spam",
                        "X-KSMG-AntiSpam-Rate": "score=9.8",
                    },
                ),
                VIA_KSMG,
            ),
            expect_min_level="LOW_RISK",
            expect_rules=("GW-002",),
            tags=("gateway", "spam"),
            category="spam",
        )
    )
    out.append(
        Fixture(
            "30_large_but_analysable",
            "Крупное письмо в пределах лимитов: разбирается полностью",
            _build(
                subject="Архив материалов проекта",
                from_addr="projects@vendor.example",
                text="Материалы во вложении.",
                attachments=[("materials.bin", b"A" * (2 * 1024 * 1024), "application/octet-stream")],
            ),
            expect_min_level="UNKNOWN",
            tags=("parser",),
            category="malformed",
        )
    )
    return out


#: Tag -> validation-corpus directory (ТЗ 1.0.1 §10). The first matching tag wins.
_CATEGORY_BY_TAG: tuple[tuple[str, str], ...] = (
    ("gateway", "gateway-headers"),
    ("bec", "bec"),
    ("impersonation", "impersonation"),
    ("lookalike", "impersonation"),
    ("spoofing", "impersonation"),
    ("phishing", "phishing"),
    ("credential", "phishing"),
    ("attachment", "malware-simulated"),
    ("malware", "malware-simulated"),
    ("ti", "malware-simulated"),
    ("parser", "malformed"),
    ("limits", "malformed"),
    ("resilience", "malformed"),
    ("spam", "spam"),
    ("campaign", "phishing"),
    ("benign", "legitimate"),
    ("false_positive", "legitimate"),
)


def _assign_categories(fixtures: list[Fixture]) -> None:
    """Derive a category from the tags for fixtures that predate the taxonomy."""
    for fixture in fixtures:
        if fixture.category != "legitimate":
            continue
        for tag, category in _CATEGORY_BY_TAG:
            if tag in fixture.tags:
                fixture.category = category
                break


CORPUS = build_corpus()
BY_NAME = {f.name: f for f in CORPUS}


def get(name: str) -> Fixture:
    return BY_NAME[name]


#: The categories of ТЗ 1.0.1 §10, in the order the export writes them.
CATEGORIES: tuple[str, ...] = (
    "legitimate",
    "phishing",
    "bec",
    "impersonation",
    "spam",
    "malware-simulated",
    "malformed",
    "gateway-headers",
)


def by_category() -> dict[str, list[Fixture]]:
    return {
        category: [f for f in CORPUS if f.category == category] for category in CATEGORIES
    }
