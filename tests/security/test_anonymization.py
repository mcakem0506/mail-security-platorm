"""Обезличивание письма (ТЗ 1.0.4 §9).

Проверяется с двух сторон, и вторая важнее первой.

Первая: персональных данных в результате нет. Вторая: **то, на чём работает детектирование,
осталось**. Письмо, из которого вычистили всё подряд, безопасно и бесполезно — по нему нельзя
проверить ни расхождение Reply-To, ни похожесть домена, ни результаты аутентификации, и значит
нельзя и пополнить им золотой корпус, ради чего обезличивание и делается.
"""

from __future__ import annotations

import hashlib
import re
from email import message_from_bytes, policy

import pytest
from msp_mail_parser import parse_message
from msp_mail_parser.anonymize import (
    AnonymizationPolicy,
    Anonymizer,
    anonymize_message,
    fingerprint,
)

SALT = b"validation-set-salt-for-tests"
CORP = "corp.example"


def _message(
    *,
    from_addr: str = "ivan.petrov@partner.example",
    from_name: str = "Иван Петров",
    to: str = "buh@corp.example",
    reply_to: str = "",
    subject: str = "Счёт на оплату",
    text: str = "",
    html: str = "",
    attachment: tuple[str, bytes, str] | None = None,
    auth: str = "spf=pass; dkim=pass; dmarc=pass",
) -> bytes:
    from email.message import EmailMessage

    message = EmailMessage()
    message["From"] = f'"{from_name}" <{from_addr}>' if from_name else from_addr
    message["To"] = to
    message["Subject"] = subject
    message["Message-ID"] = "<thread-42@partner.example>"
    message["References"] = "<earlier-1@partner.example>"
    message["Authentication-Results"] = f"mx.corp.example; {auth}"
    message["Received-SPF"] = "pass (partner.example: domain of partner.example designates ...)"
    message["DKIM-Signature"] = "v=1; a=rsa-sha256; d=partner.example; s=mail; b=AAAA"
    if reply_to:
        message["Reply-To"] = reply_to
    message.set_content(text or "Добрый день! Направляем документы.")
    if html:
        message.add_alternative(html, subtype="html")
    if attachment:
        name, data, mime = attachment
        maintype, _, subtype = mime.partition("/")
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return message.as_bytes()


def _body_text(raw: bytes) -> str:
    """Склеить текстовые части. Тело письма закодировано, поиск по сырым байтам ничего не найдёт."""
    message = message_from_bytes(raw, policy=policy.default)
    chunks: list[str] = []
    for part in message.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                chunks.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
    return "\n".join(chunks)


def _anonymize(raw: bytes, **kwargs: object) -> tuple[bytes, dict[str, int]]:
    policy_ = AnonymizationPolicy(corporate_domains=(CORP,), **kwargs)  # type: ignore[arg-type]
    result = anonymize_message(raw, salt=SALT, policy_=policy_)
    return result.raw, result.replacements


class TestPersonalDataIsGone:
    def test_local_parts_and_names_are_replaced(self) -> None:
        raw, counts = _anonymize(_message())
        body = _body_text(raw) + str(message_from_bytes(raw, policy=policy.default))
        assert "ivan.petrov" not in body
        assert "Иван Петров" not in body
        assert "buh@" not in body
        assert counts["local_parts"] >= 2
        assert counts["display_names"] >= 1

    def test_phone_numbers_and_account_numbers_are_replaced(self) -> None:
        raw, counts = _anonymize(
            _message(
                text=(
                    "Телефон для связи +7 495 123-45-67, расчётный счёт 40702810412345678901, "
                    "карта 4111 1111 1111 1111."
                )
            )
        )
        body = _body_text(raw)
        assert "123-45-67" not in body
        assert "40702810412345678901" not in body
        assert "4111 1111 1111 1111" not in body
        assert counts.get("phone_numbers", 0) + counts.get("account_numbers", 0) >= 3

    def test_thread_headers_are_stripped(self) -> None:
        raw, counts = _anonymize(_message())
        message = message_from_bytes(raw, policy=policy.default)
        assert message.get("Message-ID") is None
        assert message.get("References") is None
        assert counts["thread_headers"] >= 2

    def test_organization_secrets_are_replaced(self) -> None:
        raw, counts = _anonymize(
            _message(text="Выгрузка из системы ВЕКТОР-ФИН, код площадки SPB-OPS-7."),
            organization_secrets=("ВЕКТОР-ФИН", "SPB-OPS-7"),
        )
        body = _body_text(raw)
        assert "ВЕКТОР-ФИН" not in body
        assert "SPB-OPS-7" not in body
        assert counts["organization_secrets"] == 2

    def test_attachment_bytes_are_removed_by_default(self) -> None:
        secret = "Договор с Петровым Иваном Сергеевичем".encode()
        result = anonymize_message(
            _message(attachment=("договор.txt", secret, "text/plain")),
            salt=SALT,
            policy_=AnonymizationPolicy(corporate_domains=(CORP,)),
        )
        assert b"\xd0\x9f\xd0\xb5\xd1\x82\xd1\x80\xd0\xbe\xd0\xb2" not in result.raw
        assert result.replacements["attachment_bodies"] == 1

    def test_attachment_type_and_hash_survive_as_data(self) -> None:
        """ТЗ §9 требует сохранить тип и хеш вложения — как данные, а не как содержимое."""
        payload = b"invoice bytes"
        result = anonymize_message(
            _message(attachment=("invoice.pdf", payload, "application/pdf")),
            salt=SALT,
            policy_=AnonymizationPolicy(corporate_domains=(CORP,)),
        )
        assert len(result.attachments) == 1
        recorded = result.attachments[0]
        assert recorded["content_type"] == "application/pdf"
        assert recorded["sha256"] == hashlib.sha256(payload).hexdigest()
        assert recorded["size_bytes"] == len(payload)


class TestSecurityRelevantStructureSurvives:
    """Вторая половина задачи, и без неё первая бессмысленна."""

    def test_domains_are_preserved_on_both_sides(self) -> None:
        raw, _counts = _anonymize(_message())
        body = str(message_from_bytes(raw, policy=policy.default))
        assert "partner.example" in body, "домен отправителя — предмет анализа"
        assert CORP in body, "корпоративный домен нужен, чтобы видеть внешнего отправителя"

    def test_a_reply_to_mismatch_is_still_a_mismatch(self) -> None:
        raw, _counts = _anonymize(_message(from_addr="ceo@corp.example", reply_to="ceo@attacker.test"))
        parsed = parse_message(raw)
        assert parsed.from_ is not None
        assert parsed.reply_to
        assert parsed.reply_to[0].domain != parsed.from_.domain, (
            "расхождение Reply-To обязано остаться видимым"
        )

    def test_the_same_address_gets_the_same_pseudonym(self) -> None:
        """Иначе «письмо от того же отправителя» перестаёт быть видно корреляции кампаний."""
        first, _ = _anonymize(_message(subject="Первое"))
        second, _ = _anonymize(_message(subject="Второе"))
        sender_first = str(message_from_bytes(first, policy=policy.default).get("From"))
        sender_second = str(message_from_bytes(second, policy=policy.default).get("From"))
        assert sender_first == sender_second

    def test_different_addresses_get_different_pseudonyms(self) -> None:
        a, _ = _anonymize(_message(from_addr="one@partner.example"))
        b, _ = _anonymize(_message(from_addr="two@partner.example"))
        assert message_from_bytes(a, policy=policy.default).get("From") != message_from_bytes(
            b, policy=policy.default
        ).get("From")

    def test_the_same_local_part_in_different_domains_is_not_merged(self) -> None:
        """``info`` у двух контрагентов — разные люди; один псевдоним придумал бы им связь."""
        anonymizer = Anonymizer(SALT, AnonymizationPolicy(corporate_domains=(CORP,)))
        assert anonymizer.local_part("info", "a.example") != anonymizer.local_part("info", "b.example")

    def test_authentication_results_are_untouched(self) -> None:
        raw, _counts = _anonymize(_message(auth="spf=fail; dkim=none; dmarc=fail"))
        message = message_from_bytes(raw, policy=policy.default)
        assert "spf=fail" in str(message.get("Authentication-Results"))
        assert "dmarc=fail" in str(message.get("Authentication-Results"))
        assert message.get("Received-SPF") is not None
        assert message.get("DKIM-Signature") is not None

    def test_mime_structure_is_preserved(self) -> None:
        raw, _counts = _anonymize(
            _message(
                text="Текст письма",
                html="<html><body><p>Текст письма</p></body></html>",
                attachment=("file.pdf", b"pdf", "application/pdf"),
            )
        )
        before = [
            part.get_content_type()
            for part in message_from_bytes(
                _message(
                    text="Текст письма",
                    html="<html><body><p>Текст письма</p></body></html>",
                    attachment=("file.pdf", b"pdf", "application/pdf"),
                ),
                policy=policy.default,
            ).walk()
        ]
        after = [part.get_content_type() for part in message_from_bytes(raw, policy=policy.default).walk()]
        assert after == before

    def test_an_external_url_keeps_its_host(self) -> None:
        raw, _counts = _anonymize(_message(text="Подробности: http://payment-corp-example.test/invoice/7781"))
        body = _body_text(raw)
        assert "payment-corp-example.test" in body, "хост внешней ссылки и есть предмет анализа"
        assert "/invoice/7781" not in body, "путь может нести идентификатор получателя"

    def test_an_internal_url_is_replaced_entirely(self) -> None:
        raw, counts = _anonymize(
            _message(text="Документ во внутренней системе: https://portal.corp.example/doc/112")
        )
        body = _body_text(raw)
        assert "portal.corp.example" not in body
        assert "internal-" in body
        assert counts["internal_urls"] == 1

    def test_the_result_still_parses(self) -> None:
        """Обезличенное письмо должно оставаться письмом: иначе его нельзя прогнать движком."""
        raw, _counts = _anonymize(
            _message(
                text="Счёт 1234, звоните +7 495 000-00-00",
                html="<html><body>Счёт</body></html>",
                attachment=("a.pdf", b"x", "application/pdf"),
            )
        )
        parsed = parse_message(raw)
        assert parsed.parse_ok
        assert parsed.from_ is not None
        assert parsed.attachments


class TestFingerprint:
    def test_a_message_and_its_anonymized_copy_share_a_fingerprint(self) -> None:
        """По отпечатку письмо узнаётся после обезличивания, иначе оно попадёт в набор дважды."""
        raw = _message(attachment=("a.pdf", b"payload", "application/pdf"))
        anonymized, _ = _anonymize(raw)
        assert fingerprint(raw, SALT, corporate_domains=(CORP,)) == fingerprint(
            anonymized, SALT, corporate_domains=(CORP,)
        )

    def test_different_messages_differ(self) -> None:
        a = _message(from_addr="one@partner.example")
        b = _message(from_addr="two@other.example")
        assert fingerprint(a, SALT) != fingerprint(b, SALT)

    def test_the_fingerprint_does_not_depend_on_the_subject(self) -> None:
        """Тема в основание не входит: иначе замена адреса в теме меняла бы отпечаток."""
        a = _message(subject="Счёт на оплату")
        b = _message(subject="Совсем другая тема")
        assert fingerprint(a, SALT) == fingerprint(b, SALT)

    def test_the_fingerprint_reveals_nothing(self) -> None:
        raw = _message(from_addr="ivan.petrov@partner.example")
        value = fingerprint(raw, SALT)
        assert re.fullmatch(r"[0-9a-f]{32}", value)
        assert "petrov" not in value
        assert "partner" not in value

    def test_a_different_salt_gives_a_different_fingerprint(self) -> None:
        """Смена соли делает прежние псевдонимы несопоставимыми — это используется при экспорте."""
        raw = _message()
        assert fingerprint(raw, SALT) != fingerprint(raw, b"another-salt")


class TestTheSaltIsRequired:
    def test_an_empty_salt_is_refused(self) -> None:
        with pytest.raises(ValueError, match="соль"):
            Anonymizer(b"")
