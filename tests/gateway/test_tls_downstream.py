"""TLS к Exchange (ТЗ 1.1 §10, §52, §68.8): недоверенное соединение не используется для доставки.

Шлюз настроен на проверку сертификата (профиль REQUIRED). Если проверка не проходит, письмо не
должно уйти «хотя бы так» по открытому или недоверенному каналу: оно остаётся в очереди и
ждёт, пока канал не починят. Принято оно при этом всё равно — Exchange недоступен для
доставки, но не причина отказывать отправителю.
"""

from __future__ import annotations

import uuid

import pytest

from .harness import Authority, make_message


def new_id() -> str:
    return f"tls-{uuid.uuid4().hex[:10]}"


def send(stack, mid: str):  # type: ignore[no-untyped-def]
    sender, rcpt = "a@partner.example", "ivan@corp.example"
    return stack.send_external(sender, [rcpt], make_message(mid, sender, rcpt))


def full_id(mid: str) -> str:
    return f"<{mid}@lab.example>"


@pytest.fixture(autouse=True)
def restore(lab):  # type: ignore[no-untyped-def]
    yield
    lab.reissue_exchange_certificate()
    lab.flush()
    lab.wait_until(lambda: lab.queue_size() == 0, timeout=120, what="очередь опустела")


def broken_channel_keeps_the_mail(stack, mid: str, reason_fragments: tuple[str, ...]) -> None:  # type: ignore[no-untyped-def]
    assert send(stack, mid) == {}, "приём письма не зависит от состояния канала к Exchange"
    stack.wait_until(lambda: stack.queue_size() >= 1, what="письмо в очереди")
    stack.wait_until(
        lambda: any(f in stack.postfix_log().lower() for f in reason_fragments),
        timeout=60,
        what="в журнале причина отказа TLS",
    )
    assert stack.exchange1.message_ids().count(full_id(mid)) == 0
    assert stack.exchange2.message_ids().count(full_id(mid)) == 0, "по недоверенному каналу письмо не уходит"


class TestUntrustedDownstream:
    def test_an_expired_certificate_blocks_delivery_until_it_is_replaced(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.reissue_exchange_certificate(days=-2)
        mid = new_id()
        broken_channel_keeps_the_mail(clean, mid, ("expired", "not verified", "verification failed"))
        clean.reissue_exchange_certificate()
        clean.flush()
        assert clean.exchange1.wait_for(full_id(mid), timeout=90) is not None

    def test_a_certificate_for_another_hostname_is_not_accepted(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.reissue_exchange_certificate(dns_names=["somebody-else.example"])
        mid = new_id()
        broken_channel_keeps_the_mail(clean, mid, ("host name", "hostname", "not verified", "mismatch"))
        clean.reissue_exchange_certificate()
        clean.flush()
        assert clean.exchange1.wait_for(full_id(mid), timeout=90) is not None

    def test_a_certificate_from_an_unknown_authority_is_not_accepted(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.reissue_exchange_certificate(authority=Authority.create("Чужой центр сертификации"))
        mid = new_id()
        broken_channel_keeps_the_mail(clean, mid, ("untrusted", "unable to get", "not verified", "self"))
        clean.reissue_exchange_certificate()
        clean.flush()
        assert clean.exchange1.wait_for(full_id(mid), timeout=90) is not None

    def test_nothing_is_sent_in_the_clear_when_verification_fails(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Двойник считает сессии: ни одна из них не должна быть открытой."""
        clean.reissue_exchange_certificate(days=-2)  # перезапуск обнуляет счётчики двойника
        mid = new_id()
        send(clean, mid)
        clean.wait_until(lambda: clean.queue_size() >= 1, what="письмо в очереди")
        clean.wait_until(
            lambda: "expired" in clean.postfix_log().lower() or "not verified" in clean.postfix_log().lower(),
            timeout=60,
            what="попытка доставки и отказ проверки",
        )
        assert clean.exchange1.state()["plain_sessions"] == 0
        assert clean.exchange1.message_ids().count(full_id(mid)) == 0


class TestRecovery:
    def test_delivery_resumes_by_itself_once_the_channel_is_good_again(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.reissue_exchange_certificate(days=-2)
        mid = new_id()
        send(clean, mid)
        clean.wait_until(lambda: clean.queue_size() >= 1, what="письмо в очереди")
        clean.reissue_exchange_certificate()
        clean.flush()
        assert clean.exchange1.wait_for(full_id(mid), timeout=90) is not None
        clean.wait_until(lambda: clean.queue_size() == 0, what="очередь опустела")
