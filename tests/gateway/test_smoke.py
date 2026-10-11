"""Дымовая проверка стенда: Postfix запущен, письмо проходит от источника до получателя."""

from __future__ import annotations

import uuid

from .harness import make_message


def test_postfix_is_running_with_the_generated_config(lab) -> None:  # type: ignore[no-untyped-def]
    status = lab.exec("postfix status 2>&1", check=False)
    assert status.returncode == 0, status.stdout + status.stderr
    node = lab.exec("python3 -m msp_gateway.node status")
    assert '"active_version"' in node.stdout


def test_a_valid_recipient_is_delivered_to_exchange(clean) -> None:  # type: ignore[no-untyped-def]
    message_id = f"smoke-{uuid.uuid4().hex[:10]}"
    refused = clean.send_external(
        "sender@partner.example",
        ["ivan@corp.example"],
        make_message(message_id, "sender@partner.example", "ivan@corp.example"),
    )
    assert refused == {}
    delivered = clean.exchange1.wait_for(f"<{message_id}@lab.example>", timeout=60)
    assert delivered is not None, clean.postfix_log()[-2000:]
    assert delivered["tls"] is True, "доставка в Exchange обязана идти по TLS"
