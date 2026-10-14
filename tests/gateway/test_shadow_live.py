"""Теневая копия на настоящем Postfix (ТЗ 1.1 §34, §58, §68.16).

Главное свойство: тень никогда не мешает доставке. Остальное — что копия вообще появляется,
читается сборщиком и недоступна тем, кому не положена.
"""

from __future__ import annotations

import json
import uuid

from .harness import make_message

JOURNAL = "/var/lib/msp/journal"


def new_id() -> str:
    return f"shd-{uuid.uuid4().hex[:10]}"


def send(stack, mid: str, rcpt: str = "ivan@corp.example"):  # type: ignore[no-untyped-def]
    sender = "a@partner.example"
    return stack.send_external(sender, [rcpt], make_message(mid, sender, rcpt))


def collect_once(stack, *extra: str) -> dict[str, int]:  # type: ignore[no-untyped-def]
    args = " ".join(extra)
    out = stack.exec(
        f"setpriv --reuid=mspjournal --regid=mspjournal --clear-groups "
        f"python3 -m msp_gateway.node collector --once {args}"
    ).stdout
    return json.loads(out.strip().splitlines()[-1])


class TestShadowCopy:
    def test_a_copy_is_written_and_collected(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid = new_id()
        assert send(clean, mid) == {}
        clean.wait_until(
            lambda: int(clean.exec(f"ls {JOURNAL}/new | wc -l").stdout.strip() or 0) >= 1,
            what="копия записана",
        )
        stats = collect_once(clean, "--sink-dir /var/lib/msp/journal/sink")
        assert stats["collected"] >= 1
        found = clean.exec(f"grep -l '{mid}' {JOURNAL}/sink/*.eml", check=False).stdout
        assert found.strip(), "письмо должно дойти до приёмника без искажений"

    def test_collector_failure_does_not_touch_delivery(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Приёмник недоступен — почта идёт, копия ждёт."""
        mid = new_id()
        assert send(clean, mid) == {}
        assert clean.exchange1.wait_for(f"<{mid}@lab.example>", timeout=60) is not None
        clean.exec("echo token > /tmp/tok", check=False)
        out = clean.exec(
            "setpriv --reuid=mspjournal --regid=mspjournal --clear-groups "
            "python3 -m msp_gateway.node collector --once --url http://10.77.0.250:9/ingest "
            "--token-file /tmp/tok",
            check=False,
        )
        assert out.returncode == 0
        assert json.loads(out.stdout.strip().splitlines()[-1])["failed"] >= 1
        pending = int(clean.exec(f"ls {JOURNAL}/new | wc -l").stdout.strip() or 0)
        assert pending >= 1, "копия не должна пропасть, пока её не приняли"

    def test_mail_is_delivered_even_if_the_journal_cannot_be_written(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Диск журнала недоступен писателю: копия теряется и считается, почта не страдает (§58)."""
        clean.exec(f"chmod 0500 {JOURNAL}/new")
        try:
            mid = new_id()
            assert send(clean, mid) == {}
            assert clean.exchange1.wait_for(f"<{mid}@lab.example>", timeout=60) is not None
            clean.wait_until(
                lambda: (
                    int(clean.exec(f"stat -c %s {JOURNAL}/.dropped 2>/dev/null || echo 0").stdout.strip())
                    >= 1
                ),
                what="потеря копии посчитана",
            )
            clean.wait_until(lambda: clean.queue_size() == 0, what="очередь пуста: доставка не застряла")
        finally:
            clean.exec(f"chmod 0700 {JOURNAL}/new")

    def test_journal_is_not_readable_by_other_users(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Копии содержат письма целиком; агенту наблюдения и Postfix они недоступны (§62)."""
        for user in ("mspagent", "postfix", "nobody"):
            result = clean.exec(f"ls {JOURNAL}/new", check=False, user=user)
            assert result.returncode != 0, f"{user} видит журнал копий"
