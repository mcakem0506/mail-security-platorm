"""Давление на диск и нагрузка на настоящем Postfix (ТЗ 1.1 §25, §26, §54, §68.10).

Принятая почта важнее новой: при нехватке места шлюз временно отказывает **новым** письмам, а уже принятые
доставляет. Здесь проверяется, что это действительно так, что состояние давления видно в метриках и что
шлюз выдерживает параллельные сессии, письма разных размеров и медленный Exchange, не теряя писем и не
раздувая память.
"""

from __future__ import annotations

import concurrent.futures
import re
import smtplib
import urllib.request
import uuid

import pytest
from msp_gateway.spec import Backpressure, Limits

from .harness import LAB_RECIPIENTS, lab_spec, make_message

TIB = 1024**4


def new_id(prefix: str = "ld") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def full(mid: str) -> str:
    return f"<{mid}@lab.example>"


def scrape(stack) -> str:  # type: ignore[no-untyped-def]
    url = f"http://127.0.0.1:{stack.ports['GW_PORT_METRICS']}/metrics"
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8")


def pressure(stack) -> str | None:  # type: ignore[no-untyped-def]
    for line in scrape(stack).splitlines():
        match = re.match(r'msp_gateway_pressure_state\{state="(\w+)"\} 1$', line)
        if match:
            return match.group(1)
    return None


def send_one(stack, mid: str, size: int = 0) -> int | None:  # type: ignore[no-untyped-def]
    """Код отказа или ``None``, если принято."""
    sender, rcpt = "a@partner.example", "ivan@corp.example"
    try:
        stack.send_external(sender, [rcpt], make_message(mid, sender, rcpt, size=size))
    except smtplib.SMTPResponseException as error:
        return int(error.smtp_code)
    except smtplib.SMTPRecipientsRefused as error:
        return int(next(iter(error.recipients.values()))[0])
    except (smtplib.SMTPException, OSError):
        return -1
    return None


@pytest.fixture(autouse=True)
def restore(lab):  # type: ignore[no-untyped-def]
    yield
    for control in (lab.exchange1, lab.exchange2):
        control.mode("accept")
    lab.apply(lab_spec(), LAB_RECIPIENTS)
    lab.flush()
    lab.wait_until(lambda: lab.queue_size() == 0, timeout=180, what="очередь опустела")


class TestDiskPressure:
    def test_below_the_critical_threshold_new_mail_is_deferred_and_accepted_mail_is_kept(self, clean) -> None:  # type: ignore[no-untyped-def]
        accepted = new_id("held")
        for control in (clean.exchange1, clean.exchange2):
            control.mode("tempfail")
        assert send_one(clean, accepted) is None
        clean.wait_until(lambda: clean.queue_size() >= 1, what="письмо принято и ждёт")

        # Порог «критично» выше любого реального тома: для шлюза это «места нет».
        spec = lab_spec(
            backpressure=Backpressure(disk_pressure_free_bytes=20 * TIB, disk_critical_free_bytes=10 * TIB)
        )
        assert clean.apply(spec, LAB_RECIPIENTS)["outcome"] == "ACTIVE"

        refused = send_one(clean, new_id("new"))
        assert refused is not None and 400 <= refused < 500, f"ожидался временный отказ, получено {refused}"
        assert clean.queue_size() >= 1, "ранее принятое письмо осталось в очереди"

        for control in (clean.exchange1, clean.exchange2):
            control.mode("accept")
        clean.apply(lab_spec(), LAB_RECIPIENTS)
        clean.flush()
        assert clean.exchange1.wait_for(full(accepted), timeout=120) is not None, "принятое письмо доставлено"

    def test_the_state_is_visible_in_the_metrics_and_follows_the_active_configuration(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.wait_until(lambda: pressure(clean) == "NORMAL", timeout=60, what="норма")
        spec = lab_spec(
            backpressure=Backpressure(disk_pressure_free_bytes=20 * TIB, disk_critical_free_bytes=10 * TIB)
        )
        clean.apply(spec, LAB_RECIPIENTS)
        clean.wait_until(
            lambda: pressure(clean) == "CRITICAL", timeout=60, what="критическое давление видно в метриках"
        )
        clean.apply(lab_spec(), LAB_RECIPIENTS)
        clean.wait_until(
            lambda: pressure(clean) == "NORMAL", timeout=60, what="после возврата порогов — норма"
        )

    def test_service_returns_by_itself_when_space_is_back(self, clean) -> None:  # type: ignore[no-untyped-def]
        spec = lab_spec(
            backpressure=Backpressure(disk_pressure_free_bytes=20 * TIB, disk_critical_free_bytes=10 * TIB)
        )
        clean.apply(spec, LAB_RECIPIENTS)
        assert send_one(clean, new_id("tight")) is not None
        clean.apply(lab_spec(), LAB_RECIPIENTS)
        mid = new_id("back")
        assert send_one(clean, mid) is None
        assert clean.exchange1.wait_for(full(mid), timeout=60) is not None


class TestLoad:
    @pytest.fixture(autouse=True)
    def roomy_limits(self, clean):  # type: ignore[no-untyped-def]
        """Лимиты на одного клиента — защита шлюза; нагрузочный источник один, поэтому они подняты."""
        limits = Limits(
            max_connections_per_client=200, connection_rate_limit=100_000, max_message_size=20 * 1024 * 1024
        )
        assert clean.apply(lab_spec(limits=limits), LAB_RECIPIENTS)["outcome"] == "ACTIVE"

    def test_fifty_parallel_sessions_lose_nothing(self, clean) -> None:  # type: ignore[no-untyped-def]
        ids = [new_id() for _ in range(50)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            results = list(pool.map(lambda mid: send_one(clean, mid), ids))
        assert results.count(None) == 50, (
            f"отказы при параллельной нагрузке: {[r for r in results if r is not None]}"
        )
        clean.wait_until(
            lambda: all(
                full(mid) in set(clean.exchange1.message_ids()) | set(clean.exchange2.message_ids())
                for mid in ids
            ),
            timeout=180,
            what="все 50 писем доставлены",
        )

    @pytest.mark.parametrize("size", [10 * 1024, 1024 * 1024, 10 * 1024 * 1024], ids=["10KB", "1MB", "10MB"])
    def test_messages_of_different_sizes_arrive_intact(self, clean, size: int) -> None:  # type: ignore[no-untyped-def]
        mid = new_id("size")
        assert send_one(clean, mid, size=size) is None
        received = clean.exchange1.wait_for(full(mid), timeout=120)
        assert received is not None
        assert int(received["size"]) >= size

    def test_a_slow_downstream_does_not_stop_acceptance(self, clean) -> None:  # type: ignore[no-untyped-def]
        for control in (clean.exchange1, clean.exchange2):
            control.mode("delay", delay=4)
        ids = [new_id("slow") for _ in range(20)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(lambda mid: send_one(clean, mid), ids))
        assert results.count(None) == 20, "приём не зависит от скорости Exchange"
        clean.wait_until(
            lambda: all(
                full(mid) in set(clean.exchange1.message_ids()) | set(clean.exchange2.message_ids())
                for mid in ids
            ),
            timeout=240,
            what="все письма доставлены, хотя Exchange отвечал медленно",
        )

    def test_a_burst_is_counted_exactly_and_memory_stays_bounded(self, clean) -> None:  # type: ignore[no-untyped-def]
        before = scrape(clean)
        ids = [new_id("burst") for _ in range(200)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(lambda mid: send_one(clean, mid), ids))
        assert results.count(None) == 200
        clean.wait_until(
            lambda: len(set(ids_in(clean)) & {full(m) for m in ids}) == 200,
            timeout=240,
            what="все 200 доставлены",
        )

        def counter(text: str) -> float:
            total = 0.0
            for line in text.splitlines():
                if line.startswith("msp_gateway_messages_received_total{"):
                    total += float(line.rsplit(" ", 1)[1])
            return total

        clean.wait_until(
            lambda: counter(scrape(clean)) - counter(before) >= 200,
            timeout=60,
            what="метрика приёма учла всю пачку",
        )
        assert counter(scrape(clean)) - counter(before) == 200, "счёт точный: ни больше, ни меньше"
        rss = container_memory_mib(clean)
        assert rss < 600, f"память контейнера {rss} МиБ после пачки в 200 писем"


def ids_in(stack) -> list[str]:  # type: ignore[no-untyped-def]
    return stack.exchange1.message_ids() + stack.exchange2.message_ids()


def container_memory_mib(stack) -> float:  # type: ignore[no-untyped-def]
    from .harness import docker

    out = docker("stats", "--no-stream", "--format", "{{.MemUsage}}", stack.gateway).stdout.strip()
    used = out.split("/")[0].strip()
    number = float(re.sub(r"[^0-9.]", "", used))
    return number * 1024 if "GiB" in used else number if "MiB" in used else number / 1024
