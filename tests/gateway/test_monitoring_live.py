"""Пробы, сертификаты, дрейф и сборщик в агенте на настоящем Postfix (ТЗ 1.1 §46–§48, §40, §41).

Юнит-тесты проверяют логику на подставных серверах. Здесь проверяется то, что без контейнера
не видно: агент, работающий от непривилегированного пользователя, действительно доходит до
Exchange с проверкой сертификата, видит свой публичный слушатель и читает файлы там, где ему
положено, и не читает там, где не положено.
"""

from __future__ import annotations

import re
import urllib.request
import uuid

import pytest

from .harness import LAB_RECIPIENTS, lab_spec, make_message


def scrape(stack) -> str:  # type: ignore[no-untyped-def]
    url = f"http://127.0.0.1:{stack.ports['GW_PORT_METRICS']}/metrics"
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8")


def value(text: str, name: str, **labels: str) -> float | None:
    pattern = rf"^{re.escape(name)}"
    if labels:
        pattern += r"\{[^}]*\}"
    for line in text.splitlines():
        if re.match(pattern + r" ", line) and all(f'{k}="{v}"' in line for k, v in labels.items()):
            return float(line.rsplit(" ", 1)[1])
    return None


def layers(text: str) -> dict[str, float]:
    result: dict[str, float] = {}
    for line in text.splitlines():
        match = re.match(r'msp_gateway_exchange_probe_ok\{layer="(\w+)",target="([^"]+)"\} (\S+)', line)
        if match:
            result[f"{match[2]}/{match[1]}"] = float(match[3])
    return result


@pytest.fixture(autouse=True)
def restore(lab):  # type: ignore[no-untyped-def]
    yield
    lab.reissue_exchange_certificate()
    lab.apply(lab_spec(), LAB_RECIPIENTS)


class TestProbesInsideTheContainer:
    def test_exchange_is_healthy_on_every_layer_and_nothing_is_sent(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.wait_until(
            lambda: len(layers(scrape(clean))) >= 8 and all(v == 1.0 for v in layers(scrape(clean)).values()),
            timeout=90,
            what="все уровни обоих серверов Exchange прошли",
        )
        found = layers(scrape(clean))
        assert {k.split("/")[1] for k in found} == {"NETWORK", "TLS", "SMTP", "DELIVERY"}
        assert clean.exchange1.message_ids() == [] and clean.exchange2.message_ids() == [], (
            "проба не создаёт писем"
        )

    def test_the_open_relay_self_test_passes_on_a_correct_gateway(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.wait_until(
            lambda: value(scrape(clean), "msp_gateway_open_relay_selftest_ok") == 1.0,
            timeout=90,
            what="самопроверка открытого релея: отказ",
        )

    def test_an_expired_exchange_certificate_is_seen_as_a_tls_failure_with_later_layers_absent(
        self, clean
    ) -> None:  # type: ignore[no-untyped-def]
        clean.reissue_exchange_certificate(days=-2)

        def tls_down() -> bool:
            found = layers(scrape(clean))
            return found.get("fake-exchange:2526/TLS") == 0.0

        clean.wait_until(tls_down, timeout=90, what="уровень TLS упал")
        found = layers(scrape(clean))
        assert found["fake-exchange:2526/NETWORK"] == 1.0
        assert "fake-exchange:2526/SMTP" not in found, "непроверенный уровень не должен быть зелёным"
        clean.reissue_exchange_certificate()
        clean.wait_until(
            lambda: layers(scrape(clean)).get("fake-exchange:2526/SMTP") == 1.0,
            timeout=90,
            what="Exchange восстановлен",
        )

    def test_the_gateway_certificate_expiry_is_reported_without_reading_the_key(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.wait_until(
            lambda: (
                (value(scrape(clean), "msp_gateway_certificate_expiry_seconds", usage="smtp-public") or 0) > 0
            ),
            timeout=90,
            what="срок сертификата виден",
        )
        left = value(scrape(clean), "msp_gateway_certificate_expiry_seconds", usage="smtp-public")
        assert left is not None and 20 * 86400 < left < 31 * 86400

    def test_the_tls_certificate_event_has_no_key_material(self, clean) -> None:  # type: ignore[no-untyped-def]
        outbox = clean.exec("cat /var/lib/msp/agent/outbox.jsonl", check=False).stdout
        assert "PRIVATE KEY" not in outbox
        assert "BEGIN" not in outbox


class TestConfigDrift:
    def test_a_hand_edit_of_the_active_config_is_seen_and_a_new_version_clears_it(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.wait_until(
            lambda: value(scrape(clean), "msp_gateway_config_drift") == 0.0, timeout=60, what="дрейфа нет"
        )
        clean.exec("echo '# edited by hand' >> /var/lib/msp/config/active/relay_domains")
        clean.wait_until(
            lambda: value(scrape(clean), "msp_gateway_config_drift") == 1.0, timeout=60, what="дрейф виден"
        )
        assert clean.apply(lab_spec(), LAB_RECIPIENTS)["outcome"] == "ACTIVE"
        clean.wait_until(
            lambda: value(scrape(clean), "msp_gateway_config_drift") == 0.0, timeout=60, what="дрейф снят"
        )


class TestShadowCollectorReport:
    def test_the_agent_sees_the_collector_without_seeing_the_journal(self, clean) -> None:  # type: ignore[no-untyped-def]
        sender, rcpt = "a@partner.example", "ivan@corp.example"
        mid = f"mon-{uuid.uuid4().hex[:10]}"
        clean.send_external(sender, [rcpt], make_message(mid, sender, rcpt))
        clean.exec(
            "setpriv --reuid=mspjournal --regid=mspjournal --clear-groups "
            "python3 -m msp_gateway.node collector --once --sink-dir /var/lib/msp/journal/sink"
        )
        clean.wait_until(
            lambda: value(scrape(clean), "msp_gateway_shadow_collector_report_age_seconds") is not None,
            timeout=60,
            what="отчёт сборщика виден агенту",
        )
        assert value(scrape(clean), "msp_gateway_shadow_pending_seconds") == 0.0
        listing = clean.exec("ls /var/lib/msp/journal", check=False, user="mspagent")
        assert listing.returncode != 0, "журнал для агента закрыт, отчёт лежит отдельно"
