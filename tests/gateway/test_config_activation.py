"""Активация, откат и дрейф конфигурации на настоящем Postfix (ТЗ 1.1 §39–§40).

Смысл активации — узел **всегда** остаётся в рабочем состоянии. Поэтому главные проверки здесь
не про то, что хорошая конфигурация применяется (это тривиально), а про то, что плохая не оставляет
узел ни остановленным, ни открытым, и что почта идёт и во время неудачной попытки, и после неё.
"""

from __future__ import annotations

import uuid

import pytest
from msp_gateway import probes

from .harness import LAB_RECIPIENTS, lab_spec, make_message


def mid() -> str:
    return f"act-{uuid.uuid4().hex[:10]}"


def deliver_one(stack) -> str:  # type: ignore[no-untyped-def]
    """Послать письмо и дождаться его в Exchange: доказательство, что транспорт работает."""
    message_id = mid()
    stack.send_external(
        "a@partner.example",
        ["ivan@corp.example"],
        make_message(message_id, "a@partner.example", "ivan@corp.example"),
    )
    assert stack.exchange1.wait_for(f"<{message_id}@lab.example>", timeout=60) is not None, (
        stack.postfix_log()[-1500:]
    )
    return message_id


@pytest.fixture(autouse=True)
def restore_baseline(lab):  # type: ignore[no-untyped-def]
    """Каждый сценарий начинает с эталонной конфигурации и ею заканчивает."""
    yield
    lab.apply(lab_spec(), LAB_RECIPIENTS)


class TestAGoodConfigurationIsActivated:
    def test_a_new_version_becomes_active_and_mail_keeps_flowing(self, clean) -> None:  # type: ignore[no-untyped-def]
        result = clean.apply(lab_spec(hopcount_limit=21))
        assert result["outcome"] == "ACTIVE", result
        deliver_one(clean)

    def test_the_new_value_is_really_in_force(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Не «пакет принят», а «Postfix теперь так настроен»."""
        assert clean.apply(lab_spec(hopcount_limit=17))["outcome"] == "ACTIVE"
        assert (
            "hopcount_limit = 17"
            in clean.exec("postconf -c /var/lib/msp/config/active hopcount_limit").stdout
        )

    def test_a_recipient_added_by_a_new_version_is_accepted_afterwards(self, clean) -> None:  # type: ignore[no-untyped-def]
        from msp_gateway.render import Recipient

        newcomer = "newcomer@corp.example"
        assert (
            probes.smtp_probe(
                "127.0.0.1", clean.ports["GW_PORT_IN"], mail_from="a@partner.example", rcpt_to=newcomer
            ).code
            == 550
        )
        assert clean.apply(lab_spec(), [*LAB_RECIPIENTS, Recipient(newcomer)])["outcome"] == "ACTIVE"
        assert (
            probes.smtp_probe(
                "127.0.0.1", clean.ports["GW_PORT_IN"], mail_from="a@partner.example", rcpt_to=newcomer
            ).state
            is probes.ProbeState.ACCEPTED
        )

    def test_applying_the_same_version_again_is_a_no_op(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.apply(lab_spec(hopcount_limit=19))
        again = clean.apply(lab_spec(hopcount_limit=19))
        # Номер версии растёт, поэтому каталог другой, но смысл тот же: сумма не меняется.
        assert again["outcome"] == "ACTIVE"
        status = clean.node_status()
        assert status["active_checksum"] == status["disk_checksum"]


class TestABrokenConfigurationDoesNotTakeTheNodeDown:
    def test_a_configuration_postfix_rejects_is_refused_and_the_old_one_keeps_serving(self, clean) -> None:  # type: ignore[no-untyped-def]
        before = clean.node_status()["active_version"]
        result = clean.apply_crafted(
            lab_spec(), {"main.cf": lambda text: text + "this_is_not_a_postfix_parameter = 1\n"}
        )
        assert result["outcome"] == "FAILED", result
        # postfix check неизвестный параметр НЕ отвергает, а лишь предупреждает; поймал его белый
        # список узла на этапе сверки. Так на настоящем Postfix выяснилось, что без этой
        # проверки подделанный пакет с пересчитанной суммой применялся.
        assert result["stage"] == "verify", result
        assert "белого списка" in str(result["message"]), result
        assert clean.node_status()["active_version"] == before
        deliver_one(clean)

    def test_a_syntactically_broken_master_cf_is_refused(self, clean) -> None:  # type: ignore[no-untyped-def]
        result = clean.apply_crafted(
            lab_spec(), {"master.cf": lambda text: text.replace("smtpd\n", "smtpd-no-such-daemon\n", 1)}
        )
        assert result["outcome"] == "FAILED", result
        deliver_one(clean)

    def test_a_tampered_bundle_is_refused_before_anything_changes(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Файл изменён, сумма в описании прежняя — это подмена по дороге (§62)."""
        import json

        from msp_gateway.render import render

        clean._bundle_counter += 1
        version = clean._bundle_counter + 1
        config = render(lab_spec(), LAB_RECIPIENTS, version=version)
        directory = clean.workdir / "bundles" / f"t{version}"
        directory.mkdir(parents=True)
        for name, content in config.files.items():
            (directory / name).write_bytes(content)
        (directory / "main.cf").write_bytes(config.files["main.cf"] + b"mynetworks = 0.0.0.0/0\n")
        (directory / "manifest.json").write_text(json.dumps(config.manifest), encoding="utf-8")
        before = clean.node_status()["active_version"]
        out = clean.exec(f"python3 -m msp_gateway.node apply /bundles/t{version}", check=False)
        assert "контрольная сумма" in out.stdout
        assert clean.node_status()["active_version"] == before

    def test_an_open_relay_configuration_is_rolled_back_by_the_health_check(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Главное свойство §39. Конфигурация синтаксически безупречна, сумма верна, Postfix её принимает.
        Она открывает релей — ровно так выглядит ошибка в списке доверенных сетей. Поймать её может
        только проверка поведения после перезагрузки."""
        before = clean.node_status()["active_version"]

        def open_the_public_listener(text: str) -> str:
            head, _, tail = text.partition("2525 inet")
            head = head.replace("-o mynetworks=\n", "-o mynetworks=127.0.0.0/8\n", 1)
            head = head.replace(
                "smtpd_relay_restrictions=reject_unauth_destination",
                "smtpd_relay_restrictions=permit_mynetworks,reject",
                1,
            )
            return head + "2525 inet" + tail

        result = clean.apply_crafted(lab_spec(), {"master.cf": open_the_public_listener})
        assert result["outcome"] == "ROLLED_BACK", result
        assert "принял внешнего получателя" in str(result["message"]), result
        assert clean.node_status()["active_version"] == before, "прежняя версия должна быть возвращена"

        # И шлюз после отката действительно закрыт, а не только так записано.
        assert probes.open_relay_probe(
            "127.0.0.1", clean.ports["GW_PORT_IN"], timeout=15
        ).is_safe_for_relay_test
        deliver_one(clean)

    def test_the_mutation_really_opens_the_relay_so_the_rollback_test_means_something(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Проверка самой проверки: без отката та же конфигурация действительно принимает чужого.

        Иначе предыдущий тест мог бы проходить потому, что мутация ничего не открывает, а откат
        сработал по какой-то другой причине."""
        from msp_gateway.apply import ConfigStore  # noqa: F401 - документирует, чьё поведение проверяем

        def open_the_public_listener(text: str) -> str:
            head, _, tail = text.partition("2525 inet")
            head = head.replace("-o mynetworks=\n", "-o mynetworks=127.0.0.0/8\n", 1)
            head = head.replace(
                "smtpd_relay_restrictions=reject_unauth_destination",
                "smtpd_relay_restrictions=permit_mynetworks,reject",
                1,
            )
            return head + "2525 inet" + tail

        # Применяем в обход проверки здоровья: опция --no-health существует для первой загрузки.
        import json

        from msp_gateway.bundle import bundle_checksum
        from msp_gateway.render import render

        clean._bundle_counter += 1
        version = clean._bundle_counter + 1
        config = render(lab_spec(), LAB_RECIPIENTS, version=version)
        files = dict(config.files)
        files["master.cf"] = open_the_public_listener(files["master.cf"].decode()).encode()
        manifest = dict(config.manifest)
        manifest["checksum"] = bundle_checksum(files)
        directory = clean.workdir / "bundles" / f"m{version}"
        directory.mkdir(parents=True)
        for name, content in files.items():
            (directory / name).write_bytes(content)
        (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        out = clean.exec(f"python3 -m msp_gateway.node apply /bundles/m{version} --no-health", check=False)
        assert '"ACTIVE"' in out.stdout, out.stdout + out.stderr
        # Проба идёт с 127.0.0.1 ВНУТРИ узла: именно этот адрес мутация объявила доверенным.
        # Релей открывается не мгновенно: reload асинхронен, поэтому слушатель сначала дожидаются.
        inside = clean.exec(
            'python3 -c "import json; from msp_gateway.node import _wait_for_greeting; '
            "from msp_gateway.probes import open_relay_probe; _wait_for_greeting('127.0.0.1', 25, 20); "
            "r = open_relay_probe('127.0.0.1', 25); print(json.dumps({'state': r.state.value}))\"",
            check=False,
        )
        assert '"ACCEPTED"' in inside.stdout, "мутация обязана открывать релей, иначе откат проверяет не то"


class TestDrift:
    def test_a_hand_edit_on_the_node_is_visible_as_drift(self, clean) -> None:  # type: ignore[no-untyped-def]
        status = clean.node_status()
        assert status["active_checksum"] == status["disk_checksum"], "до правки узел в синхроне"
        clean.exec("echo 'mynetworks = 10.0.0.0/8' >> /var/lib/msp/config/active/main.cf")
        status = clean.node_status()
        assert status["active_checksum"] != status["disk_checksum"], "правка руками должна быть видна"

    def test_applying_a_clean_bundle_removes_the_drift(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.exec("echo 'mynetworks = 10.0.0.0/8' >> /var/lib/msp/config/active/main.cf")
        assert clean.apply(lab_spec(hopcount_limit=18))["outcome"] == "ACTIVE"
        status = clean.node_status()
        assert status["active_checksum"] == status["disk_checksum"]
