"""Узел проверяет содержимое пакета сам (ТЗ 1.1 §39, §62, §64).

Находка при проверке на настоящем Postfix: ``postfix check`` не считает ошибкой неизвестный
параметр в main.cf, а контрольная сумма не защищает от подмены — кто может изменить файл, может
пересчитать сумму. Поэтому узел проверяет ``main.cf`` и ``master.cf`` белыми списками, и тесты
здесь идут по тому, что именно можно было бы протащить через ``master.cf``: он определяет, какие
программы Postfix запустит от имени root.
"""

from __future__ import annotations

import pytest
from msp_gateway.bundle import (
    ALLOWED_PIPE_EXECUTABLE,
    BundleError,
    bundle_checksum,
    check_main_cf,
    check_master_cf,
    verify_bundle,
)
from msp_gateway.render import Recipient, render
from msp_gateway.spec import GatewaySpec, InternalListener, Outbound, OutboundMode, RelayDomain, Route, Target


def spec() -> GatewaySpec:
    return GatewaySpec(
        hostname="gw.lab.example",
        relay_domains=(RelayDomain(domain="corp.example", route="exchange"),),
        routes=(Route(name="exchange", targets=(Target(host="ex1", port=2526),)),),
        internal=InternalListener(trusted_networks=("10.0.0.0/8",)),
        outbound=Outbound(mode=OutboundMode.SINK, host="sink", port=2527),
    )


class TestWhatTheGeneratorProducesPassesTheNodeCheck:
    """Если бы эти проверки были строже генератора, узел отвергал бы собственные пакеты."""

    def test_main_cf(self) -> None:
        check_main_cf(render(spec()).files["main.cf"].decode())

    def test_master_cf(self) -> None:
        check_master_cf(render(spec()).files["master.cf"].decode())

    def test_a_whole_bundle_verifies(self) -> None:
        config = render(spec(), [Recipient("ivan@corp.example")])
        assert verify_bundle(config.files, config.manifest) == config.checksum

    def test_a_bundle_with_domains_but_no_recipients_is_refused(self) -> None:
        """Пустой справочник при настроенных доменах отверг бы всю почту: узел такое не применяет."""
        config = render(spec())
        with pytest.raises(BundleError, match="справочник"):
            verify_bundle(config.files, config.manifest)

    def test_the_emptiness_check_cannot_be_bypassed_by_recomputing_the_checksum(self) -> None:
        config = render(spec(), [Recipient("ivan@corp.example")])
        files = {**config.files, "relay_recipients": b"  "}
        manifest = {**config.manifest, "checksum": bundle_checksum(files)}
        with pytest.raises(BundleError, match="справочник"):
            verify_bundle(files, manifest)


class TestMainCf:
    @pytest.mark.parametrize(
        "line",
        [
            "this_is_not_a_postfix_parameter = 1",
            "mynetworks_style = host",
            "smtpd_milters = inet:evil:1234",
            "content_filter = smtp:evil:25",
            "always_bcc = spy@evil.example",
            "recipient_bcc_maps = hash:/tmp/x",
            "sender_bcc_maps = hash:/tmp/x",
            "forward_path = /tmp/x",
            "command_directory = /tmp/evil",
            "daemon_directory = /tmp/evil",
            "mail_owner = root",
            "setgid_group = root",
        ],
    )
    def test_a_parameter_outside_the_whitelist_is_refused(self, line: str) -> None:
        """Каждый из этих параметров — способ украсть почту или запустить чужой код."""
        with pytest.raises(BundleError):
            check_main_cf(f"myhostname = gw.lab.example\n{line}\n")

    @pytest.mark.parametrize(
        "body",
        ["myhostname = a\r\nrelay_domains = x\n", "myhostname = a\x00\n", "not a directive\n", "= value\n"],
    )
    def test_a_malformed_or_control_character_line_is_refused(self, body: str) -> None:
        with pytest.raises(BundleError):
            check_main_cf(body)

    def test_a_continuation_line_is_not_a_way_to_hide_a_directive(self) -> None:
        """В main.cf строка с отступом продолжает предыдущую; здесь она — не «параметр = значение»."""
        with pytest.raises(BundleError):
            check_main_cf("myhostname = a\n    content_filter = smtp:evil:25\n")

    def test_comments_and_blank_lines_are_fine(self) -> None:
        check_main_cf("# комментарий\n\nmyhostname = a\n")

    def test_an_empty_value_is_legal(self) -> None:
        """mydestination = — законная строка: локальной доставки нет совсем."""
        check_main_cf("mydestination =\n")


class TestMasterCf:
    BASE = "smtp inet n - n - - smtpd\n"

    @pytest.mark.parametrize(
        "service",
        [
            "evil unix - n n - - /bin/sh",
            "evil unix - n n - - spawn",
            "evil unix - n n - - local",
            "evil unix - n n - - virtual",
            "evil unix - n n - - lmtp",
            "evil unix - n n - - postkick",
            "evil unix - n n - - sendmail",
        ],
    )
    def test_a_command_outside_the_whitelist_is_refused(self, service: str) -> None:
        """master.cf определяет, какие программы Postfix запустит от имени root."""
        with pytest.raises(BundleError):
            check_master_cf(self.BASE + service + "\n")

    @pytest.mark.parametrize(
        "option",
        [
            "-o content_filter=smtp:evil:25",
            "-o smtpd_milters=inet:evil:1,inet:other:2",
            "-o smtpd_milters=inet:ev il:1",
            "-o milter_macro_daemon_name=ot her",
            "-o mail_owner=root",
            "-o recipient_bcc_maps=hash:/x",
            "-o smtpd_sasl_auth_enable=yes",
            "-o relay_domains=*",
        ],
    )
    def test_an_option_outside_the_whitelist_is_refused(self, option: str) -> None:
        with pytest.raises(BundleError):
            check_master_cf(f"{self.BASE}  {option}\n")

    def test_an_inline_option_is_checked_too(self) -> None:
        with pytest.raises(BundleError):
            check_master_cf("smtp inet n - n - - smtpd -o content_filter=smtp:evil:25\n")

    def test_an_inline_argument_that_is_not_an_option_is_refused(self) -> None:
        with pytest.raises(BundleError):
            check_master_cf("smtp inet n - n - - smtpd -v\n")

    @pytest.mark.parametrize(
        "argv",
        ["argv=/bin/sh -c id", "argv=/usr/bin/python3 -c x", "argv=/usr/local/bin/other-binary", "argv="],
    )
    def test_a_pipe_may_run_only_the_journal_writer(self, argv: str) -> None:
        """Транспорт pipe — это запуск произвольной программы над каждым письмом."""
        body = f"{self.BASE}msp-journal unix - n n - 10 pipe\n  flags=R user=mspjournal\n  {argv}\n"
        with pytest.raises(BundleError):
            check_master_cf(body)

    def test_the_journal_writer_itself_is_allowed(self) -> None:
        body = (
            f"{self.BASE}msp-journal unix - n n - 10 pipe\n  flags=R user=mspjournal\n"
            f"  argv={ALLOWED_PIPE_EXECUTABLE} ${{queue_id}}\n"
        )
        check_master_cf(body)

    @pytest.mark.parametrize("user", ["root", "postfix", "nobody"])
    def test_a_pipe_may_not_run_as_anyone_but_the_journal_user(self, user: str) -> None:
        """Писатель выполняет код над письмом; у него не должно быть прав на очередь."""
        head = f"{self.BASE}msp-journal unix - n n - 10 pipe\n"
        body = f"{head}  flags=R user={user}\n  argv={ALLOWED_PIPE_EXECUTABLE}\n"
        with pytest.raises(BundleError):
            check_master_cf(body)

    @pytest.mark.parametrize("flags", ["flags=F", "flags=DRhu", "flags=Xq"])
    def test_pipe_flags_that_change_the_message_are_refused(self, flags: str) -> None:
        head = f"{self.BASE}msp-journal unix - n n - 10 pipe\n"
        body = f"{head}  {flags} user=mspjournal\n  argv={ALLOWED_PIPE_EXECUTABLE}\n"
        with pytest.raises(BundleError):
            check_master_cf(body)

    @pytest.mark.parametrize("line", ["too short", "smtp weird n - n - - smtpd", "25 inet n - n - smtpd"])
    def test_a_malformed_service_line_is_refused(self, line: str) -> None:
        with pytest.raises(BundleError):
            check_master_cf(line + "\n")

    def test_an_unknown_continuation_line_is_refused(self) -> None:
        with pytest.raises(BundleError):
            check_master_cf(f"{self.BASE}  something=else\n")

    def test_control_characters_are_refused(self) -> None:
        with pytest.raises(BundleError):
            check_master_cf("smtp inet n - n - - smtpd\r\n")


class TestTheNodeDoesNotTrustTheChecksum:
    """Кто может изменить файл, может пересчитать сумму."""

    def test_a_bundle_with_a_recomputed_checksum_and_an_evil_parameter_is_refused(self) -> None:
        config = render(spec())
        files = dict(config.files)
        files["main.cf"] = files["main.cf"] + b"content_filter = smtp:evil.example:25\n"
        manifest = dict(config.manifest)
        manifest["checksum"] = bundle_checksum(files)
        with pytest.raises(BundleError):
            verify_bundle(files, manifest)

    def test_a_bundle_with_an_evil_service_and_a_recomputed_checksum_is_refused(self) -> None:
        config = render(spec())
        files = dict(config.files)
        files["master.cf"] = files["master.cf"] + b"evil unix - n n - - spawn\n"
        manifest = dict(config.manifest)
        manifest["checksum"] = bundle_checksum(files)
        with pytest.raises(BundleError):
            verify_bundle(files, manifest)
