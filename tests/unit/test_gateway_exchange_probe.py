"""Проба Exchange по уровням (ТЗ 1.1 §48): NETWORK, TLS, SMTP, DELIVERY — без отправки письма.

Сервер — настоящий SMTP (aiosmtpd) с настоящим TLS. Проба идёт через те же проверки сертификата,
что и доставка в Postfix, поэтому просроченный сертификат, чужое имя и неизвестный центр
сертификации видны в пробе так же, как их увидит шлюз.
"""

from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path

import pytest
from aiosmtpd.controller import Controller
from gateway.harness import Authority
from msp_gateway.probes import LAYERS, exchange_probe


class Handler:
    def __init__(self, reject_rcpt: bool = False) -> None:
        self.reject_rcpt = reject_rcpt
        self.data_received = 0

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):  # type: ignore[no-untyped-def]
        if self.reject_rcpt:
            return "550 5.1.1 No such user"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):  # type: ignore[no-untyped-def]
        self.data_received += 1
        return "250 OK"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Server:
    def __init__(
        self,
        tmp_path: Path,
        *,
        authority: Authority,
        days: int = 30,
        names=None,
        tls: bool = True,
        reject=False,
        port: int | None = None,
    ):  # type: ignore[no-untyped-def]
        self.handler = Handler(reject_rcpt=reject)
        context = None
        if tls:
            authority.issue(
                tmp_path,
                "srv",
                names or ["exchange.lab.example"],
                days=days,
                valid_from_days_ago=max(1, 5 - days) if days < 0 else 1,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(tmp_path / "srv.crt", tmp_path / "srv.key")
        self.port = port or free_port()
        self.controller = Controller(
            self.handler,
            hostname="127.0.0.1",
            port=self.port,
            tls_context=context,
            require_starttls=tls,
        )

    def __enter__(self) -> Server:
        self.controller.start()
        return self

    def __exit__(self, *_a: object) -> None:
        self.controller.stop()


@pytest.fixture
def authority(tmp_path: Path) -> Authority:
    auth = Authority.create()
    auth.write_ca(tmp_path / "ca.crt")
    return auth


def probe(server: Server, tmp_path: Path, **kw):  # type: ignore[no-untyped-def]
    kw.setdefault("ca_file", str(tmp_path / "ca.crt"))
    kw.setdefault("server_hostname", "exchange.lab.example")
    kw.setdefault("timeout", 10.0)
    return exchange_probe("127.0.0.1", server.port, **kw)


def states(result) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return {layer.layer: layer.state for layer in result.layers}


class TestHealthy:
    def test_all_layers_pass_with_a_probe_recipient(self, tmp_path: Path, authority: Authority) -> None:
        with Server(tmp_path, authority=authority) as server:
            result = probe(server, tmp_path, probe_recipient="probe@corp.example")
        assert states(result) == {"NETWORK": "OK", "TLS": "OK", "SMTP": "OK", "DELIVERY": "OK"}
        assert result.healthy is True
        assert result.failed_layer == ""

    def test_delivery_is_skipped_without_a_probe_recipient_not_reported_as_passed(
        self, tmp_path: Path, authority: Authority
    ) -> None:
        with Server(tmp_path, authority=authority) as server:
            result = probe(server, tmp_path)
        assert states(result)["DELIVERY"] == "SKIPPED"
        assert result.healthy is True

    def test_no_message_is_ever_created(self, tmp_path: Path, authority: Authority) -> None:
        """Проба закрывает сессию до DATA: у получателя не появляется ни одного письма."""
        with Server(tmp_path, authority=authority) as server:
            probe(server, tmp_path, probe_recipient="probe@corp.example")
            probe(server, tmp_path, probe_recipient="probe@corp.example")
            assert server.handler.data_received == 0

    def test_layers_come_in_the_documented_order(self, tmp_path: Path, authority: Authority) -> None:
        with Server(tmp_path, authority=authority) as server:
            result = probe(server, tmp_path)
        assert tuple(layer.layer for layer in result.layers) == LAYERS


class TestTlsFailuresAreNamedAndStopTheProbe:
    def failed(self, result) -> dict[str, str]:  # type: ignore[no-untyped-def]
        return states(result)

    def test_an_expired_certificate(self, tmp_path: Path, authority: Authority) -> None:
        with Server(tmp_path, authority=authority, days=-2) as server:
            result = probe(server, tmp_path)
        assert self.failed(result) == {
            "NETWORK": "OK",
            "TLS": "FAILED",
            "SMTP": "SKIPPED",
            "DELIVERY": "SKIPPED",
        }
        assert "expired" in result.layers[1].detail
        assert result.healthy is False
        assert result.failed_layer == "TLS"

    def test_a_certificate_for_another_hostname(self, tmp_path: Path, authority: Authority) -> None:
        with Server(tmp_path, authority=authority, names=["somebody-else.example"]) as server:
            result = probe(server, tmp_path)
        assert result.failed_layer == "TLS"
        assert "SMTP" in states(result) and states(result)["SMTP"] == "SKIPPED"

    def test_an_unknown_authority(self, tmp_path: Path) -> None:
        stranger = Authority.create("Чужой центр сертификации")
        trusted = Authority.create()
        trusted.write_ca(tmp_path / "ca.crt")
        with Server(tmp_path, authority=stranger) as server:
            result = probe(server, tmp_path)
        assert result.failed_layer == "TLS"

    def test_tls_not_offered_when_it_is_required(self, tmp_path: Path, authority: Authority) -> None:
        with Server(tmp_path, authority=authority, tls=False) as server:
            result = probe(server, tmp_path, require_tls=True)
        assert result.failed_layer == "TLS"
        assert "STARTTLS" in result.layers[1].detail

    def test_tls_not_offered_and_not_required_is_skipped_not_passed(
        self, tmp_path: Path, authority: Authority
    ) -> None:
        with Server(tmp_path, authority=authority, tls=False) as server:
            result = probe(server, tmp_path, require_tls=False)
        assert states(result)["TLS"] == "SKIPPED"
        assert states(result)["SMTP"] == "OK"


class TestProbeIsNotStricterThanPostfix:
    def test_x509_strict_is_off_but_verification_is_on(self) -> None:
        from msp_gateway.probes import probe_tls_context

        context = probe_tls_context(None)
        assert not context.verify_flags & ssl.VERIFY_X509_STRICT
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    def test_a_certificate_without_authority_key_identifier_is_accepted(
        self, tmp_path: Path, authority: Authority
    ) -> None:
        """Сертификаты стенда выпущены без AKI; Postfix их принимает, и проба обязана принимать."""
        with Server(tmp_path, authority=authority) as server:
            result = probe(server, tmp_path)
        assert result.layers[1].state == "OK"


class TestOtherFailures:
    def test_nothing_is_listening(self, tmp_path: Path) -> None:
        result = exchange_probe("127.0.0.1", free_port(), timeout=2.0)
        assert states(result) == {
            "NETWORK": "FAILED",
            "TLS": "SKIPPED",
            "SMTP": "SKIPPED",
            "DELIVERY": "SKIPPED",
        }
        assert result.healthy is False

    def test_a_silent_server_times_out(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        accepted: list[socket.socket] = []
        threading.Thread(target=lambda: accepted.append(listener.accept()[0]), daemon=True).start()
        try:
            result = exchange_probe("127.0.0.1", port, timeout=1.0)
        finally:
            listener.close()
            for conn in accepted:
                conn.close()
        assert result.failed_layer == "NETWORK"

    def test_the_probe_recipient_being_refused_is_a_delivery_failure(
        self, tmp_path: Path, authority: Authority
    ) -> None:
        with Server(tmp_path, authority=authority, reject=True) as server:
            result = probe(server, tmp_path, probe_recipient="nobody@corp.example")
        assert states(result) == {"NETWORK": "OK", "TLS": "OK", "SMTP": "OK", "DELIVERY": "FAILED"}
        assert "550" in result.layers[3].detail

    def test_details_never_contain_the_probe_address(self, tmp_path: Path, authority: Authority) -> None:
        with Server(tmp_path, authority=authority, reject=True) as server:
            result = probe(server, tmp_path, probe_recipient="secret.person@corp.example")
        assert all("secret.person" not in layer.detail for layer in result.layers)
