"""Стенд MSP 1.2: настоящий Postfix + настоящий Rspamd + управляемый DNS (ТЗ 1.2 §37, §40).

Над стендом шлюза MSP 1.1 добавлены сканер, Redis и DNS, в котором тест сам задаёт записи SPF,
DKIM, DMARC, PTR и «чёрных списков». Реальных DNSBL и чужих зон нет, поэтому проверки не
зависят от Интернета, а сбои DNS воспроизводятся командой.
"""

from __future__ import annotations

import base64
import json
import textwrap
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from msp_antispam.rspamd_config import DkimSigning, RspamdNodeConfig, SigningDomain, Thresholds
from msp_gateway.spec import Milter

from tests.gateway.harness import (
    COMPOSE,
    LAB_RECIPIENTS,
    REPO,
    TRUSTED_CLIENT_IP,
    TRUSTED_NETWORK,
    UNTRUSTED_CLIENT_IP,
    Stack,
    _free_port,
    docker,
    lab_spec,
)

SPAM_COMPOSE = REPO / "deployment" / "spam" / "compose.yml"
DNS_IP = "10.77.0.51"
REDIS_IP = "10.77.0.52"
RSPAMD_IP = "10.77.0.50"

#: Адреса «внешних серверов» в сети стенда. Не доверенная подсеть (10.77.0.64/26).
SENDER_IP = "10.77.0.150"
OTHER_IP = "10.77.0.151"


def milter_spec(**overrides: object):  # type: ignore[no-untyped-def]
    overrides.setdefault(
        "milter",
        Milter(
            enabled=True, inbound_socket=f"inet:{RSPAMD_IP}:11332", outbound_socket=f"inet:{RSPAMD_IP}:11333"
        ),
    )
    return lab_spec(**overrides)


def node_config(**overrides: object) -> RspamdNodeConfig:
    base: dict[str, object] = {
        "authserv_id": "gw.lab.example",
        "nameservers": (DNS_IP,),
        "redis": {"host": REDIS_IP, "port": 6379},
        "thresholds": Thresholds(),
        "local_networks": (TRUSTED_NETWORK,),
        "hyperscan": False,
    }
    base.update(overrides)
    return RspamdNodeConfig(**base)  # type: ignore[arg-type]


class Dns:
    """Управление DNS стенда по HTTP."""

    def __init__(self, port: int) -> None:
        self.base = f"http://127.0.0.1:{port}"

    def _send(self, method: str, path: str, payload: object | None = None) -> object:
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read())

    def records(self, records: dict[str, dict[str, object]]) -> None:
        self._send("PUT", "/records", records)

    def faults(self, **faults: object) -> None:
        self._send("PUT", "/faults", faults)

    def reset(self) -> None:
        self._send("POST", "/reset", {})

    def queries(self) -> list[dict[str, object]]:
        return list(self._send("GET", "/queries"))  # type: ignore[call-overload]


@dataclass
class DkimKey:
    domain: str
    selector: str
    private_pem: bytes
    public_b64: str

    @classmethod
    def generate(cls, domain: str, selector: str = "s1", *, bits: int = 2048) -> DkimKey:
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        private = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        public = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return cls(domain, selector, private, base64.b64encode(public).decode())

    @property
    def dns_name(self) -> str:
        return f"{self.selector}._domainkey.{self.domain}"

    @property
    def dns_record(self) -> dict[str, list[str]]:
        return {"TXT": [f"v=DKIM1; k=rsa; p={self.public_b64}"]}

    def sign(
        self,
        raw: bytes,
        headers: tuple[bytes, ...] = (b"from", b"to", b"subject", b"message-id", b"date"),
        *,
        algorithm: bytes = b"rsa-sha256",
        domain: str | None = None,
        selector: str | None = None,
    ) -> bytes:
        signature = dkim.sign(
            raw,
            (selector or self.selector).encode(),
            (domain or self.domain).encode(),
            self.private_pem,
            include_headers=list(headers),
            signature_algorithm=algorithm,
        )
        return signature + raw


def build_message(
    message_id: str,
    mail_from: str,
    rcpt: str = "ivan@corp.example",
    *,
    subject: str = "Тест",
    body: str = "Содержимое письма для проверки.",
    extra_headers: str = "",
    from_header: str | None = None,
) -> bytes:
    text = (
        f"From: {from_header or mail_from}\r\nTo: {rcpt}\r\nSubject: {subject}\r\n"
        f"Message-ID: <{message_id}@sender.example>\r\nDate: Mon, 12 Oct 2026 10:00:00 +0000\r\n"
        f"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n{extra_headers}\r\n{body}\r\n"
    )
    return text.encode("utf-8")


class SpamStack(Stack):
    compose_files = (COMPOSE, SPAM_COMPOSE)
    compose_profiles = ("gateway-test", "spam-security-test")

    def __init__(self, workdir: Path, **kwargs: object) -> None:
        super().__init__(workdir, **kwargs)  # type: ignore[arg-type]
        self.ports["SPAM_DNS_CONTROL"] = _free_port()
        (workdir / "rspamd-bootstrap").mkdir(parents=True, exist_ok=True)
        (workdir / "secrets" / "rspamd").mkdir(parents=True, exist_ok=True)
        self.node_cfg = node_config()

    @property
    def dns(self) -> Dns:
        return Dns(self.ports["SPAM_DNS_CONTROL"])

    @property
    def rspamd_container(self) -> str:
        return self.container("rspamd")

    def write_rspamd(self, cfg: RspamdNodeConfig | None = None) -> None:
        self.node_cfg = cfg or self.node_cfg
        (self.workdir / "rspamd-bootstrap" / "rspamd.json").write_text(
            self.node_cfg.model_dump_json(), encoding="utf-8"
        )
        secrets = self.workdir / "secrets" / "rspamd"
        secrets.mkdir(parents=True, exist_ok=True)
        # Пароль контроллера: хэш создаётся при развёртывании; для стенда — фиксированный.
        (secrets / "controller.inc").write_text(
            'password = "$2$xwtn6bkbz4dkdsxdjp3wjmyzmzpdepg5$tsd3tzcb65msjcjnzzhoh1h39ub8ykg8cs3dy6z6xhi1xpg5rtpb";\n',
            encoding="utf-8",
        )
        for path in secrets.rglob("*"):
            path.chmod(0o644)

    def up(self, spec=None, recipients=None) -> None:  # type: ignore[no-untyped-def]
        self.write_rspamd()
        super().up(spec or milter_spec(), recipients if recipients is not None else LAB_RECIPIENTS)

    def reapply_rspamd(self, cfg: RspamdNodeConfig) -> dict[str, object]:
        """Выпустить новую конфигурацию сканера на работающем узле тем же путём, что и при запуске."""
        self.write_rspamd(cfg)
        result = docker(
            "exec",
            self.rspamd_container,
            "python3",
            "-m",
            "msp_antispam.node",
            "apply",
            "--config",
            "/bootstrap/rspamd.json",
            check=False,
            timeout=200,
        )
        try:
            return dict(json.loads(result.stdout.strip().splitlines()[-1]))
        except (ValueError, IndexError):
            return {"outcome": "ERROR", "detail": (result.stdout + result.stderr)[-600:]}

    # --- отправка с заданного адреса -------------------------------------------------------
    def smtp_from(
        self,
        ip: str,
        mail_from: str,
        rcpts: list[str],
        raw: bytes,
        *,
        helo: str = "mail.sender.example",
        target: str = "gateway-postfix",
        port: int = 25,
        starttls: bool = False,
    ) -> dict[str, object]:
        script = f"""
        import json, smtplib, ssl
        raw = bytes.fromhex("{raw.hex()}")
        out = {{"ok": False}}
        try:
            c = smtplib.SMTP("{target}", {port}, timeout=60, local_hostname="{helo}")
            c.ehlo("{helo}")
            if {starttls!r}:
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                c.starttls(context=ctx); c.ehlo("{helo}")
            refused = c.sendmail("{mail_from}", {json.dumps(rcpts)}, raw)
            out = {{"ok": True, "refused": {{k: [v[0], v[1].decode()] for k, v in refused.items()}}}}
            c.quit()
        except smtplib.SMTPRecipientsRefused as e:
            out = {{"ok": False, "stage": "rcpt", "refused": {{k: [v[0], v[1].decode()] for k, v in e.recipients.items()}}}}
        except smtplib.SMTPResponseException as e:
            out = {{"ok": False, "stage": "response", "code": e.smtp_code, "error": e.smtp_error.decode(errors="replace")}}
        except Exception as e:
            out = {{"ok": False, "stage": "error", "error": type(e).__name__}}
        print(json.dumps(out))
        """
        result = self.run_client(textwrap.dedent(script), ip=ip)
        try:
            return dict(json.loads(result.stdout.strip().splitlines()[-1]))
        except (ValueError, IndexError):
            return {"ok": False, "stage": "harness", "error": (result.stdout + result.stderr)[-500:]}

    def send_inbound(
        self,
        message_id: str | None = None,
        *,
        ip: str = SENDER_IP,
        mail_from: str = "a@example.test",
        helo: str = "mail.example.test",
        raw: bytes | None = None,
        rcpt: str = "ivan@corp.example",
        envelope_from: str | None = None,
    ) -> tuple[str, dict[str, object]]:
        mid = message_id or f"sp-{uuid.uuid4().hex[:10]}"
        body = raw if raw is not None else build_message(mid, mail_from, rcpt)
        result = self.smtp_from(
            ip, mail_from if envelope_from is None else envelope_from, [rcpt], body, helo=helo
        )
        return mid, result

    def send_outbound(
        self,
        message_id: str | None = None,
        *,
        mail_from: str = "ivan@corp.example",
        rcpt: str = "partner@elsewhere.example",
        raw: bytes | None = None,
        ip: str = TRUSTED_CLIENT_IP,
        helo: str = "exchange.lab.example",
    ) -> tuple[str, dict[str, object]]:
        mid = message_id or f"so-{uuid.uuid4().hex[:10]}"
        body = raw if raw is not None else build_message(mid, mail_from, rcpt)
        result = self.smtp_from(ip, mail_from, [rcpt], body, helo=helo, port=2525, starttls=True)
        return mid, result

    # --- результаты сканера ----------------------------------------------------------------
    def scans(self) -> list[dict[str, object]]:
        """Записи, которые приёмник узла получил от Rspamd (до отправки в панель)."""
        script = (
            "import glob,json;print(json.dumps([json.load(open(p)) for p in sorted(glob.glob("
            "'/var/lib/msp-rspamd/outbox/*.json'))]))"
        )
        result = docker("exec", self.rspamd_container, "python3", "-c", script, check=False)
        try:
            return list(json.loads(result.stdout.strip().splitlines()[-1]))
        except (ValueError, IndexError):
            return []

    def scan_for(self, message_id: str, *, timeout: float = 90.0) -> dict[str, object]:
        found: dict[str, object] = {}

        def check() -> bool:
            for record in self.scans():
                if message_id in str(record.get("message_id", "")):
                    found.update(record)
                    return True
            return False

        self.wait_until(check, timeout=timeout, what=f"результат сканирования письма {message_id}")
        return found

    def clear_scans(self) -> None:
        docker(
            "exec", self.rspamd_container, "sh", "-c", "rm -f /var/lib/msp-rspamd/outbox/*.json", check=False
        )

    def analysis(self, message_id: str, *, timeout: float = 90.0, policy=None, **kwargs):  # type: ignore[no-untyped-def]
        """Результат сканирования письма, пропущенный через анализ MSP."""
        from msp_antispam.analysis import analyze
        from msp_antispam.policy import SpamPolicy

        record = self.scan_for(message_id, timeout=timeout)
        return analyze(record, policy or SpamPolicy(), **kwargs)

    def auth_of(self, message_id: str, **kwargs):  # type: ignore[no-untyped-def]
        return self.analysis(message_id, **kwargs).auth

    def send_from_zone(
        self, zone, message_id: str | None = None, *, ip: str = SENDER_IP, sign: bool = True, **kwargs
    ):  # type: ignore[no-untyped-def]
        mid = message_id or f"sp-{uuid.uuid4().hex[:10]}"
        raw = kwargs.pop("raw", None) or zone.message(mid, sign=sign)
        envelope = kwargs.pop("mail_from", zone.address)
        result = self.smtp_from(ip, envelope, ["ivan@corp.example"], raw, helo=kwargs.pop("helo", zone.helo))
        return mid, result

    def delivered(self, message_id: str, *, timeout: float = 90.0) -> dict[str, object] | None:
        return self.exchange1.wait_for(
            f"<{message_id}@sender.example>", timeout=timeout
        ) or self.exchange2.wait_for(f"<{message_id}@sender.example>", timeout=1)

    def rspamd_log(self, tail: int = 80) -> str:
        return docker("logs", "--tail", str(tail), self.rspamd_container, check=False).stdout


__all__ = [
    "OTHER_IP",
    "SENDER_IP",
    "TRUSTED_CLIENT_IP",
    "TRUSTED_NETWORK",
    "UNTRUSTED_CLIENT_IP",
    "DkimKey",
    "DkimSigning",
    "Dns",
    "SigningDomain",
    "SpamStack",
    "build_message",
    "milter_spec",
    "node_config",
]
