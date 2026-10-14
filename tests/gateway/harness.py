"""Стенд проверки транспорта шлюза (ТЗ 1.1 §49–§54, §67).

Стенд управляет настоящим Postfix в контейнере и двойниками Exchange. Здесь нет подмены
Postfix: открытый релей, потеря письма при перезапуске и обработка временных отказов — свойства
поведения MTA, и проверить их можно только на нём самом.

Всё, что делает стенд, — через интерфейс ``docker``: поднять, остановить, убить процесс,
перезапустить контейнер, выполнить команду. Другого способа повлиять на узел у тестов нет, и
это намеренно: сбой, который нельзя вызвать извне, не является сценарием, который произойдёт
в эксплуатации.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import shutil
import smtplib
import socket
import ssl
import subprocess
import textwrap
import time
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from msp_gateway.render import Recipient, manifest_bytes, render
from msp_gateway.spec import (
    GatewaySpec,
    InboundListener,
    InternalListener,
    Outbound,
    OutboundMode,
    RelayDomain,
    Route,
    Target,
    TlsPolicy,
    TlsProfile,
)

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "deployment" / "gateway" / "compose.yml"

#: Подсеть доверенных источников стенда и адрес «Exchange», с которого отправляются письма.
TRUSTED_NETWORK = "10.77.0.64/26"
TRUSTED_CLIENT_IP = "10.77.0.70"
UNTRUSTED_CLIENT_IP = "10.77.0.200"


def docker(
    *args: str, check: bool = True, timeout: float = 300.0, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603 - фиксированная команда docker, без оболочки
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
        input=input_text,
        encoding="utf-8",
        errors="replace",
    )


def docker_available() -> bool:
    try:
        return docker("info", check=False, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# ---------------------------------------------------------------------------------------------
# Сертификаты
# ---------------------------------------------------------------------------------------------
def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


@dataclass
class Authority:
    key: rsa.RSAPrivateKey
    certificate: x509.Certificate

    @classmethod
    def create(cls, common_name: str = "MSP gateway lab CA") -> Authority:
        key = _key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = dt.datetime.now(dt.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        return cls(key, cert)

    def issue(
        self,
        directory: Path,
        stem: str,
        dns_names: list[str],
        *,
        days: int = 30,
        valid_from_days_ago: int = 1,
    ) -> None:
        """Выпустить сертификат. ``days`` отрицательный — уже истёкший (проверка §52)."""
        key = _key()
        now = dt.datetime.now(dt.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])]))
            .issuer_name(self.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=valid_from_days_ago))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(n) for n in dns_names] + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{stem}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        _write_key(directory / f"{stem}.key", key)

    def write_ca(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.certificate.public_bytes(serialization.Encoding.PEM))


# ---------------------------------------------------------------------------------------------
# Топология по умолчанию
# ---------------------------------------------------------------------------------------------
def lab_spec(**overrides: object) -> GatewaySpec:
    """Типовая лабораторная топология: один домен, два сервера Exchange, приёмник исходящей почты."""
    base: dict[str, object] = {
        "hostname": "gw.lab.example",
        "tls_profile": TlsProfile.REQUIRED,
        "relay_domains": (RelayDomain(domain="corp.example", route="exchange"),),
        "routes": (
            Route(
                name="exchange",
                targets=(
                    Target(host="fake-exchange", port=2526, priority=10, tls_policy=TlsPolicy.VERIFY),
                    Target(host="fake-exchange-2", port=2526, priority=20, tls_policy=TlsPolicy.VERIFY),
                ),
            ),
        ),
        # В изолированной сети стенда обратного DNS нет: синхронный поиск имени клиента ждал бы
        # таймаута, и приветствие приходило бы позже, чем клиент готов ждать.
        "inbound": InboundListener(peername_lookup=False),
        "internal": InternalListener(trusted_networks=(TRUSTED_NETWORK,)),
        "outbound": Outbound(mode=OutboundMode.SINK, host="outbound-sink", port=2527),
        "maximal_queue_lifetime_seconds": 600,
        "bounce_queue_lifetime_seconds": 600,
    }
    base.update(overrides)
    return GatewaySpec(**base)  # type: ignore[arg-type]


LAB_RECIPIENTS = [
    Recipient("ivan@corp.example", ("i.petrov@corp.example",)),
    Recipient("shared@corp.example"),
    Recipient("all-staff@corp.example"),
]


# ---------------------------------------------------------------------------------------------
# Стенд
# ---------------------------------------------------------------------------------------------
def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Control:
    """Управление двойником Exchange или приёмником по HTTP."""

    def __init__(self, port: int) -> None:
        self.base = f"http://127.0.0.1:{port}"

    def _call(self, path: str, payload: dict[str, object] | None = None) -> object:
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            self.base + path, data=data, method="POST" if data is not None else "GET"
        )
        request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read())

    def mode(self, mode: str, *, delay: float = 0.0, rejected_recipients: list[str] | None = None) -> None:
        self._call("/mode", {"mode": mode, "delay": delay, "rejected_recipients": rejected_recipients or []})

    def reset(self) -> None:
        self._call("/reset", {})

    def received(self) -> list[dict[str, object]]:
        return list(self._call("/received"))  # type: ignore[call-overload]

    def state(self) -> dict[str, object]:
        return dict(self._call("/state"))  # type: ignore[call-overload]

    def message_ids(self) -> list[str]:
        return [str(item["message_id"]) for item in self.received()]

    def wait_for(self, message_id: str, *, timeout: float = 60.0) -> dict[str, object] | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for item in self.received():
                if item["message_id"] == message_id:
                    return item
            time.sleep(0.5)
        return None

    def wait_up(self, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self._call("/health")
                return
            except OSError:
                time.sleep(0.5)
        raise TimeoutError(f"{self.base} не ответил")


def make_message(message_id: str, sender: str, recipient: str, *, body: str = "тест", size: int = 0) -> bytes:
    text = (
        f"From: {sender}\r\nTo: {recipient}\r\nSubject: test {message_id}\r\n"
        f"Message-ID: <{message_id}@lab.example>\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
        f"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
        f"Content-Transfer-Encoding: 8bit\r\n\r\n{body}\r\n"
    )
    if size:
        text += ("x" * 70 + "\r\n") * max(1, size // 72)
    return text.encode("utf-8")


class Stack:
    def __init__(self, workdir: Path, *, panel_port: int | None = None, panel_token: str = "") -> None:
        self.workdir = workdir
        #: Порт панели на хосте; если задан, узел и сборщик получают её адрес и токен.
        self.panel_port = panel_port
        self.panel_token = panel_token
        self.project = f"gwt{uuid.uuid4().hex[:8]}"
        self.ports = {
            "GW_PORT_IN": _free_port(),
            "GW_PORT_INTERNAL": _free_port(),
            "GW_PORT_METRICS": _free_port(),
            "EX1_CONTROL": _free_port(),
            "EX2_CONTROL": _free_port(),
            "SINK_CONTROL": _free_port(),
        }
        self.authority = Authority.create()
        self._bundle_counter = 0
        for sub in ("bootstrap", "bundles", "secrets/gateway", "secrets/exchange"):
            (workdir / sub).mkdir(parents=True, exist_ok=True)

    # --- окружение и compose -------------------------------------------------------------
    @property
    def env(self) -> dict[str, str]:
        return {
            **os.environ,
            "COMPOSE_PROJECT_NAME": self.project,
            "GW_TEST_DIR": str(self.workdir),
            **{k: str(v) for k, v in self.ports.items()},
            **(self.panel_env() if self.panel_port else {}),
        }

    def panel_env(self) -> dict[str, str]:
        base = f"http://host.docker.internal:{self.panel_port}/api/v1/gateway-agent"
        return {
            "GW_PANEL_URL": base,
            "GW_INGEST_URL": f"{base}/shadow",
            "GW_PANEL_TOKEN_FILE": "/run/secrets/gateway/panel.token",
            "GW_SYNC_INTERVAL": "3",
        }

    def compose(
        self, *args: str, check: bool = True, timeout: float = 600.0
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(  # nosec B603 - фиксированная команда docker compose
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE),
                "--profile",
                "gateway-test",
                *(["--profile", "gateway-panel"] if self.panel_port else []),
                *args,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=self.env,
            encoding="utf-8",
            errors="replace",
        )
        if check and result.returncode != 0:
            # Код возврата без вывода ничего не объясняет, а причина почти всегда в последних
            # строках: сборка образа, порт, недоступный том.
            raise RuntimeError(
                f"docker compose {' '.join(args)} завершился с кодом {result.returncode}\n"
                f"{(result.stdout + result.stderr)[-3500:]}"
            )
        return result

    @property
    def gateway(self) -> str:
        return f"{self.project}-gateway-postfix-1"

    @property
    def network(self) -> str:
        return f"{self.project}_gwnet"

    # --- сертификаты и пакеты --------------------------------------------------------------
    def issue_certificates(self, *, gateway_days: int = 30, exchange_days: int = 30) -> None:
        secrets = self.workdir / "secrets"
        if self.panel_port:
            (secrets / "gateway").mkdir(parents=True, exist_ok=True)
            token = secrets / "gateway" / "panel.token"
            token.write_text(self.panel_token, encoding="utf-8")
            token.chmod(0o644)  # читают root (синхронизация) и владелец журнала (сборщик)
        self.authority.issue(
            secrets / "gateway", "tls", ["gw.lab.example", "gateway-postfix", "localhost"], days=gateway_days
        )
        self.authority.write_ca(secrets / "gateway" / "ca.crt")
        self.authority.issue(
            secrets / "exchange", "exchange", ["fake-exchange", "fake-exchange-2"], days=exchange_days
        )
        for path in secrets.rglob("*.key"):
            path.chmod(0o644)  # внутри контейнера читает пользователь, не владелец тома

    def write_bundle(
        self,
        directory: Path,
        spec: GatewaySpec,
        recipients: list[Recipient],
        *,
        version: int,
        recipients_meta: dict[str, object] | None = None,
    ) -> Path:
        config = render(spec, recipients, version=version, recipients_meta=recipients_meta)
        directory.mkdir(parents=True, exist_ok=True)
        for name, content in config.files.items():
            (directory / name).write_bytes(content)
        (directory / "manifest.json").write_bytes(manifest_bytes(config))
        return directory

    def bootstrap(self, spec: GatewaySpec, recipients: list[Recipient]) -> None:
        shutil.rmtree(self.workdir / "bootstrap", ignore_errors=True)
        self.write_bundle(self.workdir / "bootstrap", spec, recipients, version=1)

    def apply(
        self,
        spec: GatewaySpec,
        recipients: list[Recipient] | None = None,
        *,
        recipients_meta: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Применить новый пакет на работающем узле — тем же путём, каким это делает агент."""
        self._bundle_counter += 1
        version = self._bundle_counter + 1
        name = f"b{version}"
        self.write_bundle(
            self.workdir / "bundles" / name,
            spec,
            recipients if recipients is not None else LAB_RECIPIENTS,
            version=version,
            recipients_meta=recipients_meta,
        )
        ports = f"--internal-port {spec.internal.port}" if spec.internal.enabled else ""
        result = self.exec(
            f"python3 -m msp_gateway.node apply /bundles/{name} --inbound-port {spec.inbound.port} {ports}",
            check=False,
        )
        try:
            return dict(json.loads(result.stdout.strip().splitlines()[-1]))
        except (ValueError, IndexError):
            return {"outcome": "ERROR", "message": (result.stdout + result.stderr)[-500:]}

    def apply_crafted(
        self,
        spec: GatewaySpec,
        mutate: dict[str, object],
        recipients: list[Recipient] | None = None,
    ) -> dict[str, object]:
        """Применить пакет, в котором файлы изменены ПОСЛЕ генерации, с пересчитанной суммой.

        Так выглядит конфигурация, написанная руками или испорченная по дороге: сумма верна, потому
        что её пересчитали, а смысл другой. Сверка суммы такую не поймает по построению — ловить её
        должны проверки postfix check и проверка здоровья после перезагрузки.
        """
        from msp_gateway.bundle import bundle_checksum

        self._bundle_counter += 1
        version = self._bundle_counter + 1
        config = render(spec, recipients if recipients is not None else LAB_RECIPIENTS, version=version)
        files = dict(config.files)
        for name, change in mutate.items():
            files[name] = change(files[name].decode()).encode()  # type: ignore[operator]
        manifest = dict(config.manifest)
        manifest["checksum"] = bundle_checksum(files)
        directory = self.workdir / "bundles" / f"c{version}"
        directory.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            (directory / name).write_bytes(content)
        (directory / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        ports = f"--internal-port {spec.internal.port}" if spec.internal.enabled else ""
        result = self.exec(
            f"python3 -m msp_gateway.node apply /bundles/c{version} "
            f"--inbound-port {spec.inbound.port} {ports}",
            check=False,
        )
        try:
            return dict(json.loads(result.stdout.strip().splitlines()[-1]))
        except (ValueError, IndexError):
            return {"outcome": "ERROR", "message": (result.stdout + result.stderr)[-500:]}

    def node_status(self) -> dict[str, object]:
        return dict(
            json.loads(self.exec("python3 -m msp_gateway.node status").stdout.strip().splitlines()[-1])
        )

    # --- жизненный цикл --------------------------------------------------------------------
    def up(self, spec: GatewaySpec | None = None, recipients: list[Recipient] | None = None) -> None:
        self.issue_certificates()
        self.bootstrap(spec or lab_spec(), recipients if recipients is not None else LAB_RECIPIENTS)
        try:
            self.compose("up", "-d", "--build", "--wait", "--wait-timeout", "240", timeout=900)
        except RuntimeError as exc:
            # Причина сбоя запуска — в журнале контейнера, а не в выводе compose.
            raise RuntimeError(f"{exc}\n--- журнал шлюза ---\n{self.logs(tail=80)}") from exc
        for control in (self.exchange1, self.exchange2, self.sink):
            control.wait_up()
        self.wait_listening(self.ports["GW_PORT_IN"])

    def down(self) -> None:
        self.compose("down", "-v", "--remove-orphans", check=False, timeout=300)

    def logs(self, service: str = "gateway-postfix", tail: int = 200) -> str:
        return self.compose("logs", "--no-color", "--tail", str(tail), service, check=False).stdout

    # --- управление узлом ------------------------------------------------------------------
    def exec(
        self, command: str, *, check: bool = True, user: str = "root"
    ) -> subprocess.CompletedProcess[str]:
        return docker("exec", "-u", user, self.gateway, "sh", "-c", command, check=check, timeout=120)

    def postfix_log(self) -> str:
        return self.exec("cat /var/log/msp/postfix.log 2>/dev/null || true", check=False).stdout

    def queue(self) -> list[dict[str, object]]:
        out = self.exec("postqueue -j 2>/dev/null || true", check=False).stdout
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("{"):
                rows.append(json.loads(line))
        return rows

    def queue_size(self) -> int:
        return len(self.queue())

    def flush(self) -> None:
        self.exec("postqueue -f", check=False)

    def kill_postfix_hard(self) -> None:
        """Убить процессы Postfix без остановки: так узел падает от OOM-killer или потери питания."""
        docker("kill", "--signal", "KILL", self.gateway, check=False)

    def reissue_exchange_certificate(
        self,
        *,
        authority: Authority | None = None,
        dns_names: list[str] | None = None,
        days: int = 30,
    ) -> None:
        """Заменить сертификат двойников Exchange и перезапустить их (проверки TLS, §52).

        Файлы лежат на хосте и смонтированы только для чтения; двойники читают их при запуске,
        поэтому без перезапуска замена не вступит в силу.
        """
        (authority or self.authority).issue(
            self.workdir / "secrets" / "exchange",
            "exchange",
            dns_names or ["fake-exchange", "fake-exchange-2"],
            days=days,
            valid_from_days_ago=max(1, 5 - days) if days < 0 else 1,
        )
        for path in (self.workdir / "secrets" / "exchange").glob("*.key"):
            path.chmod(0o644)
        for service, control in (("fake-exchange", self.exchange1), ("fake-exchange-2", self.exchange2)):
            docker("restart", "-t", "2", self.container(service), timeout=60)
            control.wait_up()

    def restart(self) -> None:
        docker("restart", "-t", "10", self.gateway, timeout=120)
        self.wait_listening(self.ports["GW_PORT_IN"])

    def start(self) -> None:
        docker("start", self.gateway, timeout=120)
        self.wait_listening(self.ports["GW_PORT_IN"])

    def wait_listening(self, port: int, timeout: float = 90.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                    sock.settimeout(3)
                    if sock.recv(64).startswith(b"220"):
                        return
            except OSError:
                pass
            time.sleep(0.5)
        raise TimeoutError(f"порт {port} не отвечает приветствием SMTP\n{self.diagnostics()}")

    def diagnostics(self) -> str:
        """Состояние узла для разбора сбоя: журнал Postfix, процессы, слушающие порты."""
        parts = [
            ("postfix status", self.exec("postfix status 2>&1", check=False).stdout),
            ("postfix.log", self.postfix_log()[-3000:]),
            ("процессы", self.exec("ps -eo user,pid,args 2>&1 | head -25", check=False).stdout),
            ("порты", self.exec("cat /proc/net/tcp 2>&1 | head -12", check=False).stdout),
            ("журнал контейнера", self.logs(tail=40)),
        ]
        return "\n".join(f"--- {name} ---\n{text}" for name, text in parts)

    # --- сбои соседей ----------------------------------------------------------------------
    def container(self, service: str) -> str:
        return f"{self.project}-{service}-1"

    def stop_service(self, service: str) -> None:
        """Остановить соседа целиком: для шлюза это «хост недоступен», а не «хост отказал»."""
        docker("stop", "-t", "2", self.container(service), timeout=60)

    def start_service(self, service: str) -> None:
        docker("start", self.container(service), timeout=60)
        control = {
            "fake-exchange": self.exchange1,
            "fake-exchange-2": self.exchange2,
            "outbound-sink": self.sink,
        }[service]
        control.wait_up()

    def wait_until(
        self, condition, *, timeout: float = 60.0, interval: float = 0.5, what: str = "условие"
    ) -> None:  # type: ignore[no-untyped-def]
        """Дождаться условия. Слепые паузы в этих тестах недопустимы: они делают тест либо
        медленным, либо ненадёжным, а чаще и тем и другим."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(interval)
        raise TimeoutError(f"не дождались: {what}\n{self.postfix_log()[-2500:]}")

    def queue_ids(self) -> set[str]:
        return {str(item.get("queue_id")) for item in self.queue()}

    # --- двойники --------------------------------------------------------------------------
    @property
    def exchange1(self) -> Control:
        return Control(self.ports["EX1_CONTROL"])

    @property
    def exchange2(self) -> Control:
        return Control(self.ports["EX2_CONTROL"])

    @property
    def sink(self) -> Control:
        return Control(self.ports["SINK_CONTROL"])

    # --- отправка --------------------------------------------------------------------------
    def send_external(
        self,
        mail_from: str,
        rcpts: list[str],
        raw: bytes,
        *,
        starttls: bool = False,
        port: int | None = None,
    ) -> dict[str, tuple[int, str]]:
        """Отправка с хоста через опубликованный порт: источник виден шлюзу как адрес моста сети
        Docker, то есть заведомо недоверенный."""
        client = smtplib.SMTP("127.0.0.1", port or self.ports["GW_PORT_IN"], timeout=30)
        try:
            client.ehlo("external.example")
            if starttls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                client.starttls(context=context)
                client.ehlo("external.example")
            return client.sendmail(mail_from, rcpts, raw) or {}  # type: ignore[return-value]
        finally:
            try:
                client.quit()
            except (smtplib.SMTPException, OSError):
                client.close()

    def run_client(self, script: str, *, ip: str = TRUSTED_CLIENT_IP) -> subprocess.CompletedProcess[str]:
        """Выполнить Python-скрипт в контейнере сети стенда с заданным адресом источника."""
        return docker(
            "run",
            "--rm",
            "-i",
            "--network",
            self.network,
            "--ip",
            ip,
            "msp-gateway-tools:test",
            "python",
            "-",
            input_text=textwrap.dedent(script),
            check=False,
            timeout=120,
        )

    def send_trusted(
        self, mail_from: str, rcpts: list[str], raw: bytes, *, ip: str = TRUSTED_CLIENT_IP
    ) -> dict[str, object]:
        """Отправка с доверенного адреса (роль Exchange) на внутренний порт, с обязательным STARTTLS."""
        script = f"""
        import json, smtplib, ssl
        raw = bytes.fromhex("{raw.hex()}")
        out = {{"ok": False}}
        try:
            c = smtplib.SMTP("gateway-postfix", 2525, timeout=30)
            c.ehlo("exchange.lab.example")
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            c.starttls(context=ctx); c.ehlo("exchange.lab.example")
            refused = c.sendmail("{mail_from}", {json.dumps(rcpts)}, raw)
            out = {{"ok": True, "refused": {{k: [v[0], v[1].decode()] for k, v in refused.items()}}}}
            c.quit()
        except smtplib.SMTPRecipientsRefused as e:
            refused = {{k: [v[0], v[1].decode()] for k, v in e.recipients.items()}}
            out = {{"ok": False, "stage": "rcpt", "refused": refused}}
        except smtplib.SMTPResponseException as e:
            error = e.smtp_error.decode(errors="replace")
            out = {{"ok": False, "stage": "response", "code": e.smtp_code, "error": error}}
        except Exception as e:
            out = {{"ok": False, "stage": "error", "error": type(e).__name__}}
        print(json.dumps(out))
        """
        result = self.run_client(script, ip=ip)
        try:
            return dict(json.loads(result.stdout.strip().splitlines()[-1]))
        except (ValueError, IndexError):
            return {"ok": False, "stage": "harness", "error": (result.stdout + result.stderr)[-400:]}
