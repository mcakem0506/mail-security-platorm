"""Стенд принуждения MSP 1.3: настоящий Postfix, Rspamd, служба принуждения, послеочередной шлюз и панель.

Стенд расширяет стенд анти-спама (1.2) тремя вещами: служба ``gateway-enforcement`` (решение до очереди для
Rspamd), ``gateway-afterqueue`` (карантин после очереди) и панель с ключом подписи политики. Все решения
принимаются по настоящей подписанной политике, которую узел забирает у панели; подмен в обход проверки нет.
"""

from __future__ import annotations

import dataclasses
import json
import runpy
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from msp_antispam import corpus
from msp_antispam.rspamd_config import EnforcementGate
from msp_gateway.spec import AfterQueue

from tests.gateway.harness import REPO as REPO_ROOT
from tests.gateway.harness import docker
from tests.gateway.panel import ADMIN_PASSWORD, Panel
from tests.spam.harness import OTHER_IP, SENDER_IP, SpamStack, node_config
from tests.spam.zone import Zone

POLICY_TOKEN = "enforcement-policy-" + "p" * 32
SIGNING_KEY = "lab-signing-key-" + "k" * 40
QUARANTINE_KEY = "lab-quarantine-key-" + "q" * 40
ENFORCEMENT_IP = "10.77.0.53"
AFTERQUEUE_IP = "10.77.0.54"
POSTFIX_IP = "10.77.0.10"

_RECORDER = runpy.run_path(str(REPO_ROOT / "scripts" / "record_spam_corpus.py"), run_name="recorder")
dns_for: Callable[..., Any] = _RECORDER["dns_for"]
build_case: Callable[..., Any] = _RECORDER["build"]


def after_queue_spec() -> AfterQueue:
    return AfterQueue(enabled=True, filter_host=AFTERQUEUE_IP, reinject_host=POSTFIX_IP)


def gate() -> EnforcementGate:
    return EnforcementGate(enabled=True, url=f"http://{ENFORCEMENT_IP}:11390/v1/decide", timeout_ms=1500)


class Person:
    """Человек в консоли панели. Четыре глаза требуют другой учётной записи."""

    def __init__(self, panel: Panel, email: str, role: str = "SECURITY_ADMIN") -> None:
        from msp_api.db.models import Organization, User
        from msp_api.security.auth import hash_password
        from msp_contracts import Role

        with panel.database() as session:
            org = session.query(Organization).first()
            if session.query(User).filter(User.email == email).first() is None:
                session.add(
                    User(
                        organization_id=org.id,
                        email=email,
                        display_name=email,
                        role=Role[role],
                        password_hash=hash_password(ADMIN_PASSWORD),
                    )
                )
                session.commit()
        self.email = email
        self.client = httpx.Client(base_url=f"http://127.0.0.1:{panel.port}", timeout=90)
        response = self.client.post("/api/v1/auth/login", json={"email": email, "password": ADMIN_PASSWORD})
        response.raise_for_status()
        self.csrf = response.json()["csrf_token"]

    def get(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        return self.client.get(path, params=params)

    def post(self, path: str, json: object = None) -> httpx.Response:
        return self.client.post(path, json=json, headers={"x-csrf-token": self.csrf})


class EnforcementStack(SpamStack):
    compose_profiles = ("gateway-test", "spam-security-test", "enforcement-test")

    def __init__(self, workdir: Path, **kwargs: object) -> None:
        super().__init__(workdir, **kwargs)  # type: ignore[arg-type]
        self.ports["ENF_METRICS_PORT"] = _free()
        (workdir / "secrets" / "enforcement").mkdir(parents=True, exist_ok=True)
        self.node_cfg = node_config(enforcement=gate())

    def panel_env(self) -> dict[str, str]:
        env = super().panel_env()
        env["ENF_PANEL_URL"] = f"http://host.docker.internal:{self.panel_port}/api/v1"
        env["ENF_GATE_TIMEOUT"] = "25"
        env["ENF_HOLD_TTL"] = "60"
        return env

    def write_enforcement_secrets(self) -> None:
        directory = self.workdir / "secrets" / "enforcement"
        (directory / "policy.token").write_text(POLICY_TOKEN, encoding="utf-8")
        (directory / "signing.key").write_text(SIGNING_KEY, encoding="utf-8")
        for path in directory.iterdir():
            path.chmod(0o644)
        directory.chmod(0o755)

    @property
    def enforcement_container(self) -> str:
        return self.container("gateway-enforcement")

    @property
    def afterqueue_container(self) -> str:
        return self.container("gateway-afterqueue")

    # --- состояние служб ---------------------------------------------------------------------
    def node_status(self, container: str | None = None) -> dict[str, Any]:
        result = docker(
            "exec",
            container or self.enforcement_container,
            "python",
            "-m",
            "msp_enforcement.node",
            "status",
            check=False,
        )
        try:
            return dict(json.loads(result.stdout.strip().splitlines()[-1]))
        except (ValueError, IndexError):
            return {}

    def wait_policy(self, version: str, *, timeout: float = 60.0) -> None:
        def ready() -> bool:
            return (
                self.node_status().get("policy_version") == version
                and self.node_status(self.afterqueue_container).get("policy_version") == version
            )

        self.wait_until(ready, timeout=timeout, what=f"узлы получили политику {version}")

    def wait_kill_switch(self, active: bool, *, timeout: float = 30.0) -> float:
        started = time.monotonic()
        self.wait_until(
            lambda: self.node_status().get("kill_switch") is active,
            timeout=timeout,
            what=f"общий выключатель = {active}",
        )
        return time.monotonic() - started

    def set_local_bypass(self, on: bool) -> None:
        docker(
            "exec",
            self.enforcement_container,
            "python",
            "-m",
            "msp_enforcement.node",
            "bypass",
            "on" if on else "off",
        )

    def enforcement_metrics(self) -> str:
        return docker(
            "exec",
            self.enforcement_container,
            "python",
            "-c",
            "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:11390/metrics').read().decode())",
            check=False,
        ).stdout

    # --- письма корпуса -----------------------------------------------------------------------
    def case(self, category: str, index: int = 1) -> corpus.Case:
        wanted = [c for c in corpus.generate_cases() if c.category == category]
        return wanted[index - 1]

    def send_case(
        self, case: corpus.Case, rcpts: list[str], *, unique: str = ""
    ) -> tuple[str, dict[str, object]]:
        zone = Zone("en")
        self.dns.reset()
        self.dns.records(dns_for(case, zone, None))
        ip = SENDER_IP if case.context.client == "authorized" else OTHER_IP
        helo = {"mail": zone.helo, "ip": f"[{ip}]"}.get(case.context.helo, "evil.example")
        if unique:
            # Идентификатор входит в подписываемые заголовки, поэтому меняется до подписи, а не после.
            case = dataclasses.replace(case, id=f"{case.id}-{unique}")
        raw = build_case(case, zone, None)
        message_id = f"{case.id.lower()}@corpus.example"
        result = self.smtp_from(ip, f"sender@{zone.domain}", rcpts, raw, helo=helo)
        return message_id, result


def _free() -> int:
    from tests.gateway.harness import _free_port

    return int(_free_port())


# --- общие действия над панелью ---------------------------------------------------------------
BASE = "/api/v1/enforcement"
CANARY_RCPT = "ivan@corp.example"
OTHER_RCPT = "shared@corp.example"


def seed_reviewed_rejects(panel: Panel, count: int = 120) -> None:
    """Лабораторная выборка просмотренных кандидатов на отказ: достаточна для канарейки, не для пилота (ТЗ §83)."""
    from msp_api.db.models import Organization
    from msp_api.db.models_antispam import SpamReview, SpamScan

    with panel.database() as session:
        org = session.query(Organization).first()
        already = session.query(SpamReview).count()
        for i in range(already, count):
            scan = SpamScan(
                organization_id=org.id,
                node_id="b" * 32,
                queue_id=f"SEED{i:06d}",
                internet_message_id=f"seed-{i}@lab",
                score=18.0,
                suggested_action="REJECT",
                spam_class="HIGH_CONFIDENCE_SPAM",
            )
            session.add(scan)
            session.flush()
            session.add(
                SpamReview(
                    organization_id=org.id,
                    scan_id=scan.id,
                    verdict="SPAM",
                    selection="SUGGESTED_REJECT",
                    reviewed_by="lab-analyst@corp.example",
                )
            )
        session.commit()


def make_ready(enf: EnforcementStack, admin: Person, kind: str = "SPAM_REJECT") -> str:
    seed_reviewed_rejects(enf.panel)  # type: ignore[attr-defined]
    for name in ("control_tests_green", "rspamd_failopen_tested"):
        response = admin.post(
            f"{BASE}/controls/{kind}/attest", {"name": name, "value": True, "ref": "lab-run"}
        )
        assert response.status_code == 200, response.text

    def ready() -> bool:
        view = admin.get(f"{BASE}/controls/{kind}").json()
        return bool(view["eligibility"].get("can_canary"))

    enf.wait_until(
        ready, timeout=90, what="контроль готов к канарейке (аудит действий сканера дошёл до панели)"
    )
    return str(admin.get(f"{BASE}/controls/{kind}").json()["id"])


def activate(
    enf: EnforcementStack,
    admin: Person,
    admin2: Person,
    kind: str,
    *,
    scope: dict[str, Any],
    thresholds: dict[str, float] | None = None,
    justification: str = "лабораторная канарейка принуждения",
) -> str:
    """Запрос и согласование двумя людьми; возвращает версию политики, которую получили оба узла."""
    request = admin.post(
        f"{BASE}/controls/{kind}/canary",
        {
            "action": "request",
            "scope": scope,
            "thresholds": thresholds,
            "justification": justification,
        },
    )
    assert request.status_code == 200, request.text
    approved = admin2.post(f"{BASE}/controls/{kind}/canary", {"action": "approve"})
    assert approved.status_code == 200, approved.text
    version = str(approved.json()["policy"]["version"])
    enf.wait_policy(version)
    return version


def pause(enf: EnforcementStack, admin: Person, kind: str) -> str:
    response = admin.post(f"{BASE}/controls/{kind}/pause", {"reason": "лабораторная проверка завершена"})
    assert response.status_code in (200, 409), response.text
    version = str(admin.get(f"{BASE}/policies/current").json()["version"])
    enf.wait_policy(version)
    return version


def decisions(admin: Person, **params: str) -> list[dict[str, Any]]:
    return list(admin.get(f"{BASE}/decisions", params={"limit": "200", **params}).json()["items"])


def rejected_text(result: dict[str, object]) -> str:
    return f"{result.get('code')} {result.get('error')}"


def ensure_canary(
    enf: EnforcementStack,
    admin: Person,
    admin2: Person,
    kind: str = "SPAM_REJECT",
    *,
    scope: dict[str, Any] | None = None,
    thresholds: dict[str, float] | None = None,
) -> None:
    """Привести контроль в канарейку обычным путём (готовность, запрос, согласование вторым человеком)."""
    view = admin.get(f"{BASE}/controls/{kind}").json()
    if view["state"] == "CANARY":
        return
    if view["state"] in ("PAUSED", "ROLLED_BACK"):
        response = admin.post(f"{BASE}/controls/{kind}/shadow", {"reason": "подготовка проверки"})
        assert response.status_code == 200, response.text
        enf.wait_policy(str(response.json()["policy"]["version"]))
    make_ready(enf, admin, kind)
    activate(
        enf,
        admin,
        admin2,
        kind,
        scope=scope or {"recipients": [CANARY_RCPT]},
        thresholds=thresholds if thresholds is not None else {"reject_score": 12.0},
    )


def delivered(lab: EnforcementStack, message_id: str, timeout: float = 90.0) -> Any:
    return lab.exchange1.wait_for(f"<{message_id}>", timeout=timeout) or lab.exchange2.wait_for(
        f"<{message_id}>", timeout=2
    )


def not_delivered(lab: EnforcementStack, message_id: str, wait: float = 12.0) -> bool:
    time.sleep(wait)
    return (
        lab.exchange1.wait_for(f"<{message_id}>", timeout=1) is None
        and lab.exchange2.wait_for(f"<{message_id}>", timeout=1) is None
    )


def diagnostics(lab: EnforcementStack) -> str:
    """Что видно на стенде, когда ожидание не дождалось: журнал послеочередного шлюза и очередь Postfix."""
    aq = docker("logs", "--tail", "30", lab.afterqueue_container, check=False)
    queue = lab.exec("postqueue -p 2>&1 | tail -20", check=False).stdout
    return f"--- afterqueue ---\n{(aq.stdout + aq.stderr)[-2500:]}\n--- postqueue ---\n{queue}"


def wait_with_diagnostics(
    lab: EnforcementStack, condition: Callable[[], bool], *, timeout: float, what: str
) -> None:
    try:
        lab.wait_until(condition, timeout=timeout, what=what)
    except TimeoutError as exc:
        raise TimeoutError(f"{exc}\n{diagnostics(lab)}") from exc


def wait_panel_quiet(lab: EnforcementStack, *, quiet: float = 10.0, timeout: float = 600.0) -> None:
    """Дождаться, пока панель перестанет принимать теневые копии предыдущих проверок.

    Панель стенда держит одну блокировку базы (SQLite): пока она разбирает очередь копий, запрос полного анализа ждёт своей очереди и
    может упереться в тайм-аут шлюза — тогда письмо (штатно) доставляется, а не уходит в карантин. Боевая панель с PostgreSQL
    такого общего замка не имеет; это свойство стенда, поэтому проверки карантина начинаются на тихой панели.
    """
    from msp_api.db.models_transport import TransportMessage

    def count() -> int:
        with lab.panel.database() as session:  # type: ignore[attr-defined]
            return int(session.query(TransportMessage).count())

    deadline = time.monotonic() + timeout
    last, since = count(), time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(2)
        current = count()
        if current != last:
            last, since = current, time.monotonic()
        elif time.monotonic() - since >= quiet:
            return
    raise TimeoutError("панель продолжает принимать копии писем")


def wait_afterqueue_listening(lab: EnforcementStack, *, timeout: float = 90.0) -> None:
    script = "import socket;socket.create_connection(('127.0.0.1',10025),3).close()"

    def up() -> bool:
        return docker("exec", lab.afterqueue_container, "python", "-c", script, check=False).returncode == 0

    lab.wait_until(up, timeout=timeout, what="послеочередной шлюз принимает соединения")
