"""Настоящая панель управления для сквозных проверок «панель ↔ узел» (ТЗ 1.1 §37, §67).

Панель — это само приложение FastAPI с настоящими маршрутами, правами и аудитом, поднятое в
потоке тестового процесса на свободном порту. Узлы в контейнерах ходят к ней по сети как к
настоящей: токен, HTTP, идемпотентные ключи. Подставным здесь остаётся только то, что вне границы
проверки: база (файл SQLite вместо PostgreSQL) и очередь задач (брокера нет, и анализ копий ставится
в очередь «в никуда», что панель переносит штатно).

SQLite не переносит параллельных записей, а три процесса узла пишут в панель одновременно. Поэтому
сеансы базы здесь выдаются под общей блокировкой: это свойство тестового хранилища, а не панели
(PostgreSQL в боевой установке работает с параллельными сеансами).

Панель слушает на всех интерфейсах, потому что контейнер обращается к хосту через шлюз Docker.
Это допустимо только в тесте: порт короткоживущий, а каждый запрос требует токена или сессии.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest import mock

import httpx
import uvicorn

TOKEN = "panel-test-token-" + "x" * 32
ADMIN_EMAIL = "admin@corp.example"
ADMIN_PASSWORD = "Panel-Test-Password-9"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("0.0.0.0", 0))
        return int(sock.getsockname()[1])


class Panel:
    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.port = free_port()
        self.token = TOKEN
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._patches: list[Any] = []
        self._write_lock = threading.Lock()
        self.session_factory: Any = None

    # ------------------------------------------------------------------ запуск и остановка
    def start(self) -> None:
        from msp_api import deps
        from msp_api.config import get_settings
        from msp_api.db.models import Base, Organization, User
        from msp_api.security.auth import hash_password
        from msp_contracts import Role
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine(
            f"sqlite+pysqlite:///{self.workdir / 'panel.db'}",
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        Base.metadata.create_all(engine)
        self.session_factory = sessionmaker(bind=engine, expire_on_commit=False)

        with self.session_factory() as session:
            if session.query(Organization).first() is None:
                org = Organization(id="org-panel", name="Corp", corporate_domains=["corp.example"])
                session.add(org)
                session.flush()
                session.add(
                    User(
                        organization_id=org.id,
                        email=ADMIN_EMAIL,
                        display_name="admin",
                        role=Role.SECURITY_ADMIN,
                        password_hash=hash_password(ADMIN_PASSWORD),
                    )
                )
                session.commit()

        settings = get_settings()
        self._patches = [
            mock.patch.object(settings, "gateway_ingest_token", self.token),
            mock.patch.object(deps, "_redis_client", lambda: None),
        ]
        for patch in self._patches:
            patch.start()
        deps.reset_provider_cache()
        deps.reset_rate_limiter()
        self._launch()
        if not self._server or not self._server.started:
            raise RuntimeError("панель не запустилась")

    def _session(self) -> Iterator[Any]:
        with self._write_lock:
            session = self.session_factory()
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    def _launch(self) -> None:
        from msp_api.config import get_settings
        from msp_api.db.session import get_session
        from msp_api.main import create_app

        app = create_app(get_settings())
        app.dependency_overrides[get_session] = self._session
        config = uvicorn.Config(app, host="0.0.0.0", port=self.port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True, name="panel")
        self._thread.start()
        deadline = time.time() + 30
        while time.time() < deadline and not self._server.started:
            time.sleep(0.1)

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=15)
        self._server = None
        self._thread = None

    def restart(self) -> None:
        """Остановить и поднять заново на том же порту: узел увидит перебой, а не смену адреса."""
        self.stop()
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                with socket.socket() as probe:
                    probe.bind(("0.0.0.0", self.port))
                break
            except OSError:
                time.sleep(0.3)
        self._launch()

    def close(self) -> None:
        self.stop()
        for patch in self._patches:
            patch.stop()
        self._patches = []

    # ------------------------------------------------------------------ клиент администратора
    @contextmanager
    def admin_client(self) -> Iterator[Admin]:
        client = httpx.Client(base_url=f"http://127.0.0.1:{self.port}", timeout=60)
        try:
            yield Admin(client)
        finally:
            client.close()

    @contextmanager
    def database(self) -> Iterator[Any]:
        """Сеанс прямого доступа к базе для проверок, которые подменяют данные в обход API."""
        with self._write_lock:
            session = self.session_factory()
            try:
                yield session
            finally:
                session.close()


class Admin:
    def __init__(self, client: httpx.Client) -> None:
        self.client = client
        response = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        response.raise_for_status()
        self.csrf = response.json()["csrf_token"]

    def get(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        return self.client.get(path, params=params)

    def post(self, path: str, json: Any = None) -> httpx.Response:
        return self.client.post(path, json=json, headers={"x-csrf-token": self.csrf})
