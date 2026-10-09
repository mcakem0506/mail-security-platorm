"""Короткие похожие домены и QR через весь конвейер по HTTP (ТЗ 1.0.4 §27, сценарии 1–3).

Модульные тесты проверяют сигнал, прогон корпуса — поведение на всех случаях сразу. Ни то, ни
другое не проходит путь, по которому письмо идёт в жизни: приём от сотрудника, анализ, запись
вердикта, выдача причин — и отдельно то, что сотрудник в ответе **видит**.

Последнее здесь и есть предмет первого сценария. Правило может сработать верно, а причина, которую
увидит сотрудник, может не сказать ему ничего — и тогда детектирование, формально сработавшее, не
сработало.

Два представления одного письма различаются намеренно, и тесты ходят в оба. Сотрудник получает
причины без устройства детектирования: ни правил, ни версий, ни перечня недостающего. Аналитик
получает всё это через расследования. Проба показала, что я писал тесты против первого,
ожидая содержимого второго.

Три сценария ТЗ:

1. вредоносный короткий похожий домен обнаружен, и причина доходит до сотрудника;
2. легитимный похожий домен не обвинён;
3. письмо с QR-кодом: содержимое прочитано, либо честно отмечено как непрочитанное.
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from msp_contracts import Role

#: Кейсы золотого корпуса. Берутся они, а не новые письма: корпус — то, на чём измеряется
#: качество, и сценарий, идущий по другому письму, проверял бы другое.
MALICIOUS_SHORT = "SDM-001"
LEGITIMATE_SHORT = "SDN-001"
#: Семейство SDW: похожий короткий домен **без** независимого подтверждения. Здесь должно
#: сработать зеркальное SND-025 с нулевым весом и не должно — SND-024.
SHORT_WITHOUT_CORROBORATION = "SDW-001"
QR_CASE = "QRD-001"

#: Вердикты, означающие обвинение. ``UNKNOWN`` сюда не входит: на стенде без обогащения
#: платформа не объявляет письмо чистым, и это прямое следствие запрета считать отсутствие
#: детекта безопасностью. Требовать от легитимного письма ``LOW_RISK`` значило бы требовать от
#: платформы ровно того, что ей запрещено.
ACCUSING_VERDICTS = frozenset({"SUSPICIOUS", "HIGH_RISK", "MALICIOUS"})


@pytest.fixture(scope="module")
def golden():  # type: ignore[no-untyped-def]
    from msp_detection_eval.corpus import build_golden_dataset

    dataset, messages = build_golden_dataset()
    return {c.id: c for c in dataset.cases}, messages


@pytest.fixture
def client(engine, storage_dir, monkeypatch):  # type: ignore[no-untyped-def]
    from msp_api import deps
    from msp_api.config import get_settings
    from msp_api.db.session import get_session
    from msp_api.main import create_app
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_session():  # type: ignore[no-untyped-def]
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    deps.reset_provider_cache()
    monkeypatch.setattr(deps, "_redis_client", lambda: None)
    deps.reset_rate_limiter()

    app = create_app(get_settings())
    app.dependency_overrides[get_session] = override_session
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    deps.reset_provider_cache()


@pytest.fixture
def people(engine, organization):  # type: ignore[no-untyped-def]
    from msp_api.db.models import User
    from msp_api.security.auth import hash_password
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    password = "ShortDomain-Test-Password-5"
    accounts = {
        "employee": ("user@corp.example", Role.EMPLOYEE),
        "analyst": ("analyst@corp.example", Role.SECURITY_ANALYST),
    }
    created: dict[str, dict[str, str]] = {}
    with factory() as session:
        for key, (email, role) in accounts.items():
            user = User(
                organization_id=organization.id,
                email=email,
                display_name=key,
                role=role,
                password_hash=hash_password(password),
            )
            session.add(user)
            session.flush()
            created[key] = {"id": user.id, "email": email, "password": password}
        session.commit()
    return created


class Actor:
    def __init__(self, client: TestClient, email: str, password: str) -> None:
        self.client = client
        response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert response.status_code == 200, response.text
        self.csrf = response.json()["csrf_token"]

    def get(self, path: str, **kwargs):  # type: ignore[no-untyped-def]
        return self.client.get(path, **kwargs)

    def post(self, path: str, json=None, **kwargs):  # type: ignore[no-untyped-def]
        return self.client.post(path, json=json, headers={"x-csrf-token": self.csrf}, **kwargs)

    def logout(self) -> None:
        self.client.post("/api/v1/auth/logout", headers={"x-csrf-token": self.csrf})
        self.client.cookies.clear()


def _submit(client, people, golden, case_id: str) -> str:  # type: ignore[no-untyped-def]
    """Сотрудник отправляет письмо корпуса на проверку; возвращается идентификатор задачи."""
    _cases, messages = golden
    raw = messages[f"generated:{case_id}"]
    employee = Actor(client, people["employee"]["email"], people["employee"]["password"])
    submitted = employee.post(
        "/api/v1/analysis",
        json={"raw_eml_base64": base64.b64encode(raw).decode(), "report_as_phishing": True},
    )
    assert submitted.status_code == 202, submitted.text
    job_id = str(submitted.json()["job_id"])
    employee.logout()
    return job_id


def _employee_view(client, people, golden, case_id: str) -> dict:  # type: ignore[no-untyped-def]
    """То, что видит сотрудник.

    Ни сигналов, ни версий правил здесь нет, и это решение 1.0, а не пробел: сотруднику
    достаются причины, а не устройство детектирования.
    """
    _cases, messages = golden
    raw = messages[f"generated:{case_id}"]
    employee = Actor(client, people["employee"]["email"], people["employee"]["password"])
    submitted = employee.post(
        "/api/v1/analysis",
        json={"raw_eml_base64": base64.b64encode(raw).decode(), "report_as_phishing": True},
    )
    assert submitted.status_code == 202, submitted.text
    body = employee.get(f"/api/v1/analysis/{submitted.json()['job_id']}")
    assert body.status_code == 200, body.text
    employee.logout()
    return body.json()


def _analyst_verdict(client, people, golden, case_id: str) -> dict:  # type: ignore[no-untyped-def]
    """То же письмо глазами аналитика: сигналы, версии, чего не хватило.

    Адрес другой, и это не деталь: /analysis/{job} отдаёт представление для сотрудника —
    причины без правил, — а /analysis/{job}/detail отдаёт разбор. Я писал первые версии
    этих тестов против первого адреса, ожидая содержимого второго, и они падали на верном коде.

    Путь при этом начинается с расследований, а не с идентификатора задачи сотрудника: аналитик
    находит письмо в своей очереди, и job_id берётся из списка — ровно так же, как это
    делает консоль.
    """
    _submit(client, people, golden, case_id)

    analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
    listing = analyst.get("/api/v1/investigations/messages?limit=5")
    assert listing.status_code == 200, listing.text
    items = listing.json()["items"]
    assert items, "письмо должно появиться в расследованиях"
    job_id = items[0].get("job_id")
    assert job_id, "без ссылки на анализ консоль не покажет причины вердикта"
    detail = analyst.get(f"/api/v1/analysis/{job_id}/detail")
    assert detail.status_code == 200, detail.text
    analyst.logout()
    return detail.json()


def _rules(verdict: dict) -> set[str]:
    return {signal.get("rule_id") for signal in (verdict.get("signals") or [])}


class TestScenario1MaliciousShortDomainIsCaughtAndExplained:
    def test_the_verdict_is_not_clean(self, client, people, golden) -> None:  # type: ignore[no-untyped-def]
        """Письмо с коротким похожим доменом и подтверждением не должно пройти как безопасное."""
        body = _employee_view(client, people, golden, MALICIOUS_SHORT)
        assert body["classification"] in ACCUSING_VERDICTS, body.get("reasons")

    def test_the_short_domain_rule_fired(self, client, people, golden) -> None:  # type: ignore[no-untyped-def]
        verdict = _analyst_verdict(client, people, golden, MALICIOUS_SHORT)
        assert "SND-024" in _rules(verdict), _rules(verdict)

    def test_the_employee_is_told_why_in_their_own_view(self, client, people, golden) -> None:  # type: ignore[no-untyped-def]
        """Правило, сработавшее без объяснимой причины, для сотрудника не сработало.

        Проверяется наличие причин и то, что причина о коротком домене до сотрудника доходит.
        Понятность формулировки оценивается опросом участников пилота; а вот пустой или
        безличный список причин — дефект, который тест обязан поймать.
        """
        body = _employee_view(client, people, golden, MALICIOUS_SHORT)
        reasons = body.get("reasons") or []
        assert reasons, "вердикт без причин сотруднику ничего не говорит"
        assert all(reason.get("title") for reason in reasons)
        titles = " ".join(str(reason.get("title")) for reason in reasons).lower()
        assert "метка домена" in titles, titles

    def test_the_verdict_is_reproducible(self, client, people, golden) -> None:  # type: ignore[no-untyped-def]
        """Версии того, что решало, записаны: иначе расхождение потом не объяснить.

        В представлении для сотрудника их нет намеренно — это внутреннее устройство, — поэтому
        проверяются они там, где нужны: у аналитика.
        """
        verdict = _analyst_verdict(client, people, golden, MALICIOUS_SHORT)
        assert verdict.get("engine_version")
        assert verdict.get("risk_engine_version")


class TestScenario2LegitimateShortDomainIsNotAccused:
    def test_a_legitimate_similar_domain_is_not_accused(self, client, people, golden) -> None:  # type: ignore[no-untyped-def]
        """Самый дорогой вид ошибки для этого сигнала: домен, похожий на защищаемый случайно.

        Цена ложного срабатывания здесь выше цены пропуска — именно поэтому GAP-001 так долго
        оставался принятым ограничением.
        """
        body = _employee_view(client, people, golden, LEGITIMATE_SHORT)
        assert body["classification"] not in ACCUSING_VERDICTS, body.get("reasons")

    def test_neither_short_domain_rule_fired(self, client, people, golden) -> None:  # type: ignore[no-untyped-def]
        verdict = _analyst_verdict(client, people, golden, LEGITIMATE_SHORT)
        rules = _rules(verdict)
        assert "SND-024" not in rules, rules
        assert "SND-025" not in rules, rules

    def test_a_short_lookalike_without_corroboration_does_not_accuse(self, client, people, golden) -> None:  # type: ignore[no-untyped-def]
        """Похожесть без независимого подтверждения измеряется, но не обвиняет.

        Зеркальное SND-025 с нулевым весом существует ровно для этого: случай виден в
        статистике, а вердикт от него не меняется. Это и есть проверка того, что сигнал
        **условный**, а не просто слабый.
        """
        body = _employee_view(client, people, golden, SHORT_WITHOUT_CORROBORATION)
        assert body["classification"] not in ACCUSING_VERDICTS, body.get("reasons")

        verdict = _analyst_verdict(client, people, golden, SHORT_WITHOUT_CORROBORATION)
        rules = _rules(verdict)
        assert "SND-024" not in rules, "без подтверждения обвинять нельзя"
        assert "SND-025" in rules, "но случай должен быть виден в статистике"


class TestScenario3QrProfile:
    def test_a_qr_message_is_not_silently_clean(self, client, people, golden) -> None:  # type: ignore[no-untyped-def]
        """С декодером содержимое кода читается; без него код остаётся непрочитанным.

        Оба исхода допустимы, недопустим третий: чистый вердикт за счёт того, чего никто не
        прочитал. Тест поэтому проверяет не наличие декодера, а то, что его отсутствие видно.
        """
        body = _employee_view(client, people, golden, QR_CASE)
        assert body["classification"] != "LOW_RISK", (
            "письмо с QR-кодом не должно получать чистый вердикт: либо код прочитан и даёт "
            f"сигнал, либо он не прочитан и проверка неполна; причины: {body.get('reasons')}"
        )

    def test_the_analyst_sees_either_the_decoded_link_or_what_was_missing(
        self, client, people, golden
    ) -> None:  # type: ignore[no-untyped-def]
        """Один из двух исходов обязателен, и оба названы вслух.

        Без этой проверки прогон с установленным декодером и без него выглядел бы одинаково, а
        это ровно то различие, которое профиль ``qr-analysis`` и делает видимым.
        """
        verdict = _analyst_verdict(client, people, golden, QR_CASE)
        decoded = any(
            "qr" in str(signal.get("rule_id") or "").lower() or "qr" in str(signal.get("title") or "").lower()
            for signal in (verdict.get("signals") or [])
        )
        missing = verdict.get("missing_evidence") or []
        assert decoded or missing, (
            "либо код прочитан и это видно сигналом, либо не прочитан и это видно "
            f"в missing_evidence; сигналы: {_rules(verdict)}"
        )
