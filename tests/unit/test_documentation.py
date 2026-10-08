"""Руководства для людей должны оставаться правдой (ТЗ 1.0.4, требование заказчика).

Документы по архитектуре читают те, кто пишет код, и они расходятся с кодом заметно. Руководства
сотрудника, аналитика и администратора читают другие люди, и у них нет способа заметить, что
написанное устарело. Именно так в руководстве аналитика полтора этапа простояла строка «не
извлекает URL из QR-кодов и office-документов» — к тому моменту платформа извлекала и то, и
другое, и аналитик из-за этой строки не стал бы искать ссылку.

Проверяется то, что проверяемо автоматически: ссылки между документами и имена прав, лимитов и
ревизий, названные в руководстве администратора. Содержательную свежесть тест не заменяет — для
этого в документе приёмки каждого этапа есть отдельный пункт о том, какие инструкции обновлены.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from msp_api.security.rbac import permissions_for
from msp_contracts import Role

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = REPO_ROOT / "docs"

#: Руководства, адресованные людям, а не разработчикам.
HUMAN_GUIDES = ("EMPLOYEE_GUIDE.md", "ANALYST_GUIDE.md", "ADMIN_GUIDE.md", "DEPLOYMENT.md")

_LINK = re.compile(r"\]\(([^)#]+\.md)\)")
#: Права записаны в руководстве как `scope:action`.
_PERMISSION = re.compile(r"`([a-z]+:[a-z_]+)`")


def _markdown_files() -> list[pathlib.Path]:
    return [*sorted(DOCS.rglob("*.md")), REPO_ROOT / "README.md"]


def test_every_guide_for_people_exists() -> None:
    """Руководство, на которое ссылается индекс, должно существовать."""
    missing = [name for name in HUMAN_GUIDES if not (DOCS / name).is_file()]
    assert not missing, f"нет руководств: {missing}"


def test_no_broken_links_between_documents() -> None:
    broken: list[str] = []
    for path in _markdown_files():
        for target in _LINK.findall(path.read_text(encoding="utf-8")):
            if not (path.parent / target).resolve().is_file():
                broken.append(f"{path.relative_to(REPO_ROOT)} -> {target}")
    assert not broken, "битые ссылки между документами: " + "; ".join(broken)


def test_admin_guide_names_only_permissions_that_exist() -> None:
    """Право, которого нет, невозможно выдать — и невозможно заметить в тексте."""
    known = {permission.value for role in Role for permission in permissions_for(role)}
    named = set(_PERMISSION.findall((DOCS / "ADMIN_GUIDE.md").read_text(encoding="utf-8")))
    assert named, "в руководстве администратора не нашлось ни одного права — изменился формат?"
    unknown = named - known
    assert not unknown, f"руководство называет несуществующие права: {sorted(unknown)}"


def test_deployment_limits_match_the_code() -> None:
    """Числа лимитов декодера в инструкции по развёртыванию — те же, что в коде.

    Администратор по ним принимает решение, ставить компонент или нет, поэтому разойтись им
    нельзя. Руководство администратора те же лимиты описывает словами и числа не повторяет: два
    места с одними и теми же цифрами расходятся ровно вдвое чаще одного.
    """
    from msp_mail_parser.images import DECODE_TIMEOUT_SECONDS, MAX_DECODE_BYTES

    guide = (DOCS / "DEPLOYMENT.md").read_text(encoding="utf-8")
    assert f"{int(DECODE_TIMEOUT_SECONDS)} секунд" in guide
    assert f"{MAX_DECODE_BYTES // (1024 * 1024)} МБ" in guide


def test_deployment_names_the_container_user_the_image_really_uses() -> None:
    """Неверный uid в инструкции означает стек, который не поднимется, и ошибку о правах."""
    dockerfile = (REPO_ROOT / "infrastructure" / "compose" / "Dockerfile.python").read_text(encoding="utf-8")
    match = re.search(r"--uid (\d+)", dockerfile)
    assert match, "в Dockerfile не нашёлся uid контейнерного пользователя"
    uid = match.group(1)
    for name in ("DEPLOYMENT.md", "ADMIN_GUIDE.md"):
        text = (DOCS / name).read_text(encoding="utf-8")
        assert uid in text, f"{name} не называет uid {uid}, под которым работают образы"


@pytest.mark.parametrize("name", HUMAN_GUIDES)
def test_guides_do_not_promise_absent_capabilities(name: str) -> None:
    """Формулировки, устаревшие после 1.0.3: платформа умеет то, что они отрицают."""
    text = (DOCS / name).read_text(encoding="utf-8")
    forbidden = (
        "не извлекает URL из QR-кодов и office-документов",
        "не извлекает ссылки из office-документов",
    )
    found = [phrase for phrase in forbidden if phrase in text]
    assert not found, f"{name} отрицает возможность, которая реализована: {found}"


# ---------------------------------------------------------------------------------------------
# Этап MSP 1.0.4
# ---------------------------------------------------------------------------------------------
#: Настройки записаны в документах как `MSP_...`. Имя в документе и имя в коде расходятся молча:
#: администратор выставляет переменную, которую никто не читает, и считает, что настроил.
_SETTING = re.compile(r"`(MSP_[A-Z0-9_]+)`|^MSP_([A-Z0-9_]+)=", re.MULTILINE)

#: Имена, которые читает не конфигурация платформы: аргументы сборки образа и ключи
#: ``config.js`` надстройки Outlook. Последние лежат в файле, который редактируется вручную при
#: развёртывании надстройки, и к переменным среды сервиса отношения не имеют.
_NON_SETTINGS = frozenset(
    {
        "MSP_COMMIT_SHA",
        "MSP_EXTRAS",
        "MSP_EXPORT_ENCRYPTION_KEY",
        "MSP_API_BASE",
        "MSP_SECURITY_MAILBOX",
    }
)


def _documented_settings(name: str) -> set[str]:
    text = (DOCS / name).read_text(encoding="utf-8")
    found: set[str] = set()
    for first, second in _SETTING.findall(text):
        value = first or (f"MSP_{second}" if second else "")
        if value:
            found.add(value)
    return found - _NON_SETTINGS


@pytest.mark.parametrize("name", ["ADMIN_GUIDE.md", "DEPLOYMENT.md"])
def test_guides_name_only_settings_that_exist(name: str) -> None:
    """Настройка, которой нет в коде, — это инструкция, выполнение которой ничего не меняет."""
    from msp_api.config import Settings

    known = {f"MSP_{field.upper()}" for field in Settings.model_fields}
    unknown = {value for value in _documented_settings(name) if value not in known}
    assert unknown == set(), f"{name}: настроек не существует: {unknown}"


def test_the_check_of_settings_is_not_vacuous() -> None:
    """Иначе проверка выше проходила бы на пустом множестве."""
    documented = _documented_settings("DEPLOYMENT.md")
    assert len(documented) > 10
    assert "MSP_REAL_FLOW_SHADOW" in documented


def test_deployment_names_the_current_migration_head() -> None:
    """Голова, названная в документе, должна совпадать с той, что в репозитории.

    Иначе администратор, сверяющий состояние базы после обновления, сверяет его с числом из
    прошлого этапа — и расхождение выглядит как поломка там, где поломки нет.
    """
    versions = REPO_ROOT / "apps" / "api" / "msp_api" / "migrations" / "versions"
    revisions: dict[str, str | None] = {}
    for path in versions.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        revision = re.search(r'^revision: str = "([^"]+)"', text, re.MULTILINE)
        down = re.search(r'^down_revision: str \| None = (?:"([^"]+)"|None)', text, re.MULTILINE)
        if revision:
            revisions[revision.group(1)] = down.group(1) if down else None
    assert len(revisions) >= 7, "миграции должны находиться, иначе проверка пустая"

    parents = {value for value in revisions.values() if value}
    heads = set(revisions) - parents
    assert len(heads) == 1, f"у набора миграций должна быть одна голова, найдено: {heads}"

    text = (DOCS / "DEPLOYMENT.md").read_text(encoding="utf-8")
    head = heads.pop()
    assert head in text, f"голова {head} не названа в DEPLOYMENT.md"


@pytest.mark.parametrize(
    "name",
    [
        "REAL_FLOW_VALIDATION.md",
        "REAL_FLOW_PRIVACY.md",
        "QR_PRODUCTION_PROFILE.md",
        "GATEWAY_READINESS.md",
        "ADR_ISOLATED_ATTACHMENT_ANALYSIS.md",
        "ARCHIVE_ANALYSIS_SPIKE.md",
        "PDF_QR_ANALYSIS_SPIKE.md",
    ],
)
def test_the_stage_documents_exist(name: str) -> None:
    assert (DOCS / name).is_file()


def test_the_readiness_document_states_the_same_thresholds_as_the_code() -> None:
    """Порог в документе и порог в коде расходятся молча, а читают именно документ."""
    from msp_api.services.gateway_readiness import MIN_ANALYZED, MIN_REVIEWED

    text = (DOCS / "GATEWAY_READINESS.md").read_text(encoding="utf-8")
    assert f"≥ {MIN_ANALYZED}" in text
    assert f"≥ {MIN_REVIEWED}" in text


def test_the_employee_guide_explains_the_observation_mode() -> None:
    """Сотрудник, перестав получать уведомления, должен понимать, что это режим, а не поломка.

    Без этого объяснения тишина читается как «платформа не работает», и о письмах перестают
    сообщать — то есть пилот теряет ровно тот источник, ради которого он идёт.
    """
    text = (DOCS / "EMPLOYEE_GUIDE.md").read_text(encoding="utf-8")
    assert "режим" in text.lower()
    assert "уведомлений" in text
    assert "сообщить о подозрительном письме по-прежнему нужно" in text.lower()
