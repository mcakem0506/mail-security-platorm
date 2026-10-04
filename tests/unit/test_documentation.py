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
