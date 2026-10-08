"""Класс, которого нет в таблице стилей, — это неоформленный текст без ошибки сборки.

Повод для этого теста практический: страница реального потока была написана с классами
``metric``, ``alert--error`` и ``badge--ok``, которых в ``styles.css`` нет. TypeScript такого не
видит, сборка проходит, тест монтирования проходит — а страница выглядит как список абзацев.
Ошибка обнаруживается только глазами, и только если кто-то откроет именно эту страницу.

Тест проверяет обратное направление отдельно и намеренно не проверяет: неиспользуемый класс в
таблице стилей — это мёртвый код, а не поломка интерфейса, и запрет на него заставлял бы удалять
заготовки оформления.
"""

from __future__ import annotations

import pathlib
import re

CONSOLE = pathlib.Path("apps/security-console/src")
STYLES = CONSOLE / "styles.css"

#: Классы, которые задаёт не таблица стилей проекта: их рисует браузер или сторонняя разметка.
_EXTERNAL: frozenset[str] = frozenset()


def _declared_classes() -> set[str]:
    text = STYLES.read_text(encoding="utf-8")
    # Отбрасываем содержимое строк и значений, чтобы не принять `content: ".x"` за селектор.
    return set(re.findall(r"\.(-?[_a-zA-Z][\w-]*)", text))


def _used_classes() -> dict[str, set[str]]:
    """Классы из ``className="..."`` по файлам.

    Разбираются только литеральные строки. Классы, собранные из переменных (например словарь
    состояний), в литералах всё равно присутствуют целиком — в проекте так и написано, — а те,
    что собираются конкатенацией, тест пропустит. Это ограничение, а не дыра: он находит
    опечатку и выдуманное имя, то есть ровно те два случая, из-за которых он появился.
    """
    used: dict[str, set[str]] = {}
    pattern = re.compile(r'className=(?:"([^"]*)"|\{"([^"]*)"\})')
    literal_in_record = re.compile(r'^\s*[A-Za-z_0-9]+:\s*"([a-z][a-z0-9_ -]*)",?\s*$')
    for path in sorted(CONSOLE.rglob("*.tsx")):
        names: set[str] = set()
        text = path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            value = match.group(1) or match.group(2) or ""
            names.update(part for part in value.split() if part)
        # Словари вида `{ READY: "badge badge--approved" }`: классы живут в значениях, и без них
        # проверка не увидела бы как раз те имена, которые проще всего выдумать.
        for line in text.splitlines():
            found = literal_in_record.match(line)
            if found and ("badge" in found.group(1) or "tile" in found.group(1)):
                names.update(found.group(1).split())
        if names:
            used[str(path)] = names
    return used


def test_the_stylesheet_is_readable_and_not_empty() -> None:
    """Проверка самой проверки: пустой набор селекторов прошёл бы все тесты ниже."""
    declared = _declared_classes()
    assert len(declared) > 50, "таблица стилей должна разбираться, иначе проверки пустые"
    assert {"page", "card", "table", "muted"} <= declared


def test_pages_use_classes_that_exist() -> None:
    declared = _declared_classes() | _EXTERNAL
    unknown: dict[str, set[str]] = {}
    for path, names in _used_classes().items():
        missing = {name for name in names if name not in declared}
        if missing:
            unknown[path] = missing
    assert unknown == {}, f"классы без оформления: {unknown}"


def test_the_check_would_catch_an_invented_class() -> None:
    """Иначе тест выше мог бы проходить потому, что он ничего не сравнивает."""
    declared = _declared_classes()
    assert "metric__value" not in declared, "имя из первой версии страницы и не должно появиться"
    assert "tile__value" in declared, "а используемое — должно"


def test_every_page_is_reachable_from_the_navigation() -> None:
    """Страница, на которую нет ссылки, существует только в маршрутизаторе.

    Файл страницы, не упомянутый в ``App.tsx``, — это работа, которую никто не увидит. Отдельного
    способа это заметить нет: сборка и типы к навигации равнодушны.
    """
    app = (CONSOLE / "App.tsx").read_text(encoding="utf-8")
    pages = {path.stem for path in (CONSOLE / "pages").glob("*.tsx")}
    # Экран входа не в навигации намеренно: до него доходят не по ссылке.
    pages.discard("LoginPage")
    missing = {name for name in pages if name not in app}
    assert missing == set(), f"страницы без маршрута: {missing}"
