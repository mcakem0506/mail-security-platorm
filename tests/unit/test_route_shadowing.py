"""No literal route may share its shape with an earlier parameterised one.

Found the hard way. ``GET /campaigns/{campaign_id}`` is declared in the incidents router, which
``create_app`` includes before the detection router, so ``GET /campaigns/match-quality`` and
``GET /campaigns/merge-suggestions`` never ran: the router matched the first pattern, read
"match-quality" as a campaign id and answered 404 «Кампания не найдена». Nothing failed loudly —
the console simply showed an empty panel, which is the one failure mode this platform is not
allowed to have.

The check is written over the whole path table rather than over the two known paths, because the
same mistake is one `@router.get` away at any time. It is deliberately strict: a literal path
that another pattern can also match is ambiguous even where the framework happens to resolve it
the way the author intended, and ambiguous routing is not something to ship and hope about.

The table comes from the OpenAPI document, not from ``app.routes``: this FastAPI version wraps
each included router in an opaque object, so walking ``app.routes`` sees four routes out of
sixty-odd — which is how the first version of this test passed while the bug was live.
"""

from __future__ import annotations

import re

#: ``{name}`` or ``{name:converter}`` in a path template.
_PARAM = re.compile(r"\{[^}]+\}")


def _segments(path: str) -> list[str]:
    return [segment for segment in path.split("/") if segment]


def _shadows(pattern: str, literal: str) -> bool:
    """True when a request for ``literal`` can also be matched by ``pattern``."""
    left, right = _segments(pattern), _segments(literal)
    if len(left) != len(right):
        return False
    return all(_PARAM.fullmatch(a) is not None or a == b for a, b in zip(left, right, strict=True))


def _path_table() -> list[tuple[str, str]]:
    from msp_api.config import get_settings
    from msp_api.main import create_app

    document = create_app(get_settings()).openapi()
    return [
        (path, method.upper())
        for path, operations in document["paths"].items()
        for method in operations
        if method.upper() not in {"HEAD", "OPTIONS"}
    ]


def test_no_endpoint_is_ambiguous() -> None:
    routes = _path_table()
    assert len(routes) > 50, f"таблица маршрутов собрана не полностью: {len(routes)}"

    ambiguous: list[str] = []
    for index, (path, method) in enumerate(routes):
        if _PARAM.search(path):
            continue  # a parameterised path is the shadow, never the victim
        for earlier_path, earlier_method in routes[:index]:
            if earlier_method == method and _shadows(earlier_path, path):
                ambiguous.append(f"{method} {path} перекрыт {earlier_method} {earlier_path}")

    assert ambiguous == [], "неоднозначные маршруты: " + "; ".join(ambiguous)


def test_the_helper_recognises_the_case_that_caused_this_test() -> None:
    """Guards the guard: a comparison that always returned False would pass the test above."""
    assert _shadows("/campaigns/{campaign_id}", "/campaigns/match-quality")
    assert not _shadows("/campaigns/{campaign_id}", "/campaigns/{campaign_id}/merge")
    assert not _shadows("/campaigns/{campaign_id}/merge", "/campaigns/match-quality")
    assert not _shadows("/detection/rules/{rule_id}", "/detection/gaps")
