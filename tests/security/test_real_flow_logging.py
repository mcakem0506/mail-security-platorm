"""Тело письма реального потока не попадает в журналы (ТЗ 1.0.4 §22, §27).

Запрет прямой: body in logs, raw MIME in error text. Проверяется он здесь двумя способами,
потому что одного мало.

Первый — поведенческий: прогнать приём и разбор письма с узнаваемыми строками в теме, тексте и
адресах, перехватив **всё**, что платформа записала, и убедиться, что ни одной из этих строк там
нет. Так ловится то, что попало в журнал через поле, о котором никто не думал.

Второй — по исходнику: ни один вызов журналирования в модулях реального потока не передаёт
объект письма или его тело целиком. Так ловится то, что в этом прогоне не записалось, а
запишется при другом стечении обстоятельств — например, в обработчике ошибки, до которого тест
не дошёл.
"""

from __future__ import annotations

import ast
import logging
import pathlib

import pytest
from msp_api.services import real_flow
from msp_contracts import AnalystClassification, RiskLevel, ValidationSource

MODULES = (
    pathlib.Path("apps/api/msp_api/services/real_flow.py"),
    pathlib.Path("apps/api/msp_api/services/corpus_promotion.py"),
    pathlib.Path("packages/mail-parser/msp_mail_parser/anonymize.py"),
)

#: Строки, которых в журналах быть не должно. Составлены из обычных слов, а не из набора
#: символов с цифрами: сканер секретов принимает за ключ любую строку, похожую на пароль, и
#: первая версия этих маркеров остановила сборку. Уникальность при этом сохранена — сочетание
#: слов, которого нет ни в одном сообщении платформы, — и проверяется отдельным тестом.
MARKER_SUBJECT = "lunar-giraffe-subject"
MARKER_BODY = "amber-walrus-body"
MARKER_LOCAL = "quartz.heron.ivanov"
MARKER_ORG = "cobalt-otter-org"
ALL_MARKERS = (MARKER_SUBJECT, MARKER_BODY, MARKER_LOCAL, MARKER_ORG)


@pytest.fixture
def captured(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    """Перехват на корневом логгере: интересует всё, что записала платформа, а не один модуль."""
    caplog.set_level(logging.DEBUG)
    return caplog


def _run_the_whole_path(db, organization) -> None:  # type: ignore[no-untyped-def]
    """Приём, разбор, сводка, нагрузка правил, очередь — всё, что пишет в журнал."""
    record, _ = real_flow.ingest(
        db,
        real_flow.IngestRequest(
            organization_id=organization.id,
            source=ValidationSource.SECURITY_MAILBOX,
            message_fingerprint="log-fp-1",
            production_verdict=RiskLevel.HIGH_RISK,
            triggered_rules=["SND-024"],
            sampling_reasons=["HIGH_RISK"],
            # Поля, в которые естественнее всего затечь содержимому письма.
            anonymization_report={
                "subject_seen": MARKER_SUBJECT,
                "local_parts": 3,
            },
            unscannable_reasons=[f"ENCRYPTED: {MARKER_BODY}"],
        ),
    )
    real_flow.review(
        db,
        record=record,
        classification=AnalystClassification.FALSE_POSITIVE,
        analyst=f"{MARKER_LOCAL}@corp.example",
        comment=f"{MARKER_BODY} — рассылка {MARKER_ORG}",
    )
    db.commit()

    real_flow.summary(db, organization.id)
    real_flow.rule_pressure(db, organization.id)
    real_flow.uncertain_queue(db, organization.id)
    real_flow.expired_raw_records(db, organization.id)
    real_flow.count_by_source(db, organization.id)


class TestTheMarkersAreDistinguishable:
    """Иначе «маркера нет в журнале» ничего не доказывает."""

    def test_no_marker_occurs_in_the_platform_itself(self) -> None:
        """Маркер, встречающийся в исходниках платформы, мог бы попасть в журнал и сам по себе,
        и тест на его отсутствие падал бы на верном коде либо молчал бы на неверном."""
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for root in (pathlib.Path("apps/api/msp_api"), pathlib.Path("packages"))
            for path in root.rglob("*.py")
        )
        assert len(sources) > 100_000, "исходники должны находиться, иначе проверка пустая"
        for marker in ALL_MARKERS:
            assert marker not in sources, f"маркер {marker} встречается в самой платформе"

    def test_the_markers_do_not_look_like_secrets(self) -> None:
        """Именно то, из-за чего эта проверка появилась: сканер остановил сборку на маркерах."""
        for marker in ALL_MARKERS:
            assert not any(character.isdigit() for character in marker), marker


class TestNothingFromTheMessageReachesTheLog:
    def test_the_subject_and_body_are_absent(self, db, organization, captured) -> None:  # type: ignore[no-untyped-def]
        _run_the_whole_path(db, organization)
        written = "\n".join(record.getMessage() for record in captured.records)
        extras = "\n".join(
            str(getattr(record, key, ""))
            for record in captured.records
            for key in ("source", "reasons", "case_id", "rule_id", "verdict", "dataset_version")
        )
        haystack = f"{written}\n{extras}"
        assert MARKER_SUBJECT not in haystack
        assert MARKER_BODY not in haystack

    def test_the_analyst_comment_is_absent(self, db, organization, captured) -> None:  # type: ignore[no-untyped-def]
        """Комментарий аналитика — пересказ письма своими словами, и он тоже не для журнала."""
        _run_the_whole_path(db, organization)
        written = "\n".join(record.getMessage() for record in captured.records)
        assert MARKER_ORG not in written

    def test_the_local_part_of_an_address_is_absent(self, db, organization, captured) -> None:  # type: ignore[no-untyped-def]
        """Адрес аналитика — персональные данные сотрудника, а не идентификатор события."""
        _run_the_whole_path(db, organization)
        written = "\n".join(record.getMessage() for record in captured.records)
        assert MARKER_LOCAL not in written

    def test_something_was_actually_logged(self, db, organization, captured) -> None:  # type: ignore[no-untyped-def]
        """Проверка самой проверки: при пустом журнале все утверждения выше бессодержательны."""
        _run_the_whole_path(db, organization)
        messages = [record.getMessage() for record in captured.records]
        assert messages, "модуль обязан что-то записывать, иначе проверять нечего"
        assert any("real_flow" in message for message in messages)


class TestNoLogCallPassesTheMessageItself:
    """Проверка по исходнику: ловит то, что запишется при другом стечении обстоятельств."""

    #: Объекты, переданные в журнал целиком: письмо, его разбор, его запись. Запрещены как
    #: аргумент, но **не** как основание обращения к полю: ``record.promotion_case_id`` — это
    #: номер разбора, а не письмо, и проверка, ругающаяся на него, стала бы шумом.
    FORBIDDEN_OBJECTS = frozenset({"record", "msg", "message", "raw", "parsed", "request"})

    #: Поля с содержимым письма. Запрещены всегда, у любого объекта: само имя поля и означает,
    #: что внутри лежит то, чего в журнале быть не должно.
    FORBIDDEN_FIELDS = frozenset(
        {
            "raw",
            "body",
            "subject",
            "text",
            "payload",
            "anonymization_report",
            "review_comment",
            "comment",
            "note",
        }
    )

    def _log_calls(self, path: pathlib.Path) -> list[ast.Call]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls: list[ast.Call] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in ("debug", "info", "warning", "error", "exception", "critical"):
                continue
            target = node.func.value
            if isinstance(target, ast.Name) and target.id in ("logger", "logging", "log"):
                calls.append(node)
        return calls

    def test_the_source_scan_finds_the_log_calls(self) -> None:
        """Иначе проверка ниже проходит потому, что ей нечего разбирать."""
        total = sum(len(self._log_calls(path)) for path in MODULES)
        assert total >= 3, f"вызовов журналирования должно находиться больше: {total}"

    def _offending_names(self, node: ast.AST) -> set[str]:
        """Что именно передаётся в журнал этим выражением.

        Обход ручной, а не ``ast.walk``: нужно различать ``record`` переданное целиком и
        ``record`` как основание обращения к полю, а ``walk`` эту разницу теряет.
        """
        found: set[str] = set()
        if isinstance(node, ast.Attribute):
            if node.attr in self.FORBIDDEN_FIELDS:
                found.add(node.attr)
            # Основание не проверяется как объект: поле у него уже взято.
            found |= self._offending_names_of_base(node.value)
            return found
        if isinstance(node, ast.Name):
            if node.id in self.FORBIDDEN_OBJECTS:
                found.add(node.id)
            return found
        for child in ast.iter_child_nodes(node):
            found |= self._offending_names(child)
        return found

    def _offending_names_of_base(self, node: ast.AST) -> set[str]:
        """У основания обращения проверяются только поля, не само имя."""
        if isinstance(node, ast.Name):
            return set()
        return self._offending_names(node)

    @pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
    def test_no_log_call_passes_a_message_object(self, path: pathlib.Path) -> None:
        offenders: list[str] = []
        for call in self._log_calls(path):
            found: set[str] = set()
            for argument in call.args:
                found |= self._offending_names(argument)
            for keyword in call.keywords:
                found |= self._offending_names(keyword.value)
            if found:
                offenders.append(f"{path.name}:{call.lineno} → {sorted(found)}")
        assert offenders == [], f"в журнал передаётся письмо или его части: {offenders}"

    @pytest.mark.parametrize(
        ("code", "caught"),
        [
            # Поле с содержимым — нарушение, даже у безобидно названного объекта.
            ('logger.info("x", extra={"body": item.body})', True),
            ('logger.info("x", extra={"c": item.review_comment})', True),
            # Объект целиком — нарушение.
            ('logger.info("x", extra={"m": record})', True),
            ('logger.warning("x %s", msg)', True),
            # Безобидное поле у объекта — не нарушение. Первая версия проверки ругалась здесь,
            # и такая проверка была бы отключена первым же, кому помешала.
            ('logger.info("x", extra={"case_id": record.promotion_case_id})', False),
            ('logger.info("x", extra={"rule_id": review.rule_id})', False),
            ('logger.info("x", extra={"source": request.source.value})', False),
        ],
    )
    def test_the_scan_catches_what_it_should_and_nothing_else(self, code: str, caught: bool) -> None:
        """Проверка самой проверки — в обе стороны.

        Одного примера нарушения мало: проверка, срабатывающая на всём, так же бесполезна, как
        не срабатывающая ни на чём, и отличить их можно только отрицательными случаями.
        """
        tree = ast.parse(code + "\n")
        call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
        found: set[str] = set()
        for argument in call.args:
            found |= self._offending_names(argument)
        for keyword in call.keywords:
            found |= self._offending_names(keyword.value)
        assert bool(found) is caught, f"{code} → {sorted(found)}"
