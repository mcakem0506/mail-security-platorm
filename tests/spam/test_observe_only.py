"""Наблюдение — свойство конфигурации сканера, а не пометка в панели (ТЗ 1.2 §6).

Milter исполняет родное действие Rspamd: reject отклоняет письмо, greylist откладывает его. Поэтому
пороги этих действий недостижимы, а предложение панель считает по оценке и порогам узла.
"""

from __future__ import annotations

from msp_antispam.model import AppliedAction, SuggestedAction
from msp_antispam.rspamd_config import Thresholds

from .harness import build_message, node_config

GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"


def test_the_gtube_test_pattern_is_not_rejected(clean_spam) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    mid = "obs-gtube"
    raw = build_message(mid, "a@example.test", subject="GTUBE", body=GTUBE)
    _, result = spam.send_inbound(mid, raw=raw)
    assert result.get("ok"), result
    assert spam.delivered(mid) is not None, spam.rspamd_log()


def test_a_score_above_the_advisory_reject_threshold_is_suggested_but_not_applied(clean_spam) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    outcome = spam.reapply_rspamd(
        node_config(thresholds=Thresholds(greylist=0.1, add_header=0.2, reject=0.3))
    )
    assert outcome.get("outcome") == "ACTIVE", outcome
    mid = "obs-advisory"
    raw = build_message(
        mid, "a@example.test", subject="Срочно!!! Выигрыш", body="Только сегодня, получите приз"
    )
    _, result = spam.send_inbound(mid, raw=raw)
    assert result.get("ok"), result
    assert spam.delivered(mid) is not None, spam.rspamd_log()
    analysis = spam.analysis(mid)
    assert analysis.suggested_action is SuggestedAction.REJECT
    assert analysis.applied_action is AppliedAction.OBSERVE_ONLY
