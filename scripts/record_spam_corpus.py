"""Прогнать синтетический корпус спама через настоящие Postfix и Rspamd и записать результаты (ТЗ 1.2 §39).

Нужен Docker. Результат — ``datasets/spam/cases.json`` (письма и окружение) и ``datasets/spam/records.json``
(записи самого сканера). Оценка по этим файлам (``scripts/evaluate_spam.py``) от Docker не зависит и
выполняется в CI: прогон на сканере делается при смене версии Rspamd, его конфигурации или корпуса.

    python scripts/record_spam_corpus.py            # поднять стенд, прогнать, убрать
    python scripts/record_spam_corpus.py --reuse DIR   # использовать уже работающий стенд (state.json)
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
for extra in (
    "packages/gateway",
    "packages/antispam",
    "packages/mail-parser",
    "packages/shared-contracts",
    ".",
):
    sys.path.insert(0, str(REPO / extra))

from msp_antispam import corpus  # noqa: E402

from tests.gateway.harness import LAB_RECIPIENTS  # noqa: E402
from tests.spam.harness import OTHER_IP, SENDER_IP, DkimKey, SpamStack, milter_spec  # noqa: E402
from tests.spam.zone import Zone  # noqa: E402

DATASETS = REPO / "datasets" / "spam"


def dns_for(case: corpus.Case, zone: Zone, lists_key: DkimKey | None) -> dict[str, dict[str, object]]:
    ctx = case.context
    ip = SENDER_IP if ctx.client == "authorized" else OTHER_IP
    spf = {
        "pass": f"v=spf1 ip4:{ip} -all",
        "fail": "v=spf1 ip4:192.0.2.1 -all",
        "softfail": "v=spf1 ip4:192.0.2.1 ~all",
        "none": None,
    }[ctx.spf]
    records = zone.records(
        spf=spf, dmarc=_dmarc(ctx.dmarc), dkim=ctx.dkim != "none", sender_ip=ip, ptr=ctx.ptr
    )
    if lists_key is not None:
        records[lists_key.dns_name] = lists_key.dns_record
        records[lists_key.domain] = {"A": ["192.0.2.50"]}
    return records


def _dmarc(policy: str | None) -> str | None:
    return None if policy is None else f"v=DMARC1; p={policy}"


def build(case: corpus.Case, zone: Zone, lists_key: DkimKey | None) -> bytes:
    raw = case.eml(domain=zone.domain).encode("utf-8")
    ctx = case.context
    if ctx.dkim in ("valid", "broken"):
        raw = zone.key.sign(raw, headers=(b"from", b"to", b"subject", b"message-id", b"date"))
        if ctx.dkim == "broken":
            raw = raw.replace(
                case.body.encode("utf-8")[:20], b"[footer] " + case.body.encode("utf-8")[:20], 1
            )
    if ctx.arc and lists_key is not None:
        from dkim import ARC

        message = b"Authentication-Results: lists-hop.com; spf=pass; dkim=pass\r\n" + raw
        raw = (
            b"".join(ARC(message).sign(b"arc1", b"lists-hop.com", lists_key.private_pem, b"lists-hop.com"))
            + message
        )
    return raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reuse", help="каталог со state.json работающего стенда")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    cases = corpus.generate_cases()
    if args.limit:
        cases = cases[: args.limit]
    work = Path(tempfile.mkdtemp(prefix="spamcorpus-"))
    if args.reuse:
        from tests.spam.conftest import _attach

        stack = _attach(Path(args.reuse))
        owned = False
    else:
        stack = SpamStack(work)
        stack.up(milter_spec(), LAB_RECIPIENTS)
        owned = True
    records: dict[str, dict] = {}
    try:
        lists_key = DkimKey.generate("lists-hop.com", "arc1")
        for index, case in enumerate(cases, start=1):
            zone = Zone("co")
            stack.dns.reset()
            stack.dns.records(dns_for(case, zone, lists_key))
            ip = SENDER_IP if case.context.client == "authorized" else OTHER_IP
            helo = {"mail": zone.helo, "ip": f"[{ip}]"}.get(case.context.helo, "evil.example")
            raw = build(case, zone, lists_key)
            result = stack.smtp_from(ip, f"sender@{zone.domain}", ["ivan@corp.example"], raw, helo=helo)
            if not result.get("ok"):
                print(f"[{index}/{len(cases)}] {case.id}: письмо не принято: {result}")
                continue
            message_id = f"{case.id.lower()}@corpus.example"
            try:
                record = stack.scan_for(message_id, timeout=90)
            except TimeoutError:
                print(f"[{index}/{len(cases)}] {case.id}: результат сканера не получен")
                continue
            records[case.id] = record
            print(
                f"[{index}/{len(cases)}] {case.id} {case.category}: score={record.get('score')} action={record.get('action')}"
            )
    finally:
        if owned:
            stack.down()
    meta = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "rspamd_version": next((r.get("_msp", {}).get("rspamd_version") for r in records.values()), ""),
        "config_version": next((r.get("_msp", {}).get("config_version") for r in records.values()), ""),
        "corpus_checksum": corpus.corpus_checksum(cases),
        "cases": len(cases),
        "recorded": len(records),
        "note": "Синтетический корпус: проверка на регрессию, а не оценка качества на реальной почте.",
    }
    DATASETS.mkdir(parents=True, exist_ok=True)
    (DATASETS / "cases.json").write_text(
        json.dumps([corpus.case_to_dict(c) for c in cases], ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8",
    )
    (DATASETS / "records.json").write_text(
        json.dumps({"meta": meta, "records": records}, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(meta, ensure_ascii=False))
    return 0 if len(records) == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
