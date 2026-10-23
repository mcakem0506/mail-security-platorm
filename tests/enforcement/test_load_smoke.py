"""Нагрузочная проверка: наблюдение (1.2) против канарейки (1.3) (ТЗ 1.3 §77).

Профиль: параллельные SMTP-сессии, пачка почты со спамом, законные письма рядом. Проверяется не пропускная способность боевой
установки, а три свойства: ни одно письмо не потеряно, отказы есть только у получателей в области, задержка приёма в канарейке
отличается от наблюдения на ограниченную величину.
"""

from __future__ import annotations

import dataclasses
import json
import statistics
import time

import pytest

from tests.gateway.harness import docker
from tests.spam.harness import OTHER_IP, SENDER_IP
from tests.spam.zone import Zone

from .harness import (
    BASE,
    CANARY_RCPT,
    OTHER_RCPT,
    activate,
    build_case,
    decisions,
    dns_for,
    make_ready,
    pause,
)

CONCURRENCY = 25
SPAM_TO_CANARY = 30
SPAM_TO_OTHER = 15
LEGIT_TO_CANARY = 15

SCRIPT = (
    """
import json, smtplib, sys, threading, time
items = json.loads(sys.stdin.read())
results = [None] * len(items)
lock = threading.Lock()
queue = list(range(len(items)))

def worker():
    while True:
        with lock:
            if not queue:
                return
            index = queue.pop()
        item = items[index]
        started = time.monotonic()
        out = {"i": index, "ok": False}
        try:
            c = smtplib.SMTP("gateway-postfix", 25, timeout=90, local_hostname=item["helo"])
            c.ehlo(item["helo"])
            c.sendmail(item["from"], item["rcpts"], bytes.fromhex(item["raw"]))
            out["ok"] = True
            c.quit()
        except smtplib.SMTPResponseException as e:
            out.update(code=e.smtp_code)
        except Exception as e:
            out.update(error=type(e).__name__)
        out["seconds"] = time.monotonic() - started
        results[index] = out

threads = [threading.Thread(target=worker) for _ in range(%d)]
[t.start() for t in threads]
[t.join() for t in threads]
print(json.dumps(results))
"""
    % CONCURRENCY
)


def build_items(lab, tag: str):  # type: ignore[no-untyped-def]
    spam_zone, legit_zone = Zone(f"{tag}s"), Zone(f"{tag}l")
    phishing = lab.case("phishing", 1)
    legit = lab.case("transactional", 1)
    lab.dns.reset()
    records = dns_for(phishing, spam_zone, None)
    records.update(dns_for(legit, legit_zone, None))
    lab.dns.records(records)
    items = []

    def add(case, zone, rcpt, kind, index):  # type: ignore[no-untyped-def]
        unique = dataclasses.replace(case, id=f"{case.id}-{tag}-{kind}-{index}")
        raw = build_case(unique, zone, None)
        ip = SENDER_IP if unique.context.client == "authorized" else OTHER_IP
        items.append(
            {
                "kind": kind,
                "ip": ip,
                "rcpts": [rcpt],
                "raw": raw.hex(),
                "from": f"sender@{zone.domain}",
                "helo": zone.helo,
                "message_id": f"{unique.id.lower()}@corpus.example",
            }
        )

    for i in range(SPAM_TO_CANARY):
        add(phishing, spam_zone, CANARY_RCPT, "spam_canary", i)
    for i in range(SPAM_TO_OTHER):
        add(phishing, spam_zone, OTHER_RCPT, "spam_other", i)
    for i in range(LEGIT_TO_CANARY):
        add(legit, legit_zone, CANARY_RCPT, "legit_canary", i)
    return items


def burst(lab, items):  # type: ignore[no-untyped-def]
    """Отправка группами по адресу источника: адрес задаёт контейнер клиента."""
    results = []
    for ip in sorted({i["ip"] for i in items}):
        part = [i for i in items if i["ip"] == ip]
        run = docker(
            "run",
            "--rm",
            "-i",
            "--network",
            lab.network,
            "--ip",
            ip,
            "msp-gateway-tools:test",
            "python",
            "-c",
            SCRIPT,
            input_text=json.dumps(part),
            check=False,
            timeout=600,
        )
        out = json.loads(run.stdout.strip().splitlines()[-1])
        results.extend({**part[r["i"]], **r} for r in out)
    return results


def summarize(results):  # type: ignore[no-untyped-def]
    by = {}
    for r in results:
        by.setdefault(r["kind"], []).append(r)
    return by


class TestLoad:
    def test_1_shadow_baseline_loses_nothing(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        started = time.monotonic()
        results = burst(lab, build_items(lab, "b1"))
        TestLoad.baseline = {
            "seconds": time.monotonic() - started,
            "mean": statistics.mean(r["seconds"] for r in results),
            "p95": sorted(r["seconds"] for r in results)[int(len(results) * 0.95) - 1],
        }
        assert all(r["ok"] for r in results), [r for r in results if not r["ok"]][:3]
        for r in results:
            assert lab.exchange1.wait_for(f"<{r['message_id']}>", timeout=120) or lab.exchange2.wait_for(
                f"<{r['message_id']}>", timeout=2
            ), r["message_id"]

    def test_2_canary_rejects_only_the_canary_spam_and_loses_nothing(self, lab, admin, admin2) -> None:  # type: ignore[no-untyped-def]
        make_ready(lab, admin, "SPAM_REJECT")
        activate(
            lab,
            admin,
            admin2,
            "SPAM_REJECT",
            scope={"recipients": [CANARY_RCPT]},
            thresholds={"reject_score": 12.0},
        )
        started = time.monotonic()
        results = burst(lab, build_items(lab, "c1"))
        by = summarize(results)
        canary = {
            "seconds": time.monotonic() - started,
            "mean": statistics.mean(r["seconds"] for r in results),
            "p95": sorted(r["seconds"] for r in results)[int(len(results) * 0.95) - 1],
        }
        # Спам получателям канарейки — общий 5xx; всё остальное принято без ошибок.
        assert all((not r["ok"]) and str(r.get("code", "")).startswith("5") for r in by["spam_canary"]), by[
            "spam_canary"
        ][:3]
        assert all(r["ok"] for r in by["spam_other"] + by["legit_canary"]), [
            r for r in by["spam_other"] + by["legit_canary"] if not r["ok"]
        ][:3]
        # Принятые письма доставлены, отказанные — нет, потерь нет.
        for r in by["spam_other"] + by["legit_canary"]:
            assert lab.exchange1.wait_for(f"<{r['message_id']}>", timeout=120) or lab.exchange2.wait_for(
                f"<{r['message_id']}>", timeout=2
            ), r["message_id"]
        delivered_ids = set(lab.exchange1.message_ids()) | set(lab.exchange2.message_ids())
        assert not any(f"<{r['message_id']}>" in delivered_ids for r in by["spam_canary"])
        # Задержка приёма в канарейке отличается от наблюдения на ограниченную величину (стенд, не боевая нагрузка).
        assert canary["mean"] < TestLoad.baseline["mean"] + 5.0, (canary, TestLoad.baseline)
        lab.wait_until(
            lambda: (
                sum(
                    1 for d in decisions(admin, control="SPAM_REJECT") if d["applied_action"] == "SMTP_REJECT"
                )
                >= SPAM_TO_CANARY
            ),
            timeout=90,
            what="все отказы дошли до журнала панели",
        )
        rejects = [d for d in decisions(admin, control="SPAM_REJECT") if d["applied_action"] == "SMTP_REJECT"]
        assert all(d["evidence_ids"] and d["policy_version"] for d in rejects)
        p95 = sorted(d["latency_ms"] for d in rejects)[int(len(rejects) * 0.95) - 1]
        assert p95 < 1500, f"p95 задержки решения {p95:.0f} мс"
        TestLoad.canary = canary

    def test_3_the_measurements_are_recorded_for_the_acceptance(self, lab) -> None:  # type: ignore[no-untyped-def]
        print(
            "LOAD_RESULT",
            json.dumps(
                {
                    "shadow": TestLoad.baseline,
                    "canary": TestLoad.canary,
                    "sessions": CONCURRENCY,
                    "messages": SPAM_TO_CANARY + SPAM_TO_OTHER + LEGIT_TO_CANARY,
                }
            ),
        )


@pytest.fixture(scope="module", autouse=True)
def _restore(enf, admin):  # type: ignore[no-untyped-def]
    yield
    try:
        pause(enf, admin, "SPAM_REJECT")
    except Exception:
        pass
    _ = BASE
