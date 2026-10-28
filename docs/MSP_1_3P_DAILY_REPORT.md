# MSP 1.3P — ежедневный отчёт смены

**Относится к:** ТЗ MSP 1.3P §20

Отчёт подписывают аналитик и оператор. Числа берутся из платформы, а не из памяти:
`GET /api/v1/pilot/metrics` и `GET /api/v1/pilot/readiness`. **Нет знаменателя — пишется `null`/`UNKNOWN`, не 0 и не «норма».**

## Форма

```text
DATE_UTC:
PHASE: P2 | P3 | P4
OPERATOR:
ANALYST:
REAL_UNIQUE_TOTAL:                       sample.real_unique
REAL_NEW_TODAY:                          прирост sample.real_unique за сутки
REVIEWED_TOTAL:                          sample.real_reviewed
REVIEWED_TODAY:
REJECT_CANDIDATES_REAL:                  controls.<CONTROL>.candidates
REJECT_CANDIDATES_REVIEWED:              controls.<CONTROL>.reviewed
APPLIED_REJECTS/REVIEWED:                applied.applied_rejects / applied.applied_rejects_reviewed
QUARANTINES/REVIEWED:                    applied.applied_quarantines / applied.applied_quarantines_reviewed
CRITICAL_FP:                             critical_fp
OBSERVED_FP_RATE:                        controls.<CONTROL>.statistics.observed_fp_rate   (null без выборки)
WILSON_UPPER_95:                         controls.<CONTROL>.statistics.wilson_upper_95    (null без выборки)
SAMPLE_SIZE:                             controls.<CONTROL>.statistics.sample_size
UNKNOWN/UNSCANNABLE на 1000:             sample.unknown_per_1000 / sample.unscannable_per_1000
BIASED (ящик безопасности) / IMPORTED / DRILLS:   sample.biased_real_security_mailbox / imported_analyst_upload / drills
GATEWAY_CONFLICTS:
QUEUE_DEPTH/OLDEST_AGE:                  не собирается платформой (unavailable) — брать с узла
INGEST_DELAY_P95:                        sample.ingest_delay_p95_seconds
DECISION_P95/P99:                        applied.decision_latency_p95_ms / decision_latency_p99_ms
KILL_SWITCH/ROLLBACK:                    platform.kill_switch_active; события откатов
OPEN_INCIDENTS / OPEN_STOPS:             platform.open_stops, список остановок
BLOCKERS:
NEXT_SHIFT_ACTIONS:
SIGNOFF (роли, не адреса):
```

## Правила заполнения

- Отдельно: реальные, синтетические (лабораторные узлы), импортированные (файлы аналитика), смещённые (ящик безопасности) и учения.
  В `REAL_*` попадают только `JOURNAL_COPY`, `EWS_READONLY` и `GATEWAY_EVIDENCE` без заранее известного ответа.
- `0 ошибок из 0` — не «0 %». `0 из 100` — не «ниже 1 %»: смотри `wilson_upper_95` и `sample_for_zero_failures`.
- Покрытие просмотра применённых отказов и карантина должно быть `1.0`; `null` — отказы ещё не применялись, и это не «выполнено».
- Тела писем, темы и адреса получателей в отчёт не копируются.
- Любой критический ложный — остановка в тот же момент ([MSP_1_3P_PILOT_RUNBOOK.md](MSP_1_3P_PILOT_RUNBOOK.md), раздел F), а не пункт отчёта.
