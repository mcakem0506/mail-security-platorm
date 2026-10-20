# Приёмка MSP 1.2 — анти-спам, аутентификация и репутация

> **MSP 1.2 IS NOT APPROVED FOR PRODUCTION MX CUTOVER.**
> Этап добавляет сканер Rspamd в теневом режиме, проверки SPF/DKIM/DMARC/ARC, репутацию и подпись DKIM лабораторного
> домена. Это не «готовый к боевой почте шлюз». Принуждения нет ни в одном режиме.

## Решение

**READY_WITH_WARNINGS** для перехода к MSP 1.3 (лабораторная и теневая эксплуатация). К боевому переключению MX
решение **не** относится.

## Отчёт по §49

```text
PHASE: MSP 1.2
BASE_SHA: f6de230 (ветка msp-1-1-gateway-foundation; PR #4 не влит, поэтому ветка 1.2 создана от неё, а не от main)
FINAL_SHA: вершина ветки msp-1-2-anti-spam-auth-reputation (указана в PR)
RSPAMD_VERSION: 3.12.1 (Debian trixie)
POSTFIX_VERSION: 3.10.13
TESTS: офлайн unit/security/integration/e2e — 0 провалов; живой стенд tests/spam — 103 из 104 в общем
       прогоне (упавший тест проходит отдельно, 8 из 8), плюс tests/spam/test_observe_only.py — 2 из 2
CI: 11 новых заданий добавлены в .github/workflows/ci.yml; результат будет в PR (на GitHub ещё не запускались)
SPF: Rspamd; матрица на стенде tests/spam/test_spf.py; отличие от RFC 7208 §4.6 — GAP-005
DKIM: Rspamd; tests/spam/test_dkim.py (подделка тела, две подписи, отсутствие ключа, сбой DNS)
DMARC_RFC9989: Rspamd реализует RFC 7489, не RFC 9989 (нет поиска по дереву, np, t) — GAP-006; tests/spam/test_dmarc.py
ARC: Rspamd; tests/spam/test_arc.py
RBL_PROVIDERS: рамка провайдеров и зона стенда rbl.lab.test; публичных зон не включено
RBL_LICENSE_STATUS: ни один публичный провайдер не одобрен; без допуска и четырёх глаз — DISABLED_BY_POLICY
SPAM_CORPUS: 127 синтетических примеров (datasets/spam), записаны через настоящий Rspamd 3.12.1; контрольная сумма в baseline.json
SPAM_PRECISION: 1.000 (синтетика)
SPAM_RECALL: 0.833 (синтетика; пропущены SPC-CLAS-004, SPC-CLAS-010)
SUGGESTED_REJECT_FP_RATE: 0 из 1 предложения на синтетике — не доказательство; на реальном потоке не измерено
BAYES_STATE: NOT_TRAINED, автообучение выключено
DKIM_SIGNING: работает для лабораторного домена; подпись проверена независимой программой (dkimpy); только доверенный путь
DKIM_SELECTOR: задаётся при создании ключа; ротация проверена (tests/spam/test_dkim_signing.py)
RSPAMD_FAILOPEN: подтверждено на стенде: остановка, зависание, потеря Redis, плохая конфигурация (tests/spam/test_failopen.py)
DNS_FAILURE_TEST: подтверждено: сбой DNS даёт TEMPERROR, не FAIL; доставка продолжается
REDIS_FAILURE_TEST: подтверждено: потеря Redis не останавливает сканирование и доставку
REAL_FLOW_SAMPLE: нет — боевое переключение MX не выполнялось
KNOWN_WARNINGS: см. ниже
OPEN_GAPS: GAP-003, GAP-004, GAP-005, GAP-006 в состоянии VALIDATION; GAP-001, GAP-002 — как в 1.0.4
DECISION: READY_WITH_WARNINGS
```

## Что реализовано и чем подтверждено

| Область | Статус | Подтверждение |
|---|---|---|
| Rspamd как Milter, `milter_default_action=accept`, два направления по слушателю | реализовано | `tests/spam/test_milter_smoke.py`, `test_gateway_milter.py` |
| Наблюдение как свойство конфигурации сканера | реализовано (найдено и исправлено в этом этапе) | `tests/spam/test_observe_only.py`, `test_antispam_config.py`, эталон `infrastructure/rspamd/reference` |
| SPF, DKIM, DMARC, ARC, доверенный `Authentication-Results`, конфликты | реализовано | `tests/spam/test_{spf,dkim,dmarc,arc,trust_and_helo}.py`, `tests/unit/test_antispam_auth.py` |
| Класс спама отдельно от вердикта безопасности; отображение символов; факты и правила ASP-001..008 | реализовано | `test_antispam_core.py`, `test_antispam_analysis.py` |
| Провайдеры репутации: лицензия, четыре глаза, приватность | реализовано | `test_rbl.py`, `test_antispam_e2e.py::TestProviders` |
| Репутация IP и доменов, зрелость отправителя, HELO/PTR, BULK, Bayes `NOT_TRAINED` | реализовано | `test_antispam_core.py`, `test_trust_and_helo.py` |
| Подпись DKIM, жизненный цикл ключей, ротация | реализовано | `test_dkim_signing.py`, `test_panel_antispam.py` |
| Политика, кандидаты, симулятор (без `ACTIVE_ENFORCING`) | реализовано | `test_antispam_e2e.py` |
| Выпуск конфигурации сканера с откатом и дрейфом | реализовано | `test_antispam_config.py`, `test_failopen.py` |
| Метрики, тревоги, страница консоли, права, аудит | реализовано | `test_alerts.py`, `test_antispam_alerts.py`, `AntispamPage.tsx` |
| Проверка на реальном потоке: очереди просмотра, метрики, `reject_safety` | реализовано, данных нет | `SPAM_REAL_FLOW_VALIDATION.md` |
| Корпус, гейт регрессии | реализовано | `datasets/spam`, `scripts/evaluate_spam.py`, `test_antispam_corpus.py` |
| Документы §46, обновления, модель угроз §47 | реализовано | `docs/` |

## Предупреждения и честные отклонения

1. **Ветка 1.2 создана от ветки 1.1**, потому что PR #4 не влит. После его слияния потребуется перенос (rebase) на `main`.
2. **Реального потока нет.** Качество спам-оценки, доля ложных срабатываний и предложенных отказов на настоящей почте не
   измерены; `reject_safety.ready_for_discussion = false`. Корпус синтетический и защищает только от регрессий.
3. **Найденный и исправленный дефект.** Milter исполняет родные действия Rspamd: GTUBE получал `554`, а метка
   `OBSERVE_ONLY` в панели этого не отражала. Теперь пороги `reject/add_header/greylist` недостижимы, шаблон GTUBE выключен,
   предложение считается панелью по порогам узла. Первая версия исправления использовала равные пороги, и Rspamd
   отбрасывал блок как неверный; пороги теперь строго упорядочены.
4. **Rspamd расходится с RFC:** неверный механизм SPF не даёт `permerror` (GAP-005); DMARC по RFC 7489, без дерева доменов,
   `np` и `t` (GAP-006).
5. **Нестабильность общего прогона стенда:** `test_the_shadow_copy_enriches_the_record_with_the_helo_and_the_chain`
   упал один раз в полном прогоне `tests/spam` (таймаут 150 с на обогащение), отдельно проходит 8 из 8. Причина не
   установлена; в CI модули запускаются отдельными заданиями.
6. **Полнота синтетического корпуса:** полнота 0,833 — два примера классического спама ниже порога. Пересылка (`forwarding`)
   получает `SUSPECTED_SPAM`, но не `SPAM`. Легитимные письма (транзакционные, рассылки, сломанная аутентификация) спамом
   не признаны.
7. Общий токен узла; узлы не резервируют друг друга; нагрузочная способность боевой установки не проверялась.
8. Проверка запросов к публичным RBL требует решения организации о лицензиях; по умолчанию все такие провайдеры выключены.

## Не реализовано намеренно

Отказ, удаление, карантин, greylisting и postscreen в работе; автообучение Bayes; подпись любых доменов, кроме
лабораторного или пилотного; автоматическое изменение DNS/MX; ключ, включающий принуждение, не существует
([POSTSCREEN_EVALUATION.md](POSTSCREEN_EVALUATION.md)).

## Что нужно до рассмотрения боевого переключения

Набор реальной почты в теневом режиме и выполнение обязательных просмотров; измеренные ложные срабатывания
(`reject_safety`); решение о лицензиях провайдеров; подтверждение GAP-003..006; отдельные токены компонентов узла;
высокая доступность; регламент отката ([GATEWAY_ROLLBACK.md](GATEWAY_ROLLBACK.md)).

## Результаты прогона

Windows 11, Docker, Python 3.13:

* `tests/spam` (`MSP_GATEWAY_TESTS=1`, живые Postfix + Rspamd): общий прогон 103 из 104, упавший тест — п. 5 выше;
  `test_observe_only.py` 2 из 2; `test_panel_antispam.py` отдельно 8 из 8.
* Корпус: 127 из 127 записано, гейт `scripts/evaluate_spam.py --gate` пройден.
* `ruff`, `ruff format`, `mypy packages apps/api/msp_api apps/worker providers` — без замечаний.
* `tests/unit tests/security tests/integration tests/e2e`: все проверки пройдены (код возврата 0, без провалов); Linux-зависимые проверки пропускаются и выполняются в CI.
