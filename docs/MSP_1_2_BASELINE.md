# MSP 1.2 — исходное состояние (baseline)

Зафиксировано перед началом этапа MSP 1.2 (ТЗ §1). Ветка этапа: `msp-1-2-anti-spam-auth-reputation`.

> **MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER.** MSP 1.2 — лабораторный / теневой этап: ничего
> не отклоняется, не удаляется и не помещается в карантин.

## Отклонение от предусловий §1

| Предусловие | Состояние |
|---|---|
| 1. merge `msp-1-1-gateway-foundation` в `main` | **не выполнено**: PR [#4](https://github.com/mcakem0506/mail-security-platorm/pull/4) открыт, CI зелёный (27/27), слияния нет — оно требует отдельного решения владельца. Ветка 1.2 создана от `msp-1-1-gateway-foundation` |
| 2. green CI | выполнено для PR #4 (27/27) |
| 3. зафиксировать HEAD SHA | `f6de230b77d221fd7f019b4ccd91d323fb388b34` (`msp-1-1-gateway-foundation`); `origin/main` = `127c4ba79046ab7faaf997125e3a18c8908fde5c` |
| 4. сохранить `MSP_1_1_ACCEPTANCE.md` | сохранён, решение `READY_WITH_WARNINGS` |
| 5. создать этот документ | этот файл |

Когда PR #4 будет слит, ветку 1.2 нужно перебазировать на `main` (в ней нет коммитов вне 1.1, кроме этапа 1.2).

## Состояние на `f6de230`

| Параметр | Значение |
|---|---|
| Postfix | 3.10.13 (Debian trixie, образ `deployment/gateway/Dockerfile`) |
| Rspamd | не установлен (вводится этапом) |
| Миграция БД, голова | `a1c4e7b90d11` |
| Конфигурация шлюза | лабораторная, версия назначается при применении; предупреждение шлюза MSP 1.1 в силе |
| Тесты (обычные) | 1862 пройдено, 41 пропущено (Linux-зависимые) |
| Тесты шлюза (живые, `MSP_GATEWAY_TESTS=1`) | 159 |
| CI | 27 заданий, зелёные (PR #4) |
| Правила обнаружения | 124 версии правил в `ruleset_fingerprint` |
| Корпус | 563 случая; оценено в базовой линии 522 (precision 1.0, recall 1.0 на корпусе) |
| Категория `spam` в корпусе | **0 случаев** — корпус спама создаётся в этапе 1.2 (ТЗ §39) |
| Открытые пробелы | GAP-001 (VALIDATION), GAP-002 (VALIDATION), GAP-003 (VALIDATION), GAP-004 (VALIDATION) |
| GAP-003/004 | реализованы на синтетическом корпусе, подтверждение на реальном потоке ожидается |
| Гейт готовности (`scripts/gateway_readiness.py`) | **NOT_READY** (нет данных реального потока: blocking — `real_flow_pipeline_proven`, `real_flow_precision_measured`, `real_flow_recall_is_labelled_estimate`, `real_flow_rule_noise_reviewed`, `known_false_negatives_documented`, `gate_gaps_in_required_state`, `regression_suite`) |
| Предупреждения шлюза 1.1 | общий токен узла; архивы — только оглавление; нет высокой доступности; лабораторные сертификаты без AKI |
| PostgreSQL / Redis | на машине разработки запущены контейнеры другого проекта (`fz152-*`); платформа MSP использует собственные контейнеры Compose, при разработке — SQLite; Redis платформы в этом baseline не запущен |

## Что не меняется

Запрещено на этапе 1.2: reject/discard/quarantine по результатам анти-спама, SPF/DKIM/DMARC, RBL, репутации,
вредоносного ПО и VirusTotal; пользовательский карантин; greylisting в боевом режиме; боевое переключение MX.
`milter_default_action = accept` обязателен.
