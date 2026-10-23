# Принуждение в MSP 1.3: архитектура

**Относится к:** ТЗ MSP 1.3 §1–§23, §47–§58
**Код:** `packages/enforcement/msp_enforcement/`, `apps/api/msp_api/services/{enforcement,quarantine,credentials}.py`,
`apps/api/msp_api/routers/enforcement.py`, `packages/antispam/msp_antispam/{effective_actions,lua/rspamd.local.lua}`,
`packages/gateway/msp_gateway/{spec,render,bundle}.py` (послеочередной шлюз), `infrastructure/enforcement/`

> **MSP 1.3 IS NOT APPROVED FOR GLOBAL PRODUCTION MX CUTOVER.** Принуждение возможно только для контролируемой области
> (канарейка, пилотный домен), по контролю отдельно, по двое согласующих. Глобального переключателя нет.

## 1. Принципы

1. **Нет общего флага `ENFORCEMENT=true`.** У каждого из восьми контролей (`SPAM_REJECT`, `DMARC_REJECT`, `RBL_REJECT`,
   `MALWARE_REJECT`, `PHISHING_REJECT`, `TEMPFAIL_ABUSE`, `QUARANTINE`, `OUTBOUND_BLOCK`) своё состояние
   (`DISABLED → SHADOW → CANARY → PILOT`, плюс `PAUSED`, `ROLLED_BACK`) и своя готовность. Состояния «глобально в бою» нет.
2. **Решение принимает узел, по локальной проверенной копии политики.** Недоступность панели, базы, внешних сервисов и
   консоли не меняет синхронный ответ SMTP (§48, §49).
3. **Служба принуждения не анализирует письмо** (§13): она получает нормализованные свидетельства, применяет версионированную
   политику и возвращает решение с причинами.
4. **Предложенное и применённое действие хранятся раздельно** (§23): `suggested_action` и `applied_action`.
5. **Внутренняя ошибка не вправе отклонить письмо** (§15): режимов сбоя два — `FAIL_OPEN` и `FAIL_TEMPFAIL`; постоянного нет.
6. **Известный пробел блокирует контроль технически** (§8, §73), и это проверяется дважды: в панели при активации и в
   движке на узле при каждом решении, по снимку состояния пробелов, подписанному вместе с политикой.

## 2. Схема

```text
Интернет ─► Postfix :25 ──► Milter ──► Rspamd (оценка, проверки)
                                         │  postfilter MSP_ENFORCEMENT_GATE (Lua, версионируется в Git)
                                         │  HTTP, тайм-аут ≤ 3 с, только с адреса Rspamd
                                         ▼
                                  gateway-enforcement (решение по локальной политике)
                                         │ REJECT/TEMPFAIL → pre-result сканера → 5xx/4xx в исходной сессии SMTP
                                         ▼
                          ───────── 250 ─ письмо в очереди Postfix (источник истины) ─────────
                                         │ content_filter
                                         ▼
                                  gateway-afterqueue ──► панель: полный анализ MSP (≤ 25 с)
                                         │                       │
                          доставка ◄─────┤ решение QUARANTINE/HOLD
                          (порт повторной подачи, без фильтра)   └─► карантин (шифрованное хранение)
```

* **До очереди (§11).** Только ответ SMTP: отказ `5xx` или временный `4xx`. Контроли: спам высокой уверенности,
  утверждённый RBL, синхронно подтверждённое вредоносное, злоупотребление соединением; DMARC — только после закрытия GAP-006.
* **После очереди.** Полный MSP: имперсонация, BEC, URL/TI, песочница вложений, кампании. Только `HOLD`/`QUARANTINE`/разбор
  аналитиком, **никогда `5xx`** (§10): после `250` постоянный отказ породил бы недоставленное уведомление (backscatter, §54).
  Послеочередной шлюз по коду не умеет отвечать `5xx` (проверяется тестом).

## 3. Что гарантирует конфигурация Rspamd

Milter исполняет родное действие Rspamd, поэтому наблюдение 1.2 — свойство конфигурации, а не пометка в панели. В 1.3 родные пороги
остаются недостижимыми, а принуждение идёт отдельным управляемым путём. При каждой активации конфигурации сканера строится
`effective_actions_report` (`rspamadm configdump`): пороги, `force_actions`, greylisting, ratelimit, antivirus, multimap с действием,
правила настроек с действиями, DMARC-действия, шаблон GTUBE, `spamtrap` и любое неизвестное поле `action`. **Неизвестный источник
reject или soft reject блокирует выпуск** (§50). Единственный принятый источник — `MSP_ENFORCEMENT_GATE`, и только когда шлюз включён.
Greylisting (§51) этим аудитом блокируется до отдельного решения.

## 4. Данные и права

Таблицы миграции `7d13e0f4a2b9`: `enforcement_controls`, `enforcement_policies` (неизменяемые версии с подписью),
`enforcement_decisions`, `enforcement_exceptions`, `enforcement_switches`, `quarantine_items`, `enforcement_incidents`,
`component_credentials_seen`. Права: `enforcement:{read,simulate,canary,pilot,pause,rollback,kill_switch}`,
`quarantine:{read,release,delete}`; исключения используют существующие `create:exception` и `exception:approve`. Каждая
мутация пишет событие аудита (список — в [SECURITY_MODEL.md](SECURITY_MODEL.md)).

## 5. Ограничения этапа

Нет высокой доступности, общей записываемой очереди между узлами и пользовательского портала карантина; подпись политики
симметричная (общий ключ у панели и узла) — компрометация узла позволяет подделать политику для самого узла; подробный список —
в [MSP_1_3_ACCEPTANCE.md](MSP_1_3_ACCEPTANCE.md).

Смотрите также: [ENFORCEMENT_POLICY.md](ENFORCEMENT_POLICY.md), [ENFORCEMENT_READINESS.md](ENFORCEMENT_READINESS.md),
[SMTP_ACTION_SEMANTICS.md](SMTP_ACTION_SEMANTICS.md), [QUARANTINE_ARCHITECTURE.md](QUARANTINE_ARCHITECTURE.md).
