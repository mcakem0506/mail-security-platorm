# Матрица приёмки

Документ сопоставляет критерии приёмки §40–§44 ТЗ с реализацией и способом проверки.

Обозначения:
**✅ выполнено** — реализовано и проверено автоматическим тестом или ручной проверкой на стенде.
**⚠️ выполнено с ограничением** — реализовано, но с явно названным ограничением.
**⛔ блокер среды** — требует данных о среде по §51; реализован adapter boundary.

Команда для воспроизведения всех автоматических проверок:

```bash
pytest -q
```

---

## §40. Приёмка Outlook-модуля

| № | Критерий | Статус | Чем подтверждается |
|:--:|---|:--:|---|
| 1 | Add-in централизованно устанавливается в подтверждённой конфигурации | ⛔ | `manifest.xml` готов к централизованному развёртыванию; подтверждение конфигурации требует данных §51 (`docs/EXCHANGE_COMPATIBILITY.md`) |
| 2 | Пользователь может отправить выбранное письмо на анализ | ✅ | `POST /api/v1/analysis`; `tests/security/test_api_security.py::TestObjectLevelAuthorization`; проверено на стенде |
| 3 | Fallback через security mailbox работает | ✅ | `SecurityMailboxProvider` + `extract_original_message`; панель показывает инструкцию при недоступности API клиента |
| 4 | Пользователь видит статус | ✅ | `GET /api/v1/analysis/{job_id}`; 13 состояний §6.3 в `AnalysisStatus` |
| 5 | Пользователь может сообщить в ИБ | ✅ | `report_as_phishing=true`; кнопка «Сообщить о фишинге» |
| 6 | Нельзя получить результат другого пользователя | ✅ | `test_employee_cannot_read_another_users_analysis` — возвращается 404, а не 403 |
| 7 | Add-in корректно работает при недоступности TI | ✅ | `test_provider_outage_leaves_analysis_usable`; локальный вердикт отдаётся независимо от TI |
| 8 | Add-in не содержит secrets | ✅ | `config.js` содержит только URL; `test_public_config_exposes_no_secrets` |
| 9 | Ошибка backend не нарушает Outlook | ✅ | все вызовы возвращают состояние, а не исключение (`api.js`); при ошибке анализа возвращается `ERROR` со понятным текстом |
| 10 | Ограничения клиента отображаются явно | ✅ | `detectCapabilities()` формирует список ограничений, панель показывает их пользователю |

---

## §41. Приёмка Anti-Phishing

| № | Критерий | Статус | Тест |
|:--:|---|:--:|---|
| 1 | Detect display-name impersonation | ✅ | `test_41_1_display_name_impersonation` |
| 2 | Detect lookalike corporate domain | ✅ | `test_41_2_lookalike_corporate_domain` |
| 3 | Detect Punycode suspicious identity | ✅ | `test_41_3_punycode_identity` |
| 4 | Detect Reply-To mismatch | ✅ | `test_41_4_reply_to_mismatch` |
| 5 | Extract and normalize URLs | ✅ | `test_41_5_urls_extracted_and_normalized` |
| 6 | Identify visible-link mismatch | ✅ | `test_41_6_visible_link_mismatch` |
| 7 | Detect BEC fixtures | ✅ | `test_41_7_bec_fixtures_detected` (3 сценария) |
| 8 | Detect campaign across recipients | ✅ | `test_same_campaign_groups_across_recipients` |
| 9 | Explain every verdict | ✅ | `test_41_9_every_verdict_is_explained` — проверяются все фикстуры корпуса |
| 10 | False-positive exception works and is audited | ✅ | `test_trusted_sender_suppresses_signals`; `AuditAction.EXCEPTION_CREATED` |
| 11 | Absence of VT does not disable detection | ✅ | `test_41_11_detection_works_without_virustotal` |
| 12 | Unknown does not appear as safe | ✅ | `test_41_12_unknown_never_presented_as_safe`; уровня `SAFE` не существует |

---

## §42. Приёмка VirusTotal

| № | Критерий | Статус | Тест |
|:--:|---|:--:|---|
| 1 | Provider is disabled without configured license/key | ✅ | `test_disabled_without_a_licence`, `test_premium_requires_a_key` |
| 2 | Mock mode works | ✅ | `MockVirusTotalProvider`, детерминированные вердикты |
| 3 | API key stored server-side only | ✅ | `test_api_key_never_appears_in_health_or_quota`; задание через API отклоняется |
| 4 | Rate limits handled | ✅ | token-bucket с per-minute и per-day, backoff по `Retry-After` |
| 5 | Cache works | ✅ | `test_cache_prevents_repeated_external_calls` |
| 6 | Provider timeout isolated | ✅ | таймаут на провайдера + circuit breaker; `test_provider_outage_leaves_analysis_usable` |
| 7 | Full file upload disabled by default | ✅ | `test_file_upload_is_refused`, `test_upload_requires_private_scanning` |
| 8 | Privacy policy blocks disallowed URL/IOC queries | ✅ | `TestPrivacyGate` (8 типов + 5 видов чувствительных URL) |
| 9 | Raw provider response is normalized | ✅ | `normalize_response`; `test_enrichment_raises_verdict_and_records_lookups` проверяет отсутствие сырых полей в БД |
| 10 | Provider outage does not fail core platform | ✅ | `test_provider_outage_leaves_analysis_usable`; readiness не зависит от VT |

---

## §43. Приёмка Security Console

| № | Критерий | Статус | Чем подтверждается |
|:--:|---|:--:|---|
| 1 | Analyst sees incidents | ✅ | `GET /api/v1/incidents`; `IncidentsPage` |
| 2 | Can inspect evidence | ✅ | `GET /api/v1/analysis/{id}/detail` — сигналы с evidence, версиями правил, источниками |
| 3 | Can search IOC | ✅ | `GET /api/v1/investigations/indicators/{type}/{value}` — вердикты провайдеров, актуальность данных, внутренние наблюдения, связанные кампании (§22.4); страница Threat Intelligence в консоли; фильтры §22.2 |
| 4 | Can link related messages | ✅ | `POST /api/v1/incidents/{id}/messages/{message_id}` |
| 5 | Can classify false positive | ✅ | `POST /api/v1/messages/{id}/classify`; метрика `false_positive_total` |
| 6 | Can create exception with expiry | ✅ | `POST /api/v1/admin/exceptions` с валидацией «срок в будущем» |
| 7 | Can propose remediation | ✅ | `POST /api/v1/remediation` с dry-run отчётом |
| 8 | Admin can approve/reject | ✅ | `POST /api/v1/remediation/{id}/approve`; `test_proposer_cannot_approve_own_request` |
| 9 | Audit captures all actions | ✅ | `TestSecretHygiene::test_audit_redacts_secrets_and_bodies`; проверено на стенде (8 событий за сценарий) |
| 10 | Dangerous content does not auto-execute | ✅ | sandbox-iframe без скриптов, `href` удаляется, вложения только как `octet-stream` с подтверждением |

---

## §44. Приёмка production-пилота

### До пилота

| Пункт | Статус | Комментарий |
|---|:--:|---|
| Exchange version identified | ⛔ | требуется §51 |
| Outlook versions identified | ⛔ | требуется §51 |
| EWS / add-in capabilities verified | ⚠️ | возможности add-in определяются в runtime; EWS требует §51 |
| Service accounts provisioned | ⛔ | требования описаны в `EXCHANGE_COMPATIBILITY.md` §5 |
| TLS valid | ⚠️ | конфигурация nginx готова (TLS 1.2/1.3, HSTS); сертификат внутреннего PKI предоставляет организация |
| Backup restore tested | ✅ | `infrastructure/backup/restore.sh --target drill` проверяет восстановимость без остановки production |
| Retention approved | ⚠️ | значения по умолчанию из §27 заданы; **утверждение сроков — за организацией** |
| Privacy policy approved | ⚠️ | политика реализована и по умолчанию ограничительна; утверждение — за организацией |
| Logging reviewed | ✅ | JSON-логи с correlation ID, автоматическая очистка чувствительных полей, query string не логируется |
| No default credentials | ✅ | `bootstrap.py` отказывается создавать пароль по умолчанию; проверяется в CI |
| All secrets rotated | ✅ | процедура в `infrastructure/compose/secrets/README.md`; поддержка `*_FILE` |
| Security tests passed | ✅ | 237 тестов, bandit без находок medium/high, mypy без ошибок |
| Rollback documented | ✅ | `docs/DEPLOYMENT.md`, раздел «Откат» |

### Пилот

| Пункт | Статус | Комментарий |
|---|:--:|---|
| 5–10 users first | — | организационный шаг |
| Security team included | — | организационный шаг |
| At least 2 weeks shadow operation | ⚠️ | shadow-режим требует подключения к mail flow (§51); до этого доступен режим security mailbox |
| Measure false positives | ✅ | метрика `msp_false_positive_total`, отчёт по ложным срабатываниям |
| Measure latency | ✅ | `msp_analysis_duration_seconds`, `msp_http_request_duration_seconds` |
| Review user feedback | ✅ | заметки аналитика, `reported_by`, статистика обращений сотрудников |
| No automatic destructive remediation | ✅ | по умолчанию `REMEDIATION_ENABLED=false`, `DRY_RUN_ONLY=true` |

---

## §37. Отчётность

| Отчёт | Статус | Эндпоинт |
|---|:--:|---|
| Weekly phishing summary | ✅ | `GET /api/v1/reports/phishing_summary` |
| Incidents (со средним временем триажа и реагирования) | ✅ | `GET /api/v1/reports/incidents` |
| Campaigns | ✅ | `GET /api/v1/reports/campaigns` |
| Most impersonated identities | ✅ | `GET /api/v1/reports/impersonated_identities` |
| Employee reporting (с точностью обращений) | ✅ | `GET /api/v1/reports/employee_reporting` |
| False positives (исключения и подавленные сигналы) | ✅ | `GET /api/v1/reports/false_positives` |
| Provider availability | ✅ | `GET /api/v1/reports/provider_availability` |
| Экспорт CSV | ✅ | `?format=csv`, требует права `export:data`, фиксируется в аудите |
| Экспорт JSON/API | ✅ | формат по умолчанию |
| Экспорт PDF | ⚠️ | по ТЗ «later»; не входит в v1 |

Экспорт CSV защищён от инъекции формул: значения, начинающиеся с `=`, `+`, `-`, `@`, табуляции
или возврата каретки, экранируются — иначе содержимое письма могло бы выполниться в Excel.

---

## Definition of Done по §46

| Требование | Статус | Проверка |
|---|:--:|---|
| build проходит | ✅ | `docker compose build`; образы API и консоли собираются |
| linters проходят | ✅ | `ruff check` — без замечаний, `ruff format --check` — без изменений |
| type checks проходят | ✅ | `mypy` — 70 файлов, без ошибок |
| tests проходят | ✅ | `pytest` — 237 тестов |
| migrations применяются с нуля | ✅ | проверено на чистом PostgreSQL: upgrade → downgrade → upgrade; `alembic check` без расхождений |
| Compose стартует на чистом окружении | ✅ | проверено: postgres, redis, migrate, api, frontend, nginx |
| health endpoints green | ✅ | `/health/live`, `/health/ready`, `/health/dependencies` |
| secrets отсутствуют в Git | ✅ | `.gitignore` + проверка в CI |
| документированы ограничения | ✅ | `README.md`, `EXCHANGE_COMPATIBILITY.md`, раздел «Что осознанно не сделано» в `ARCHITECTURE.md` |
| acceptance matrix заполнена | ✅ | этот документ |

---

## Итоговое заключение

```text
PHASE: MSP 0.1 – MSP 1.0 (ядро платформы, Mode A/B)
DECISION: READY WITH WARNINGS

IMPLEMENTED:
  Контракты, безопасный MIME/EML-парсер, движок детектирования (93 правила),
  объяснимый risk engine, Threat Intelligence Hub с privacy gate и кэшем,
  провайдеры (VirusTotal, ClamAV, Exchange mock/security mailbox/EWS boundary,
  AD read-only, semantic disabled), API (41 эндпоинт), воркер (6 очередей),
  консоль безопасности, Outlook Add-in, инфраструктура развёртывания,
  резервное копирование с restore drill, CI.

TESTS:
  237 автоматических тестов: 49 парсер, 37 детект и риск, 35 интеграционных
  (пайплайн), 16 отчётность, 39 безопасность API, 58 усиление защиты,
  3 сквозных сценария рабочего процесса.
  Корпус из 22 synthetic EML без живого malware.

MIGRATIONS:
  1 миграция, 35 таблиц. Применяется с нуля, откатывается, alembic check чист.

SECURITY CHECKS:
  bandit — без находок medium и high; mypy — 72 файла без ошибок; ruff — без замечаний;
  проверка отсутствия секретов в Git и bidi-символов в исходниках в CI.

MANUAL CHECKS:
  Полный стек запущен: миграции на чистом PostgreSQL, health green, вход,
  анализ BEC-письма (MALICIOUS, 5 причин сотруднику, 11 сигналов аналитику),
  безопасный просмотр без script и href, корреляция кампании, dry-run
  реагирования с отказом в самоутверждении, аудит без утечки секретов,
  проверка CSRF, все 6 заголовков безопасности.

KNOWN LIMITATIONS:
  - Inline SMTP-фильтрация не реализована (вне области v1, §21).
  - Собственный AV-движок и sandbox отсутствуют; интерфейсы предусмотрены.
  - Открытие URL из писем отключено; включение требует изолированной egress-зоны.
  - Загрузка файлов в VirusTotal запрещена; требует отдельного пути Private Scanning.
  - 7z и RAR не разбираются статически — помечаются как непроверенные,
    без безопасной in-process библиотеки в v1.
  - Извлечение URL из QR-кодов и office-документов — поздние этапы (§11.1).
  - Мобильный Outlook: только передача письма в ИБ.

PRODUCTION BLOCKERS:
  1. Не предоставлены служебные учётные записи и область ящиков. Технические
     параметры среды блокером больше не являются: они определяются проверкой
     scripts/probe_exchange.py. См. EXCHANGE_COMPATIBILITY.md раздел 10.
  2. Не предоставлен сертификат внутреннего PKI для TLS.
  3. Не утверждены организацией сроки хранения (§27) и политика приватности (§2.4).
  4. Не предоставлены сервисные аккаунты (intake, AD read).
  5. MFA для привилегированных роле́й требует подключения IdP.

NEXT PHASE:
  Этапы 1.0.1 и 1.0.2 реализованы; их приёмка ведётся отдельными документами:
    docs/MSP_1_0_1_ACCEPTANCE.md — production-интеграция и теневой пилот
    docs/MSP_1_0_2_ACCEPTANCE.md — работа с произвольным почтовым шлюзом
  Порядок: проверка готовности среды → security mailbox → EWS read-only →
  теневой пилот 5–10 пользователей не менее 14 дней → отчёт о пилоте →
  решение о контролируемом развёртывании → многошлюзовой пилот.
  MSP 1.1+ (inline gateway) не начинать до фактических результатов пилота 1.0.1.
```

---

## Этапы MSP 1.0.1 и MSP 1.0.2

Настоящий документ фиксирует приёмку базового этапа MSP 1.0. Приёмка последующих этапов ведётся
отдельно, чтобы было видно, что относится к какому этапу:

| Этап | Документ | Состояние |
|---|---|---|
| MSP 1.0 | настоящий документ | READY WITH WARNINGS |
| MSP 1.0.1 — production-интеграция, теневой пилот, валидация детектирования | [MSP_1_0_1_ACCEPTANCE.md](MSP_1_0_1_ACCEPTANCE.md) | код готов, ожидает пилота |
| MSP 1.0.2 — работа с произвольным почтовым шлюзом | [MSP_1_0_2_ACCEPTANCE.md](MSP_1_0_2_ACCEPTANCE.md) | код готов, ожидает среды |
| MSP 1.0.3 — качество детектирования и работа аналитика | [MSP_1_0_3_ACCEPTANCE.md](MSP_1_0_3_ACCEPTANCE.md) | READY WITH WARNINGS |
| MSP 1.0.3B — операции детектирования | [MSP_1_0_3B_ACCEPTANCE.md](MSP_1_0_3B_ACCEPTANCE.md) | см. документ этапа |

Актуальные цифры по текущему HEAD — `python scripts/generate_acceptance_snapshot.py`. Показатель,
который скрипту установить не удалось, помечается `unknown`: непроверенное не считается
пройденным.
