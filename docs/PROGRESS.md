# Состояние реализации (черновик, ведётся по ходу работы)

ТЗ: `MAIL_SECURITY_PLATFORM_TZ_v1_0.md`. Реализация идёт по фазам MSP 0.1+ (ТЗ §45).

## Сделано и проверено вживую

- `pyproject.toml` — единый проект, 12 пакетов (ruff/mypy/bandit/pytest настроены), venv `.venv` (Python 3.12) с установленными зависимостями, `pip install -e .` проходит.
- `packages/shared-contracts` (`msp_contracts`) — все перечисления и контракты ТЗ: статусы add-in (§6.3), уровни риска без `SAFE` (§17), статусы TI (§13.3), инциденты (§19), роли (§23), remediation (§20), VT-режимы (§14.3).
- `packages/mail-parser` (`msp_mail_parser`) — безопасный MIME/EML-парсер (§8):
  лимиты и deadline, определение типа по magic-байтам, статический разбор ZIP/gzip с защитой от
  zip-бомб (проверяется реальный размер, а не заявленный), path traversal, symlink, вложенности;
  IDNA/PSL-разбор доменов офлайн; извлечение и нормализация URL с редактированием секретов в
  логах; санитизация HTML через `nh3` (скрипты, remote-контент и href удаляются).
  Проверено: фишинговый EML разобран, скрипт вырезан, punycode раскрыт, IP-литерал и
  password-форма распознаны. Исправлено восстановление «сырых» 8-bit заголовков (UTF-8/cp1251).
- `packages/detection-engine` (`msp_detection`) — омоглифы/typosquatting/lookalike (§9.3, §11.3),
  контекст организации и защищаемых идентичностей с исключениями (§15.3), разбор
  Authentication-Results без собственных SMTP-вердиктов (§9.2), BEC/соц.инженерия RU+EN (§16),
  извлечение фактов по отправителю/URL/вложениям, YAML-движок правил с версионированием и
  безопасным интерпретатором условий (без `eval`), **93 правила** в 4 файлах (§15.1, §16.2, §13).
- `packages/risk-engine` (`msp_risk`) — объяснимый вердикт (§17): насыщающая агрегация, hard-signals
  поднимают класс с сохранением источника и времени, `UNKNOWN` при неполных данных,
  фильтр причин для сотрудника (§6.4).
- `packages/ti-core/msp_ti/base.py` — интерфейс TI-провайдера, реестр и **privacy gate** (§2.4, §14.4):
  по умолчанию наружу уходят только hash/domain/IP, URL с путём/query и внутренние домены блокируются.

Сквозная проверка: BEC-письмо (lookalike-домен + подмена имени руководителя + смена реквизитов +
просьба обойти согласование) → `MALICIOUS`, 8 объяснимых причин, 5 причин для сотрудника.

## Не сделано (следующие шаги, по порядку)

1. `packages/ti-core`: кэш по provider+indicator с TTL по типу/вердикту (§13.4), TI Hub-оркестратор.
2. `providers/`: VirusTotal v3 с licensing gate `VT_MODE` и upload=DISABLED (§14), ClamAV/Mock
   scanner (§12.3), Mock/EWS/SecurityMailbox Exchange-провайдеры (§7), AD read-only sync (§10),
   опциональный semantic-провайдер (§16.4, по умолчанию disabled).
3. `apps/api`: FastAPI, модели SQLAlchemy по §26, миграции Alembic, auth+RBAC (§23, §24),
   аудит (§25), эндпоинты анализа/инцидентов/кампаний/политик/remediation, health (§31).
4. `apps/worker`: Celery, очереди `mail_parse|ti_lookup|attachment_analysis|campaign|notifications|maintenance` (§5),
   корреляция кампаний (§18), retention (§27), уведомления (§36).
5. `apps/security-console` (React+TS), `apps/outlook-addin` (Office.js + fallback через security mailbox).
6. `infrastructure/compose` + nginx + monitoring + backup (§33), `.env.example`.
7. `tests/`: корпус из 20 synthetic EML (§39), security-тесты (§38), acceptance-матрицы (§40–44).
8. `docs/`: ARCHITECTURE, SECURITY_MODEL, THREAT_MODEL, EXCHANGE_COMPATIBILITY (с blocker'ами по §51), и т.д.

## Зафиксированные blocker'ы (§51 — не выдумывать конфигурацию)

Фактические данные по среде не предоставлены: версия/build Exchange, версии Outlook и Office,
доступность OWA, конфигурация EWS, топология mail flow и Edge Transport, существующий
антиспам/SEG, модель аутентификации, топология AD, TLS/PKI, требования outbound proxy.
До их получения Exchange/AD реализуются только как mock/adapter boundary.
