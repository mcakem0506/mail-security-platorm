# Mail Security Platform

Корпоративная платформа защиты электронной почты для **Microsoft Exchange Server On-Premises**.

Работает как **Mail Security Companion** поверх существующей почтовой инфраструктуры: анализирует
письма, объясняет каждый вердикт, ведёт инциденты и кампании, и выполняет действия в Exchange
только через контролируемый workflow с согласованием. Платформа **не становится критической
точкой доставки почты** и не обязана заменять существующий Secure Email Gateway.

Реализовано по техническому заданию `MAIL_SECURITY_PLATFORM_TZ_v1_0.md`.

---

## Что делает платформа

| Возможность | Статус | ТЗ |
|---|---|---|
| Outlook Add-in: проверка письма и сообщение о фишинге | реализовано | §6 |
| Приём через security mailbox (fallback без EWS) | реализовано | §7.2 |
| Безопасный разбор MIME/EML с жёсткими лимитами | реализовано | §8 |
| Целостность отправителя, SPF/DKIM/DMARC из доверенных заголовков | реализовано | §9 |
| Защита корпоративных идентичностей, lookalike и омоглифы | реализовано | §9.3, §9.4 |
| Анализ URL и доменов | реализовано | §11 |
| Статический анализ вложений и архивов | реализовано | §12 |
| Threat Intelligence Hub с privacy gate и кэшем | реализовано | §13 |
| VirusTotal как подключаемый провайдер | реализовано | §14 |
| Anti-phishing: 93 версионируемых правила | реализовано | §15 |
| BEC и социальная инженерия (RU + EN) | реализовано | §16 |
| Объяснимый вердикт без понятия «SAFE» | реализовано | §17 |
| Корреляция кампаний | реализовано | §18 |
| Инциденты и расследования | реализовано | §19 |
| Контролируемое реагирование в Exchange (dry-run) | реализовано | §20 |
| Консоль безопасности с безопасным просмотром писем | реализовано | §22 |
| Просмотр Threat Intelligence с актуальностью данных | реализовано | §22.4 |
| Отчётность и экспорт CSV/JSON | реализовано | §37 |
| Уведомления (add-in, email, дашборд) | реализовано | §36 |
| RBAC, аутентификация, аудит | реализовано | §23–§25 |
| Retention, backup/restore, метрики | реализовано | §27, §31, §32 |
| Active Directory (только чтение) | реализовано | §10 |
| Inline SMTP-фильтрация (Secure Email Gateway) | **не входит в v1** | §21, §45 MSP 1.1+ |
| Собственный AV-движок и sandbox | **не входит в v1** | §3.2 |

---

## Ключевые архитектурные решения

Эти решения заложены в код, а не оставлены на усмотрение эксплуатации:

- **Нет понятия «SAFE».** Минимальный вердикт — `LOW_RISK`, а при неполных данных — `UNKNOWN`.
  Отсутствие обнаружения никогда не подаётся как безопасность (§17, §49.9).
- **Каждый вердикт объясним.** Голый `risk_score` невозможен: вердикт строится из сигналов,
  каждый из которых несёт причину, источник, время и версию правила (§2.2).
- **Внешние источники не критичны.** Локальный анализ завершается сам по себе; TI-обогащение —
  отдельная асинхронная стадия, которая может только **повысить** вердикт. Недоступность
  VirusTotal не влияет на readiness (§2.3, §31).
- **Privacy by design.** Наружу по умолчанию уходят только хеши, домены и IP. URL с путём или
  query, внутренние домены и адреса сотрудников блокируются policy gate до отправки (§2.4).
- **Загрузка файлов в VirusTotal запрещена** и не включается даже Premium-лицензией — только
  отдельным путём Private Scanning (§14.5).
- **Никаких автоматических разрушительных действий.** Реагирование всегда начинается с dry-run,
  автор предложения не может согласовать его сам, массовые операции требуют второго
  согласующего (§2.5, §20).
- **Ничего не исполняется.** Вложения разбираются статически, URL не открываются, HTML только
  токенизируется и санитизируется (§11.4, §12.4, §49.5, §49.6).

---

## Структура репозитория

```text
apps/
  api/               FastAPI: 41 эндпоинт, модель данных, миграции
  worker/            Celery: 6 очередей, обогащение, retention, AD-синхронизация
  security-console/  React + TypeScript: консоль аналитика и администратора
  outlook-addin/     Office.js: панель сотрудника с определением возможностей клиента
packages/
  shared-contracts/  общие перечисления и контракты
  mail-parser/       безопасный разбор MIME, архивов, URL, доменов
  detection-engine/  факты, правила (YAML), омоглифы, BEC
  risk-engine/       объяснимая агрегация вердикта
  ti-core/           интерфейс провайдеров, privacy gate, кэш, Hub
providers/
  exchange/          Mock, SecurityMailbox (IMAP), EWS (adapter boundary)
  active-directory/  read-only LDAP
  virustotal/        API v3 с licensing gate
  malware-scanner/   ClamAV-адаптер и mock
  semantic-analysis/ опциональный, по умолчанию отключён
infrastructure/
  compose/  nginx/  monitoring/  backup/
tests/
  unit/  integration/  security/  e2e/  fixtures/
docs/
```

---

## Быстрый старт (стенд)

Требования: Docker 24+, Docker Compose v2.

```bash
cp .env.example .env
```

Задайте в `.env` как минимум `POSTGRES_PASSWORD` и `MSP_CORPORATE_DOMAINS`.

Создайте файлы секретов (в Git они не попадают):

```bash
umask 077 && openssl rand -base64 48 | tr -d '\n' > infrastructure/compose/secrets/msp_secret_key
```

```bash
umask 077 && openssl rand -base64 32 | tr -d '\n' > infrastructure/compose/secrets/minio_password
```

Поместите TLS-сертификат и ключ в `infrastructure/nginx/tls/server.crt` и `server.key`
(для стенда подойдёт самоподписанный, для пилота — сертификат внутреннего PKI).

Примените миграции и запустите:

```bash
docker compose run --rm migrate
```

```bash
docker compose up -d
```

Создайте первого администратора (пароль генерируется и показывается один раз):

```bash
docker compose exec api python /app/scripts/bootstrap.py --generate-password
```

Консоль: `https://<host>:8443/`. Проверка состояния: `https://<host>:8443/health/dependencies`.

---

## Разработка

```bash
py -3.12 -m venv .venv && .venv/Scripts/pip install -e ".[dev]"
```

```bash
.venv/Scripts/python -m pytest -q
```

```bash
.venv/Scripts/ruff check . && .venv/Scripts/mypy packages apps/api apps/worker providers
```

Консоль:

```bash
cd apps/security-console && npm install && npm run dev
```

---

## Что нужно получить до пилота

Согласно §51 ТЗ, Exchange-специфичный production-код не пишется без фактических данных о среде.
До их получения Exchange и AD работают как mock/adapter boundary, а перечень blocker'ов
возвращается через `GET /health/dependencies` и документирован в
[docs/EXCHANGE_COMPATIBILITY.md](docs/EXCHANGE_COMPATIBILITY.md).

Требуются: версия и build Exchange, версии Outlook и Office, доступность OWA, конфигурация EWS,
топология mail flow и наличие Edge Transport, существующий антиспам/SEG, модель аутентификации,
топология AD, TLS/внутренний PKI, требования outbound proxy.

---

## Документация

| Документ | Назначение |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Компоненты, потоки данных, границы |
| [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Модель безопасности и разграничение доступа |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Модель угроз самой платформы |
| [EXCHANGE_COMPATIBILITY.md](docs/EXCHANGE_COMPATIBILITY.md) | Матрица совместимости и blocker'ы |
| [DATA_CLASSIFICATION.md](docs/DATA_CLASSIFICATION.md) | Классификация данных и retention |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Развёртывание, обновление, откат |
| [BACKUP_RESTORE.md](docs/BACKUP_RESTORE.md) | Резервное копирование и restore drill |
| [INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md) | Порядок реагирования |
| [ACCEPTANCE.md](docs/ACCEPTANCE.md) | Матрица приёмки по §40–§44 |
| [ANALYST_GUIDE.md](docs/ANALYST_GUIDE.md) | Руководство аналитика ИБ |
| [EMPLOYEE_GUIDE.md](docs/EMPLOYEE_GUIDE.md) | Руководство сотрудника |

---

## Ограничения

Платформа **не является** полноценным Secure Email Gateway и не фильтрует почту inline.
Она **не заменяет** корпоративный антивирус и не выполняет динамический анализ (sandbox).
Локальный сканер ClamAV — вспомогательный сигнал, а не enterprise malware protection.
Переход к inline-режиму выполняется отдельной программой MSP 1.1+ только после успешного
завершения MSP 1.0 и отдельной приёмки по HA, очередям и откату (§21, §49.13).
