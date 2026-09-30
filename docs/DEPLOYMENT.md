# Развёртывание, обновление и откат

Соответствует §29, §33, §34, §44 ТЗ.

---

## 1. Требования

### Виртуальная машина (пилот до 50 пользователей)

| Параметр | Ориентир §33.1 | Комментарий |
|---|---|---|
| vCPU | 4–8 | 4 достаточно для 50 пользователей в режиме security mailbox |
| RAM | 8–16 ГБ | PostgreSQL 2 ГБ, Redis 512 МБ, воркеры по 512 МБ, остальное — резерв |
| Диск | 100+ ГБ SSD | рассчитывается от объёма хранения, см. раздел 8 |
| ОС | Linux с Docker 24+ и Compose v2 | |

Точные ресурсы определяются нагрузочным тестированием и фактическим объёмом хранения.

### Сетевой доступ

| Направление | Назначение | Обязательно |
|---|---|:--:|
| Пользователи → платформа :443 | консоль и add-in | да |
| Платформа → Exchange :993 (IMAPS) | security mailbox | да |
| Платформа → AD :636 (LDAPS) | синхронизация каталога | нет |
| Платформа → Exchange EWS :443 | чтение писем, remediation | нет |
| Платформа → SMTP :25/587 | уведомления | нет |
| Платформа → провайдеры TI :443 | обогащение | нет |
| Мониторинг → платформа :443/metrics | метрики | рекомендуется |

Исходящий доступ требуется только воркерам `worker-ti` и `worker-maintenance`. Остальные
компоненты работают без выхода наружу.

---

## 2. Первое развёртывание

### 2.1. Конфигурация

```bash
cp .env.example .env
```

Обязательно задать: `POSTGRES_PASSWORD`, `MSP_CORPORATE_DOMAINS`, `MSP_ORGANIZATION_NAME`,
`MSP_PUBLIC_BASE_URL`, `MSP_BOOTSTRAP_ADMIN_EMAIL`.

### 2.2. Секреты

```bash
umask 077 && openssl rand -base64 48 | tr -d '\n' > infrastructure/compose/secrets/msp_secret_key
```

```bash
umask 077 && openssl rand -base64 32 | tr -d '\n' > infrastructure/compose/secrets/minio_password
```

Пароли Exchange, AD и SMTP добавляются такими же файлами, а в `.env` указываются переменные
`*_FILE`. Секреты никогда не попадают в Git — это обеспечено `.gitignore` и проверяется в CI.

### 2.3. TLS

Поместить сертификат внутреннего PKI и ключ в `infrastructure/nginx/tls/server.crt` и
`server.key`. Права на ключ — `600`.

Самоподписанный сертификат допустим только для стенда:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout infrastructure/nginx/tls/server.key -out infrastructure/nginx/tls/server.crt -subj "/CN=mail-security.corp.example"
```

### 2.4. Миграции и запуск

```bash
docker compose run --rm migrate
```

```bash
docker compose up -d
```

### 2.5. Первый администратор

```bash
docker compose exec api python scripts/bootstrap.py --generate-password
```

Пароль показывается **один раз** и требует смены при первом входе. Пароля по умолчанию
не существует.

### 2.6. Проверка

```bash
curl -s https://<host>/health/dependencies | python -m json.tool
```

Ожидается `"status": "ready"`, все обязательные зависимости `ok`. Необязательные (VirusTotal,
ClamAV, AD) могут быть `disabled` или `not_configured` — это не влияет на готовность.

---

## 3. Опциональные компоненты

### Локальный сканер

```bash
MSP_CLAMAV_ENABLED=true docker compose --profile clamav up -d
```

Первая загрузка баз занимает несколько минут — до её завершения сканер сообщает `unavailable`,
и его результаты не участвуют в анализе. ClamAV является **дополнительным** сигналом и не
эквивалентен полноценной корпоративной антивирусной защите.

### S3-совместимое хранилище

```bash
MSP_OBJECT_STORAGE_BACKEND=s3 docker compose --profile s3 up -d
```

Для одного узла достаточно файлового хранилища (по умолчанию). S3 нужен при нескольких узлах
или больших объёмах.

### VirusTotal

Требуется лицензия Premium или Private Scanning; `public` не поддерживается как production-режим.

```bash
umask 077 && printf '%s' 'КЛЮЧ' > infrastructure/compose/secrets/vt_api_key
```

В `.env`: `MSP_VT_MODE=premium` и `MSP_VT_API_KEY_FILE=/run/secrets/vt_api_key`. Загрузка файлов
остаётся запрещённой.

---

## 4. Развёртывание Outlook Add-in

1. Заменить `https://mail-security.corp.example` в `apps/outlook-addin/manifest.xml` на
   фактический внутренний адрес.
2. Указать в `apps/outlook-addin/config.js` значения `MSP_API_BASE` и `MSP_SECURITY_MAILBOX`.
3. Добавить иконки в `apps/outlook-addin/assets/` (16, 32, 64, 80, 128 px).
4. Проверить, что манифест доступен: `https://<host>/addin/manifest.xml`.
5. Развернуть централизованно средствами Exchange на пилотную группу.

Add-in не содержит секретов и работает через сессию пользователя.

---

## 5. Обновление

```bash
git pull
```

```bash
docker compose build
```

```bash
docker compose run --rm migrate
```

```bash
docker compose up -d
```

Порядок важен: миграции применяются до запуска новой версии приложения. Миграции пишутся
совместимыми вперёд, поэтому короткое время работы старого кода с новой схемой безопасно.

**Перед обновлением всегда снимается резервная копия** (`infrastructure/backup/backup.sh`).

---

## 6. Откат

### 6.1. Откат кода без изменения схемы

```bash
git checkout <предыдущий-тег>
```

```bash
docker compose build && docker compose up -d
```

### 6.2. Откат с изменением схемы

```bash
docker compose exec api sh -c "cd /app/apps/api && alembic downgrade -1"
```

Затем откатить код. Каждая миграция имеет реализованный `downgrade`, что проверяется в CI
(upgrade → downgrade → upgrade).

### 6.3. Полное восстановление из резервной копии

```bash
./infrastructure/backup/restore.sh /backup/<метка> --target production
```

Скрипт остановит приложение, потребует подтверждения имени базы, восстановит дамп, применит
миграции и запустит сервисы. Подробнее — `docs/BACKUP_RESTORE.md`.

### 6.4. Аварийное отключение опасных функций

Не требует перезапуска инфраструктуры:

```bash
docker compose exec api sh -c 'echo "remediation disabled via env"'
```

Практически: выставить в `.env` `MSP_REMEDIATION_ENABLED=false` и
`MSP_REMEDIATION_DRY_RUN_ONLY=true`, затем `docker compose up -d api worker-ti`.
Отключение VirusTotal — `MSP_VT_MODE=disabled`; анализ продолжит работать.

---

## 7. Эксплуатация

### Проверка состояния

```bash
docker compose ps
```

```bash
curl -s https://<host>/health/dependencies | python -m json.tool
```

### Логи

```bash
docker compose logs -f api worker-ti --tail 100
```

Логи в формате JSON с полями `request_id`, `analysis_job_id`, `message_id`, `incident_id`.
Чувствительные поля вычищаются автоматически.

### Глубина очередей

```bash
docker compose exec redis redis-cli --raw LLEN ti_lookup
```

Устойчивый рост `ti_lookup` означает недоступность или троттлинг провайдера. Это не влияет
на локальный анализ: письма получают вердикт без обогащения.

### Метрики

`https://<host>/metrics` — доступ только из сети мониторинга. Перед пилотом сузить список
разрешённых адресов в `infrastructure/nginx/nginx.conf` до адреса сервера мониторинга.

Ключевые метрики: `msp_analyses_total`, `msp_analysis_duration_seconds`, `msp_queue_depth`,
`msp_provider_latency_seconds`, `msp_provider_errors_total`, `msp_parser_errors_total`,
`msp_false_positive_total`, `msp_employee_reports_total`, `msp_remediation_actions_total`.

### Перезагрузка правил без перезапуска

```bash
curl -sk -X POST https://<host>/api/v1/admin/rules/reload -H "X-CSRF-Token: <token>" -b cookies.txt
```

---

## 8. Расчёт хранения

Оценка для 50 пользователей при сроках хранения по умолчанию:

| Категория | Срок | Оценка объёма |
|---|---|---|
| Метаданные писем | 180 дней | ~2 КБ на письмо |
| Результаты анализа и сигналы | 365 дней | ~8 КБ на письмо |
| Нормализованное тело | 180 дней | ~10 КБ на письмо |
| Исходные EML | 30 дней | средний размер письма |
| Вложения | 30 дней | основной объём |
| Вредоносные образцы | 365 дней | отдельная политика |
| Аудит | 400 дней | ~1 КБ на событие |

При 200 проверках в сутки и среднем письме 150 КБ: около 1,5 ГБ активного объёма
и около 25 ГБ с запасом на пики и индексы. Ориентир 100 ГБ покрывает это с большим запасом.

---

## 9. Контрольный список перед production (§44)

- [ ] Данные о среде по §51 получены и внесены в `EXCHANGE_COMPATIBILITY.md`
- [ ] Сертификат внутреннего PKI установлен, самоподписанный удалён
- [ ] Все секреты сгенерированы заново, тестовые значения удалены
- [ ] `MSP_ENVIRONMENT=production`, `MSP_DEBUG=false`, `MSP_COOKIE_SECURE=true`
- [ ] Пароль администратора сменён при первом входе
- [ ] MFA для привилегированных роле́й настроена в IdP
- [ ] Сроки хранения утверждены организацией
- [ ] Политика передачи данных провайдерам утверждена
- [ ] Резервное копирование настроено по расписанию
- [ ] **Restore drill выполнен и зафиксирован**
- [ ] Список адресов для `/metrics` сужен до сервера мониторинга
- [ ] Мониторинг и оповещения настроены
- [ ] `MSP_REMEDIATION_ENABLED=false` на время пилота
- [ ] Процедура откатa проверена на стенде
- [ ] Пилотная группа 5–10 человек определена, служба ИБ включена

---

## Дополнения этапов MSP 1.0.1 и 1.0.2

### Перед развёртыванием

```bash
docker compose exec api python scripts/probe_exchange.py --markdown /tmp/readiness.md
```

Код возврата `1` означает `NOT_READY` — проверку можно поставить шагом регламента. Подробно —
[EXCHANGE_PROBE_GUIDE.md](EXCHANGE_PROBE_GUIDE.md).

### Права служебного ящика

Устойчивый приём перемещает обработанные сообщения в `Processed`, а не поддающиеся обработке —
в `Failed`. Папки создаются автоматически при первом обращении, но учётной записи нужно право на
**перемещение** внутри ящика: доступа только на чтение теперь недостаточно.

### Описание топологии почтового потока

Без доверенных узлов заголовки шлюза не учитываются, а результаты проверки подлинности читаются
в запасном режиме. Описание — [TRUSTED_MAIL_FLOW.md](TRUSTED_MAIL_FLOW.md), проверка:

```bash
docker compose exec api python scripts/probe_exchange.py --section mailflow
```

### Приём событий шлюза по syslog

Отключён по умолчанию. При включении обязателен список разрешённых источников, в production —
TCP или TLS. Слушающий адрес по умолчанию — loopback; приём с другого узла требует явной
настройки. См. [SYSLOG_INTEGRATION.md](SYSLOG_INTEGRATION.md).

### Лимиты анализа

Десять отдельно настраиваемых лимитов (`MSP_LIMIT_*`). Повышать их следует осознанно: они
ограничивают не только объём работы, но и поверхность атаки разбора. Письмо сверх
`MSP_LIMIT_MESSAGE_SIZE` не анализируется вовсе и получает вердикт `UNKNOWN`.

### Снимок состояния для приёмки

```bash
docker compose exec api python scripts/generate_acceptance_snapshot.py --out /tmp/snapshot.md
```

Собирает коммит, число тестов, head миграций, число правил, состав корпуса, состояние сборки
консоли и результат проверки зависимостей. Значение `unknown` означает «не проверялось» и не
приравнивается к успеху.

### Защита ветки

```bash
./scripts/setup_branch_protection.sh --dry-run
```

Настройка репозитория, применяется владельцем. Скрипт печатает намеченное состояние и требует
подтверждения.
