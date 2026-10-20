# Лабораторный стенд шлюза: запуск и проверка

**Относится к:** ТЗ MSP 1.1 §66, §67
**Файлы:** `deployment/gateway/` (`compose.yml`, `Dockerfile`, `entrypoint.sh`, `test/`), `tests/gateway/`, `scripts/linux_pytest.py`

> **MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER.**
> Стенд изолирован: своя сеть, свои тома, ничего не публикуется наружу, кроме loopback-портов для проверок с
> хоста. Он не подключается к почте организации и не меняет DNS.

---

## 1. Что в стенде

Профиль Docker Compose `gateway-test` (файл `deployment/gateway/compose.yml`):

| Сервис | Роль | Адрес в сети стенда |
|---|---|---|
| `gateway-postfix` | узел шлюза: Postfix + агент + синхронизация | 10.77.0.10 |
| `fake-exchange`, `fake-exchange-2` | управляемые двойники Exchange | 10.77.0.20, .21 |
| `outbound-sink` | приёмник исходящей почты | 10.77.0.30 |
| `gateway-shadow-collector` *(профиль `gateway-panel`)* | сборщик теневых копий | 10.77.0.40 |

Двойник Exchange умеет: принимать, отвечать временным отказом (`4xx`), постоянным отказом (`5xx`), отказывать
отдельным получателям, замедлять ответ, обрывать соединение, требовать STARTTLS и вести журнал полученных писем
(Message-ID, размер, хэш тела, источник) с управлением по HTTP.

Адреса статические намеренно: доверие шлюза определяется подсетью источника, поэтому «доверенный Exchange»
(`10.77.0.64/26`) и «недоверенный клиент» различаются адресом.

Платформа (API, база, Redis, воркер) в стенде не поднимается контейнерами: сквозные проверки запускают
настоящее приложение API в потоке тестового процесса на файловой SQLite (`tests/gateway/panel.py`). Это
сделано, чтобы узел в контейнере обращался к настоящим маршрутам панели, не требуя PostgreSQL для проверки.

---

## 2. Требования

* Docker (Compose v2), доступ к Docker-демону.
* Python-окружение проекта (`pip install -e ".[dev,qr,sandbox]"`).
* Интернет не требуется для запуска; при первой сборке образам нужны пакеты Debian и Python.

---

## 3. Запуск проверок

Проверки стенда собираются pytest **только** при переменной `MSP_GATEWAY_TESTS=1`: они поднимают контейнеры и идут
минуты, поэтому в обычный прогон не входят.

```bash
# всё сразу (около 12 минут)
MSP_GATEWAY_TESTS=1 python -m pytest tests/gateway -q -o addopts=""

# отдельные группы
MSP_GATEWAY_TESTS=1 python -m pytest tests/gateway/test_open_relay.py -q -o addopts=""
MSP_GATEWAY_TESTS=1 python -m pytest tests/gateway/test_durability.py -q -o addopts=""
MSP_GATEWAY_TESTS=1 python -m pytest tests/gateway/test_panel_integration.py -q -o addopts=""
```

| Файл | Что проверяет |
|---|---|
| `test_smoke.py` | запуск и доставка от внешнего источника до двойника Exchange |
| `test_open_relay.py` | матрица «открытый релей»: кто, откуда, кому и на какой порт |
| `test_config_activation.py` | применение, откат, дрейф конфигурации |
| `test_durability.py` | сохранность принятой почты при сбоях Exchange, рестартах и `SIGKILL` |
| `test_recipients_live.py` | справочник, обновление без отказов, свежесть и закрытие приёма |
| `test_tls_downstream.py` | просроченный/чужой/неизвестный сертификат Exchange |
| `test_protocol.py` | пустой отправитель, целостность тела, контрабанда SMTP, лимиты, петли |
| `test_drain.py` | режим слива |
| `test_pressure_and_load.py` | давление на диск, параллельные сессии, размеры, медленный Exchange, пачка |
| `test_metrics_live.py`, `test_monitoring_live.py` | метрики, пробы, сертификаты, дрейф, отчёт сборщика |
| `test_shadow_live.py` | теневая копия, сборщик, изоляция журнала |
| `test_panel_integration.py` | панель ↔ узел: конфигурация, справочник, слив, повтор доставки, копии, перебои панели, враждебный пакет |
| `test_sandbox_container.py` | контейнер песочницы вложений |

Если стенд не поднялся, тест падает с журналом контейнера в сообщении. Если Docker недоступен, тесты помечаются
как **провал** (`xfail strict`), а не как пропуск: пропуск в зелёном отчёте выглядит как проверенное.

### Проверки под Linux

Часть проверок зависит от платформы (символические ссылки, пределы процесса `RLIMIT_*`, права). На Windows они
пропускаются, поэтому «зелёное» там ничего не доказывает про Linux, где шлюз и работает:

```bash
python scripts/linux_pytest.py tests/unit -k gateway
python scripts/linux_pytest.py --sandbox tests/unit/test_attachment_sandbox.py
```

Скрипт запускает тесты в чистом контейнере `python:3.12-slim`, репозиторий монтируется только для чтения.

---

## 4. Ручной запуск стенда

Каталог стенда должен содержать `bootstrap/` (пакет начальной конфигурации), `bundles/` и `secrets/`; удобнее всего
создать их кодом проверок:

```python
from pathlib import Path
from tests.gateway.harness import Stack, lab_spec, LAB_RECIPIENTS

stack = Stack(Path("/tmp/gw-lab"))
stack.up(lab_spec(), LAB_RECIPIENTS)  # выпускает сертификаты, собирает образы, поднимает стенд
print(stack.ports)  # свободные loopback-порты: 25, 2525, метрики, управление двойниками
...
stack.down()  # снести стенд вместе с томами
```

Отправка письма с хоста: SMTP на `127.0.0.1:<GW_PORT_IN>`. Метрики: `http://127.0.0.1:<GW_PORT_METRICS>/metrics`.

---

## 5. Что НЕ делает стенд

Не отправляет почту наружу; не использует боевые домены и MX; не меняет DNS; не требует и не использует учётные
данные организации. Все домены в стенде зарезервированы (`.example`, `.invalid`, `.test`) и нигде не
разрешаются.
