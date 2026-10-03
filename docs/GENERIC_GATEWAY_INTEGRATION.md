# Подключение произвольного шлюза без изменения кода

**Относится к:** ТЗ 1.0.2 §19, §36
**Реализация:** `providers/mail-gateway/msp_mail_gateway/generic_header.py`, `skeletons.py`

---

## 1. Принцип

Новый шлюз не должен требовать нового кода. Провайдер `generic_header` полностью управляется
конфигурацией: администратор описывает, какие заголовки читать и как переводить их значения в
нормализованный вердикт.

Правила доверия при этом те же, что у любого другого провайдера: заголовки учитываются только
после подтверждения цепочкой `Received` (см. [`GATEWAY_TRUST_MODEL.md`](GATEWAY_TRUST_MODEL.md)).

---

## 2. Формат конфигурации

```yaml
provider: generic
provider_id: fortimail-edge
display_name: FortiMail
direction: inbound

trusted_hops:
  - hostname: mail-edge.corp.example
    ip_networks: [10.20.0.0/24]
    authserv_ids: [mail-edge.corp.example]

headers:
  verdict:
    - X-FE-Spam-Status
    - X-Virus-Status
  score:
    - X-FE-Spam-Score
  threat:
    - X-Virus-Name
  policy:
    - X-FE-Policy-ID

verdict_map:
  MALICIOUS:      [infected, detected, virus]
  PHISHING:       [phish]
  SPAM:           [yes, spam, bulk]
  SUSPICIOUS:     [probable]
  CLEAN_OBSERVED: [clean, no, passed]
```

Сокращённая форма для доверенных узлов тоже принимается — достаточно указать сеть или имя:

```yaml
trusted_hops:
  - 10.20.0.0/24
  - mail-edge.corp.example
```

### Разделы

| Раздел | Обязателен | Назначение |
|---|---|---|
| `headers.verdict` | да | заголовки, из которых читается вердикт |
| `headers.score` | нет | числовая оценка |
| `headers.threat` | нет | имя угрозы |
| `headers.policy` | нет | сработавшее правило шлюза |
| `verdict_map` | нет | отображение значений вендора на вердикты |
| `trusted_hops` | **практически да** | без них заголовки не будут учитываться |

`verdict_map` не обязателен: встроенный словарь в `msp_mail_gateway.headers` уже покрывает
распространённые написания (`clean`, `not detected`, `infected`, `yes`, `spam`, `probable` и
другие). Задавайте его, когда вендор использует собственные слова.

**Нераспознанное значение становится `UNKNOWN`, никогда `CLEAN_OBSERVED`.** Вердикт, который не
удалось прочитать, не сказал, что с письмом всё в порядке.

---

## 3. Через консоль

**Настройки → Почтовые шлюзы → Добавить шлюз**, тип провайдера `generic_header`. Отображение
заголовков задаётся в поле настроек шлюза; доверенные узлы добавляются отдельно.

Через API:

```bash
curl -X POST .../api/v1/gateways \
  -d '{
    "provider_id": "fortimail-edge",
    "provider_type": "generic_header",
    "display_name": "FortiMail",
    "settings": {
      "headers": {"verdict": ["X-FE-Spam-Status"], "score": ["X-FE-Spam-Score"]},
      "verdict_map": {"SPAM": ["yes"], "CLEAN_OBSERVED": ["no"]}
    }
  }'
```

Поля с именами `password`, `secret`, `token`, `api_key`, `credential`, `key` в настройках
**отклоняются с объяснением**, а не отбрасываются молча: иначе администратор считал бы, что
секрет сохранён. Доступ к API шлюза настраивается ссылкой на хранилище (`secret_ref`).

---

## 4. Профили из файлов

Набор профилей можно держать файлами:

```python
from msp_mail_gateway import load_profiles, GatewayRegistry

configs = load_profiles("/etc/msp/gateway-profiles")
registry = GatewayRegistry.from_configs(configs)
```

Каждый `*.yaml` в каталоге — один шлюз в формате из §2.

---

## 5. Готовые профили вендоров

Для FortiMail, Proofpoint, Mimecast и Cisco ESA формат заголовков задокументирован публично, и
разбор для них **реализован и работает**:

```python
from msp_mail_gateway import SKELETONS

skeleton = SKELETONS["proofpoint"]
provider = skeleton.build("proofpoint-edge")  # рабочий провайдер заголовков
skeleton.implemented  # что работает сейчас
skeleton.planned  # что даст API, когда будет реализован
skeleton.prerequisites  # что нужно от организации
```

| Продукт | Работает сейчас | Планируется через API |
|---|---|---|
| FortiMail | заголовки, AV, антиспам | вердикт API, трассировка, карантин |
| Proofpoint | заголовки, антиспам, антифишинг | вердикт API, кампании, песочница |
| Mimecast | заголовки, антиспам | вердикт API, выпуск, блокировка отправителя |
| Cisco ESA | заголовки, AV, антиспам | вердикт API, песочница |

Интеграция через API появится после получения реальной среды. Заявлять её работающей до проверки
нельзя: «шлюз молчит» и «адаптер ничего не вернул» выглядят для аналитика одинаково, и второе
опаснее, потому что выглядит как первое.

Что нужно от организации, чтобы адаптер API можно было написать и проверить:

* адрес API и версия продукта;
* сервисная учётная запись только на чтение;
* способ аутентификации и место хранения секрета;
* тестовая среда.

Список выводится в консоли на странице почтовых шлюзов.

---

## 6. Встроенные разборщики

Три формата распознаются без настройки, их достаточно включить как шлюз соответствующего типа:

| Тип | Что читает |
|---|---|
| `eop` | Exchange Online Protection: `X-Forefront-Antispam-Report` (SCL, BCL, PCL, CAT) |
| `spamassassin` | SpamAssassin, Rspamd: `X-Spam-Flag`, `X-Spam-Status`, `X-Spam-Level` |
| `generic_av` | amavis, ClamSMTP и другие: `X-Virus-Status`, `X-Virus-Scanned`, `X-Virus-Name` |

`X-Spam-Level` кодирует оценку числом звёздочек — это учитывается.

---

## 7. Проверка настройки

```bash
docker compose exec api python scripts/probe_exchange.py --section mailflow
```

Затем на тестовом письме:

```bash
curl .../api/v1/gateways/messages/$MESSAGE_ID | jq '.evidence[] | {provider_id, verdict, trusted, trust_reason}'
```

Если `trusted: false`, причина будет в `trust_reason`. Чаще всего это отсутствие доверенного узла
или несовпадение его имени с фактической цепочкой.

---

## 8. Типичные ошибки

| Симптом | Причина |
|---|---|
| evidence не появляется вовсе | ни один заголовок из `headers.verdict` не найден в письме |
| `verdict: UNKNOWN` | значение не распознано — добавьте его в `verdict_map` |
| `trusted: false` на всех письмах | не описаны доверенные узлы, либо имя узла не совпадает с цепочкой |
| сигнал подделки на обычной почте | описан шлюз, но не описан почтовый сервер, который пишет `Authentication-Results` |
