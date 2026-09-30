# Контракт провайдера почтового шлюза

**Относится к:** ТЗ 1.0.2 §14–17, §22, §26–31
**Реализация:** `providers/mail-gateway/msp_mail_gateway/`

---

## 1. Зачем контракт

MSP не должен зависеть от производителя шлюза. Организация может работать вообще без SEG, с
KSMG, с FortiMail, с двумя разными шлюзами на входе и выходе — и ядро платформы во всех случаях
одинаково. Для этого любая интеграция со шлюзом живёт за одним Protocol, а ядро спрашивает
**возможности**, а не название продукта.

Отсутствие шлюза — поддерживаемая конфигурация, а не деградация: `GatewayState.NOT_PRESENT`
означает «шлюза нет», и это не ошибка (ТЗ 1.0.2 §31).

---

## 2. Protocol

```python
class MailGatewayProvider(Protocol):
    provider_id: str

    def health() -> ProviderHealth: ...
    def capabilities() -> set[GatewayCapability]: ...
    def parse_message_headers(headers, context) -> list[GatewayEvidence]: ...
    def get_message_trace(ref) -> MessageTrace | None: ...
    def get_verdict(ref) -> GatewayEvidence | None: ...
    def get_quarantine_status(ref) -> QuarantineStatus | None: ...
    def search_related(**criteria) -> list[GatewayMessageRef]: ...
    def propose_quarantine(refs) -> GatewayActionPlan: ...
    def execute_quarantine(refs, dry_run=True) -> GatewayActionResult: ...
    def release_message(ref, dry_run=True) -> GatewayActionResult: ...
    def block_sender(sender, dry_run=True) -> GatewayActionResult: ...
```

**Реализовывать всё не требуется.** Провайдер, умеющий только разбирать заголовки, — полноценный
провайдер. `BaseGatewayProvider` даёт отказ по умолчанию для всего остального, и отказ этот
честный: метод, который не реализован, возвращает план с перечнем блокеров, а не результат,
сообщающий об успехе.

---

## 3. GatewayCapability

Возможности **проверяются**, а не выводятся из названия продукта или его версии.

```text
HEADER_VERDICT     SYSLOG_EVENTS     MESSAGE_TRACE     API_VERDICT
QUARANTINE_READ    QUARANTINE_WRITE  RELEASE           SENDER_BLOCK
IOC_BLOCK          SEARCH            CAMPAIGN_DATA     SANDBOX_RESULT
AV_RESULT          SPAM_RESULT       PHISHING_RESULT
```

И backend, и UI используют capability probing:

```http
GET /api/v1/gateways/capabilities
```

```json
{
  "state": "HEALTHY",
  "by_provider": {"ksmg": ["AV_RESULT", "HEADER_VERDICT", "PHISHING_RESULT", "SPAM_RESULT"]},
  "by_capability": {"QUARANTINE_WRITE": [], "HEADER_VERDICT": ["ksmg"]}
}
```

Результат последней проверки хранится в `gateway_capability_states` вместе с отметкой времени.
Возможность, которая **исчезла**, записывается как недоступная, а не удаляется: её потеря —
эксплуатационное событие, которое стоит видеть.

Четыре возможности (`QUARANTINE_WRITE`, `RELEASE`, `SENDER_BLOCK`, `IOC_BLOCK`) собраны в
`WRITE_CAPABILITIES`. На этапе 1.0.2 их не заявляет ни один провайдер.

---

## 4. Нормализованная модель evidence

```python
GatewayEvidence
├── provider_id, provider_type
├── message_id, timestamp
├── verdict          GatewayVerdictType
├── category         antivirus | antispam | antiphishing | sandbox | reputation | policy | dlp
├── confidence       0..1  (ноль, если evidence не доверенное)
├── score            вендорская оценка, если есть
├── threat_name, engine, policy
├── source           header | syslog | api | manual
├── trusted          bool
├── trust_state      TrustState
├── trust_reason     человекочитаемое объяснение
├── raw_reference    указатель на оригинал
└── normalized_detail
```

`raw_reference` — это **указатель**, а не содержимое: имя заголовка, идентификатор syslog-события,
request id. Хранить полный ответ вендора значило бы завести вторую копию содержимого письма под
другой политикой хранения (ТЗ 1.0.2 §16, ТЗ 26.1).

`trust_reason` заполняется всегда, в том числе для доверенного evidence: аналитик должен видеть,
**почему** вердикт учтён, а не только что он учтён.

---

## 5. Семантика вердиктов

```text
MALICIOUS  PHISHING  SPAM  SUSPICIOUS  CLEAN_OBSERVED  UNKNOWN  ERROR
```

`CLEAN_OBSERVED` **не означает SAFE**. Это наблюдение о шлюзе, а не о письме: шлюз посмотрел и
ничего не сообщил. Правило закреплено в типе:

```python
@property
def lowers_risk(self) -> bool:
    """Всегда False."""
    return False
```

Это метод, а не комментарий, чтобы будущий адаптер не мог тихо предположить обратное. Проверяется
тестом `test_no_verdict_type_lowers_risk`.

Что вердикт шлюза может:

* **повысить** риск MSP (обнаружение — сигнал, а подтверждённое обнаружение вредоносного —
  жёсткий сигнал `upstream_malware_detection`);
* добавить evidence в карточку письма;
* повлиять на confidence.

Чего не может: понизить собственный вердикт MSP. Никогда, ни при каком уровне доверия.

---

## 6. Как провайдер получает контекст

Решение о доверии принимается **один раз на сообщение**, реестром, и передаётся каждому провайдеру:

```python
@dataclass
class GatewayContext:
    verification: ChainVerification   # какие узлы подтверждены в этом письме
    registered: bool                  # использует ли организация этот шлюз вообще
    internet_message_id: str
```

Провайдер не вычисляет доверие сам. Иначе адаптер мог бы — по ошибке или намеренно — доверять
собственным заголовкам.

---

## 7. Реестр

`GatewayRegistry` собирается из конфигурации организации (`build_registry`) и владеет топологией.

```python
registry = build_registry(session, settings, organization_id)
analysis = registry.analyze_message(
    parsed.headers,
    received=parsed.received,
    authentication_results=parsed.authentication_results,
    internet_message_id=parsed.message_id,
)
```

`analyze_message` дополнительно проверяет заголовки продуктов, **не** зарегистрированных в
организации: письмо с заголовками EOP в организации, где EOP не используется, получает evidence
с `trust_state=unknown_gateway`. Подделка отметки о проверке — известный приём, и молчать о ней
нельзя.

Результат превращается в `GatewayFindings` и передаётся в движок детектирования. Сам движок не
зависит ни от одного провайдера: он работает с типами из `msp_contracts`.

---

## 8. Корреляция между источниками

Один инцидент может содержать evidence от KSMG, Exchange, VirusTotal, правил MSP, контекста AD и
сообщения сотрудника. Отдельный инцидент на каждый источник не создаётся (ТЗ 1.0.2 §26).

Ключи корреляции (ТЗ 1.0.2 §23), хранятся в `message_traces`:

```text
RFC Message-ID · queue-id · отправитель · получатель
хеш темы · SHA-256 содержимого · SHA-256 вложения · время доставки
```

---

## 9. Конфликты

`ProviderConflict` описывает расхождение источников. Два из четырёх видов — **штатные**:

| Вид | Смысл |
|---|---|
| `GATEWAY_CLEAN_PLATFORM_HIGH` | шлюз ничего не нашёл, платформа считает письмо опасным. Обычный случай для BEC: письма без вложений и ссылок шлюз пропускает штатно |
| `GATEWAY_MALICIOUS_PLATFORM_LOW` | шлюз обнаружил вредоносное, платформа — нет. Вердикт **повышается** жёстким сигналом, а не оставляется человеку |
| `GATEWAY_DISAGREEMENT` | два шлюза разошлись |
| `HEADER_API_MISMATCH` | заголовки вендора расходятся с его же API — обычно ошибка корреляции |

Конфликты видимы аналитику до явного закрытия (`POST /api/v1/gateways/conflicts/{id}/resolve`).

---

## 10. Абстракция реагирования

`RemediationProvider` работает с тремя целями:

| Цель | Что делает | Состояние на 1.0.2 |
|---|---|---|
| `EXCHANGE` | перемещение в папку карантина, soft delete | выполняется, обратимо |
| `MAIL_GATEWAY` | карантин/выпуск/блокировка на шлюзе | **только чтение** |
| `MSP` | отметка внутри платформы, индикатор | выполняется, обратимо |

Последовательность одинакова для всех: `propose → dry-run → approve → execute → verify → audit`.

Шаг `verify` пропускать нельзя. Без него платформа сообщает о том, что **запросила**, а не о том,
что произошло, и частично применённое реагирование выглядит так же, как полное:

```python
verification = provider.verify(plan, targets)
verification.complete   # False, если хоть одно письмо осталось на месте
```

Реагирование на шлюзе на этапе 1.0.2 отключено **не настройкой**: запись не реализована, и план
об этом сообщает. Настройкой это не включается.

---

## 11. Добавление нового шлюза

Три пути, в порядке предпочтения:

1. **Конфигурацией, без кода** — `generic_header`, см.
   [`GENERIC_GATEWAY_INTEGRATION.md`](GENERIC_GATEWAY_INTEGRATION.md).
2. **Через syslog**, если шлюз не пишет заголовков, но пишет лог —
   [`SYSLOG_INTEGRATION.md`](SYSLOG_INTEGRATION.md).
3. **Собственным адаптером**, когда формат вендора не описывается отображением заголовков:
   унаследовать `BaseGatewayProvider`, переопределить `capabilities()` и
   `parse_message_headers()`, зарегистрировать в `PROVIDER_TYPES`.

Для FortiMail, Proofpoint, Mimecast и Cisco ESA разбор заголовков реализован и работает; API
объявлен контрактом и не реализован, пока нет реальной среды для проверки. Заявлять работающей
непроверенную интеграцию нельзя: «шлюз молчит» и «адаптер ничего не вернул» выглядят одинаково.

```python
from msp_mail_gateway import SKELETONS
provider = SKELETONS["fortimail"].build("fortimail-edge")
```

---

## 12. API

| Метод | Назначение |
|---|---|
| `GET /api/v1/gateways` | список шлюзов, состояние, возможности |
| `POST /api/v1/gateways` | добавить шлюз |
| `PUT /api/v1/gateways/{id}` | изменить или отключить |
| `POST /api/v1/gateways/{id}/hops` | добавить доверенный узел |
| `DELETE /api/v1/gateways/hops/{id}` | удалить узел |
| `POST /api/v1/gateways/probe` | перепроверить возможности |
| `GET /api/v1/gateways/capabilities` | матрица возможностей |
| `GET /api/v1/gateways/messages/{id}` | Upstream Protection для письма |
| `GET /api/v1/gateways/dead-letters` | отклонённые события |
| `POST /api/v1/gateways/conflicts/{id}/resolve` | закрыть расхождение |

Секреты в настройках шлюза не принимаются: поле с именем `password`, `token`, `api_key` и т. п.
вызывает отказ с объяснением, а не тихо отбрасывается — иначе администратор считал бы, что ключ
сохранён. Доступ к API шлюза настраивается ссылкой на хранилище секретов (`secret_ref`).
