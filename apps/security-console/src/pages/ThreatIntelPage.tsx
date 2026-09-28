import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, type MessageSummary } from "../api/client";
import { RISK_LABELS, formatDate } from "../types";

interface ProviderResult {
  provider_id: string;
  status: string;
  malicious_count: number | null;
  total_count: number | null;
  categories: string[];
  summary: Record<string, unknown>;
  from_cache: boolean;
  fetched_at: string;
  cache_age: string | null;
  error: string | null;
}

interface IndicatorDetail {
  indicator: {
    indicator_id: string;
    ioc_type: string;
    value: string;
    first_seen: string;
    last_seen: string;
    sighting_count: number;
    worst_status: string | null;
    confirmed_malicious: boolean;
  };
  internal_sightings: number;
  related_messages: MessageSummary[];
  provider_results: ProviderResult[];
  related_campaigns: string[];
}

const IOC_TYPES = [
  { value: "domain", label: "Домен" },
  { value: "url", label: "URL" },
  { value: "sha256", label: "SHA-256" },
  { value: "ipv4", label: "IPv4" },
  { value: "ipv6", label: "IPv6" },
  { value: "email", label: "Адрес" },
];

/**
 * Provider statuses are shown with their meaning spelled out, because the difference between
 * "nothing negative is known" and "safe" is exactly where analysts make mistakes (ТЗ 13.3).
 */
const STATUS_MEANING: Record<string, { label: string; tone: string; note: string }> = {
  KNOWN_BAD: { label: "Известен как вредоносный", tone: "critical", note: "" },
  SUSPICIOUS: { label: "Подозрительный", tone: "medium", note: "" },
  NO_NEGATIVE_REPUTATION: {
    label: "Негативной репутации нет",
    tone: "low",
    note: "Это не означает «безопасно»: у источника просто нет отрицательных данных.",
  },
  UNKNOWN: { label: "Неизвестен источнику", tone: "unknown", note: "Индикатор источнику не встречался." },
  NOT_SUPPORTED: { label: "Тип не поддерживается", tone: "unknown", note: "" },
  RATE_LIMITED: { label: "Лимит запросов", tone: "medium", note: "Проверка не выполнена." },
  PROVIDER_UNAVAILABLE: { label: "Источник недоступен", tone: "medium", note: "Проверка не выполнена." },
  POLICY_BLOCKED: {
    label: "Запрещено политикой",
    tone: "unknown",
    note: "Запрос не отправлялся: политика приватности не разрешает передачу этого индикатора.",
  },
  ERROR: { label: "Ошибка источника", tone: "medium", note: "Проверка не выполнена." },
};

export function ThreatIntelPage() {
  const [iocType, setIocType] = useState("domain");
  const [value, setValue] = useState("");
  const [detail, setDetail] = useState<IndicatorDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function search(event: FormEvent) {
    event.preventDefault();
    if (!value.trim()) return;
    setBusy(true);
    setError(null);
    setDetail(null);
    try {
      const data = (await api.indicator(iocType, value.trim())) as unknown as IndicatorDetail;
      setDetail(data);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setError("Индикатор не встречался в письмах организации.");
      } else {
        setError(e instanceof Error ? e.message : "Ошибка поиска");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <h1>Threat Intelligence</h1>

      <form className="filters card" onSubmit={search}>
        <select value={iocType} onChange={(e) => setIocType(e.target.value)}>
          {IOC_TYPES.map((type) => (
            <option key={type.value} value={type.value}>
              {type.label}
            </option>
          ))}
        </select>
        <input
          placeholder="Значение индикатора"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          size={48}
        />
        <button type="submit" className="button button--primary" disabled={busy}>
          Найти
        </button>
      </form>

      {error && <div className="notice notice--info">{error}</div>}

      {detail && (
        <>
          <section className="card">
            <h2>
              <code>{detail.indicator.value}</code>
              {detail.indicator.confirmed_malicious && (
                <span className="tag tag--critical">подтверждён вредоносным</span>
              )}
            </h2>
            <ul className="inline-list">
              <li>Тип: {detail.indicator.ioc_type}</li>
              <li>Впервые: {formatDate(detail.indicator.first_seen)}</li>
              <li>Последний раз: {formatDate(detail.indicator.last_seen)}</li>
              <li>
                Наблюдений внутри организации: <strong>{detail.internal_sightings}</strong>
              </li>
              {detail.related_campaigns.length > 0 && (
                <li>Связанных кампаний: {detail.related_campaigns.length}</li>
              )}
            </ul>
          </section>

          <section className="card">
            <h2>Вердикты источников</h2>
            {detail.provider_results.length === 0 ? (
              <p className="muted">
                Внешние источники по этому индикатору не опрашивались. Отсутствие данных
                не является признаком безопасности.
              </p>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>Источник</th>
                    <th>Вердикт</th>
                    <th>Обнаружений</th>
                    <th>Категории</th>
                    <th>Актуальность</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.provider_results.map((result) => {
                    const meaning = STATUS_MEANING[result.status] ?? {
                      label: result.status,
                      tone: "unknown",
                      note: "",
                    };
                    return (
                      <tr key={result.provider_id}>
                        <td>{result.provider_id}</td>
                        <td>
                          <span className={`tag tag--${meaning.tone}`}>{meaning.label}</span>
                          {meaning.note && <div className="muted">{meaning.note}</div>}
                          {result.error && <div className="muted">{result.error}</div>}
                        </td>
                        <td>
                          {result.malicious_count !== null && result.total_count !== null
                            ? `${result.malicious_count} / ${result.total_count}`
                            : "—"}
                        </td>
                        <td>
                          {result.categories.map((category) => (
                            <span key={category} className="tag">
                              {category}
                            </span>
                          ))}
                        </td>
                        <td>
                          {result.cache_age ?? "—"}
                          {result.from_cache && <div className="muted">из кэша</div>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </section>

          <section className="card">
            <h2>Письма с этим индикатором</h2>
            <table className="table">
              <thead>
                <tr>
                  <th>Получено</th>
                  <th>Отправитель</th>
                  <th>Тема</th>
                  <th>Вердикт</th>
                </tr>
              </thead>
              <tbody>
                {detail.related_messages.map((message) => (
                  <tr key={message.message_id}>
                    <td>{formatDate(message.received_at)}</td>
                    <td>
                      <code className="muted">{message.sender_address}</code>
                    </td>
                    <td>
                      <Link to={`/messages/${message.message_id}`}>
                        {message.subject || "(без темы)"}
                      </Link>
                    </td>
                    <td>
                      {message.classification && (
                        <span className={`badge badge--${message.classification.toLowerCase()}`}>
                          {RISK_LABELS[message.classification]}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
                {detail.related_messages.length === 0 && (
                  <tr>
                    <td colSpan={4} className="muted">
                      Писем не найдено
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </section>
        </>
      )}
    </div>
  );
}
