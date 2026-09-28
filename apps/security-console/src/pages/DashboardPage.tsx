import { useEffect, useState } from "react";
import { api } from "../api/client";
import { formatDate } from "../types";

interface Dashboard {
  analyses_today: number;
  suspicious: number;
  high_risk: number;
  malicious: number;
  unknown: number;
  open_incidents: number;
  active_campaigns: number;
  employee_reports_today: number;
  top_impersonated_identities: { signal: string; count: number }[];
  top_malicious_domains: { domain: string; sightings: number }[];
  top_reported_senders: { sender: string; reports: number }[];
  provider_health: { provider_id: string; status: string; mode: string | null; detail: string | null }[];
  generated_at: string;
}

function Tile({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className={`tile${tone ? ` tile--${tone}` : ""}`}>
      <div className="tile__value">{value}</div>
      <div className="tile__label">{label}</div>
    </div>
  );
}

export function DashboardPage() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api
      .dashboard()
      .then((d) => setData(d as unknown as Dashboard))
      .catch((e) => setError(e instanceof Error ? e.message : "Ошибка загрузки"));
  }, []);

  if (error) return <div className="error">{error}</div>;
  if (!data) return <div className="muted">Загрузка…</div>;

  return (
    <div className="page">
      <h1>Обзор</h1>
      <div className="tiles">
        <Tile label="Проверок за сутки" value={data.analyses_today} />
        <Tile label="Подозрительных" value={data.suspicious} tone="medium" />
        <Tile label="Высокий риск" value={data.high_risk} tone="high" />
        <Tile label="Вредоносных" value={data.malicious} tone="critical" />
        <Tile label="Неизвестно" value={data.unknown} tone="unknown" />
        <Tile label="Открытых инцидентов" value={data.open_incidents} />
        <Tile label="Активных кампаний" value={data.active_campaigns} />
        <Tile label="Обращений сотрудников" value={data.employee_reports_today} />
      </div>

      <section className="card">
        <h2>Состояние провайдеров</h2>
        <ul className="inline-list">
          {data.provider_health.map((provider) => (
            <li key={provider.provider_id}>
              <span className={`dot dot--${provider.status}`} /> {provider.provider_id}:{" "}
              <strong>{provider.status}</strong>
              {provider.detail && <span className="muted"> — {provider.detail}</span>}
            </li>
          ))}
        </ul>
        <p className="muted">
          Недоступность внешних источников не останавливает анализ: локальные проверки выполняются
          всегда, а отсутствие обнаружения не означает безопасность.
        </p>
      </section>

      <div className="columns">
        <section className="card">
          <h2>Чаще всего подделывают</h2>
          <ul>
            {data.top_impersonated_identities.map((item) => (
              <li key={item.signal}>
                {item.signal} <span className="muted">({item.count})</span>
              </li>
            ))}
            {data.top_impersonated_identities.length === 0 && <li className="muted">Нет данных</li>}
          </ul>
        </section>
        <section className="card">
          <h2>Вредоносные домены</h2>
          <ul>
            {data.top_malicious_domains.map((item) => (
              <li key={item.domain}>
                <code>{item.domain}</code> <span className="muted">({item.sightings})</span>
              </li>
            ))}
            {data.top_malicious_domains.length === 0 && <li className="muted">Нет данных</li>}
          </ul>
        </section>
        <section className="card">
          <h2>Чаще всего сообщают</h2>
          <ul>
            {data.top_reported_senders.map((item) => (
              <li key={item.sender}>
                {item.sender} <span className="muted">({item.reports})</span>
              </li>
            ))}
            {data.top_reported_senders.length === 0 && <li className="muted">Нет данных</li>}
          </ul>
        </section>
      </div>
      <p className="muted">Данные на {formatDate(data.generated_at)}</p>
    </div>
  );
}
