import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { formatDate } from "../types";

interface Campaign {
  campaign_id: string;
  name: string;
  first_seen: string;
  last_seen: string;
  message_count: number;
  recipient_count: number;
  reported_by_users: number;
  indicators: string[];
  verdict_distribution: Record<string, number>;
  confirmed_malicious: boolean;
  remediation_state: string;
  incident_id: string | null;
}

export function CampaignsPage() {
  const [items, setItems] = useState<Campaign[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [confirmedOnly, setConfirmedOnly] = useState(false);

  useEffect(() => {
    void api
      .campaigns({ confirmed_only: confirmedOnly })
      .then((data) => setItems(data.items as unknown as Campaign[]))
      .catch((e) => setError(e instanceof Error ? e.message : "Ошибка загрузки"));
  }, [confirmedOnly]);

  return (
    <div className="page">
      <h1>Кампании</h1>
      <label className="checkbox">
        <input
          type="checkbox"
          checked={confirmedOnly}
          onChange={(e) => setConfirmedOnly(e.target.checked)}
        />
        Только подтверждённые
      </label>
      {error && <div className="error">{error}</div>}
      <section className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Кампания</th>
              <th>Первое / последнее</th>
              <th>Писем</th>
              <th>Получателей</th>
              <th>От сотрудников</th>
              <th>Вердикты</th>
              <th>Реагирование</th>
            </tr>
          </thead>
          <tbody>
            {items.map((campaign) => (
              <tr key={campaign.campaign_id}>
                <td>
                  {campaign.name || "(без названия)"}
                  {campaign.confirmed_malicious && (
                    <span className="tag tag--critical">подтверждена</span>
                  )}
                  <div className="muted">
                    {campaign.indicators.slice(0, 3).map((indicator) => (
                      <code key={indicator} className="indicator">
                        {indicator}
                      </code>
                    ))}
                  </div>
                </td>
                <td>
                  {formatDate(campaign.first_seen)}
                  <div className="muted">{formatDate(campaign.last_seen)}</div>
                </td>
                <td>{campaign.message_count}</td>
                <td>{campaign.recipient_count}</td>
                <td>{campaign.reported_by_users}</td>
                <td>
                  {Object.entries(campaign.verdict_distribution).map(([verdict, count]) => (
                    <span key={verdict} className={`tag tag--${verdict.toLowerCase()}`}>
                      {verdict}: {count}
                    </span>
                  ))}
                </td>
                <td>
                  {campaign.incident_id ? (
                    <Link to="/incidents">инцидент</Link>
                  ) : (
                    <span className="muted">{campaign.remediation_state}</span>
                  )}
                </td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  Кампании не обнаружены
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
