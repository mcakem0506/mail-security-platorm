import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type CurrentUser, type QueueItem } from "../api/client";
import { INCIDENT_STATUS_LABELS, SEVERITY_LABELS, formatDate } from "../types";

/**
 * The analyst work queue (ТЗ 1.0.3 §17, §18, §19).
 *
 * The page exists to answer one question — what to look at next — and it answers it with the
 * reasons attached. Priority is deliberately not the risk level: a MALICIOUS message delivered
 * to one person who already deleted it ranks below a HIGH_RISK campaign aimed at the finance
 * department. An analyst who cannot see why will override the order, so every row carries the
 * factors that produced its score.
 */

const PRIORITY_LABELS: Record<string, string> = {
  P1: "P1 — немедленно",
  P2: "P2 — в течение часа",
  P3: "P3 — в течение дня",
  P4: "P4 — в порядке очереди",
};

const SLA_LABELS: Record<string, string> = {
  ON_TIME: "в срок",
  DUE_SOON: "скоро истекает",
  BREACHED: "просрочено",
  MET: "выполнено",
  NOT_APPLICABLE: "—",
};

/** Human wording for the factor codes the priority engine returns. */
const FACTOR_LABELS: Record<string, string> = {
  verdict_malicious: "вердикт MALICIOUS",
  verdict_high_risk: "вердикт HIGH_RISK",
  verdict_suspicious: "вердикт SUSPICIOUS",
  vip_recipient: "получатель — руководитель",
  vip_finance_recipient: "руководитель финансового блока",
  protected_recipient: "защищаемая учётная запись",
  protected_finance_recipient: "защищаемая запись в финансовом блоке",
  finance_recipient: "получатель из финансового блока",
  payment_fraud: "признаки платёжного мошенничества",
  credential_theft: "признаки кражи учётных данных",
  malware: "признаки вредоносного вложения",
  multiple_recipients: "несколько получателей",
  campaign_large: "массовая рассылка",
  campaign_small: "рассылка на несколько адресов",
  employee_report: "сообщил сотрудник",
  gateway_conflict: "расхождение со шлюзом",
  already_remediated: "письма уже удалены",
  unscannable: "письмо не удалось проверить полностью",
  // Not a factor but a band correction, shown so the analyst sees why a high score did not
  // become P1 (ТЗ 1.0.3 §18: priority needs consequence *and* spread).
  single_recipient_reversible: "один адресат, последствие обратимо — понижено до P2",
};

function describeFactor(factor: string): string {
  // Factors arrive as "code:weight" or "code:weight (detail)". The code is what we translate;
  // the weight and detail are shown as they came, because they are evidence.
  const [head = factor, ...rest] = factor.split(":");
  const label = FACTOR_LABELS[head] ?? head;
  if (!rest.length) return label;
  const value = rest.join(":");
  // A band correction carries an arrow rather than points; "+P1→P2" would read as nonsense.
  return /^[-+]?\d/.test(value) ? `${label} (+${value})` : label;
}

function formatAge(seconds: number): string {
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))} мин`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)} ч`;
  return `${Math.round(seconds / 86_400)} дн`;
}

function remaining(item: QueueItem): string {
  const value = item.sla.remaining_seconds;
  if (value === null) return SLA_LABELS[item.sla.state] ?? item.sla.state;
  if (value < 0) return `просрочено на ${formatAge(-value)}`;
  return `осталось ${formatAge(value)}`;
}

export function QueuePage({ user }: { user: CurrentUser }) {
  const [items, setItems] = useState<QueueItem[]>([]);
  const [mine, setMine] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    void api
      .investigationQueue({ mine })
      .then(setItems)
      .catch((e) => setError(e instanceof Error ? e.message : "Ошибка загрузки"));
  }, [mine]);

  useEffect(load, [load]);

  const takeIt = async (incidentId: string) => {
    setBusy(incidentId);
    try {
      await api.assignIncident(incidentId, { assignee_email: user.email });
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось назначить");
    } finally {
      setBusy(null);
    }
  };

  const breached = items.filter((item) => item.sla.state === "BREACHED").length;
  const dueSoon = items.filter((item) => item.sla.state === "DUE_SOON").length;

  return (
    <div className="page">
      <div className="page__header">
        <h1>Очередь расследований</h1>
        <label className="checkbox">
          <input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} />
          Только мои
        </label>
      </div>

      <p className="muted small">
        Порядок задаётся приоритетом, а не уровнем риска: вредоносное письмо одному адресату
        может стоять ниже подозрительной рассылки на финансовый отдел. У каждой строки показаны
        факторы, из которых сложился приоритет.
      </p>

      <div className="tiles">
        <div className="tile">
          <div className="tile__label">В очереди</div>
          <div className="tile__value">{items.length}</div>
        </div>
        <div className={breached ? "tile tile--critical" : "tile"}>
          <div className="tile__label">Просрочено по SLA</div>
          <div className="tile__value">{breached}</div>
        </div>
        <div className={dueSoon ? "tile tile--medium" : "tile"}>
          <div className="tile__label">Срок подходит</div>
          <div className="tile__value">{dueSoon}</div>
        </div>
        <div className="tile">
          <div className="tile__label">P1</div>
          <div className="tile__value">{items.filter((i) => i.priority === "P1").length}</div>
        </div>
      </div>

      {error && <div className="error">{error}</div>}

      <section className="card">
        {items.length === 0 ? (
          <p className="muted">Очередь пуста.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Приоритет</th>
                <th>Инцидент</th>
                <th>Почему именно так</th>
                <th>Серьёзность</th>
                <th>Статус</th>
                <th>SLA</th>
                <th>В работе</th>
                <th>Исполнитель</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.incident_id}>
                  <td>
                    <span className={`badge badge--${item.priority === "P1" ? "malicious" : item.priority === "P2" ? "high_risk" : "suspicious"}`}>
                      {PRIORITY_LABELS[item.priority] ?? item.priority}
                    </span>
                    <div className="small muted">{item.priority_score} баллов</div>
                  </td>
                  <td>
                    <Link to={`/incidents?incident=${item.incident_id}`}>{item.title}</Link>
                    <div className="small muted">#{item.number}</div>
                    {item.analyst_classification && (
                      <div className="small">Классификация: {item.analyst_classification}</div>
                    )}
                  </td>
                  <td>
                    <ul className="inline-list small">
                      {item.priority_factors.map((factor) => (
                        <li key={factor}>{describeFactor(factor)}</li>
                      ))}
                    </ul>
                    {item.vip_involved && <span className="tag tag--high">руководитель</span>}
                    {item.employee_report && <span className="tag tag--reported">от сотрудника</span>}
                    {item.gateway_conflict && <span className="tag tag--flag">расхождение со шлюзом</span>}
                    {item.campaign_size > 1 && (
                      <span className="tag">кампания: {item.campaign_size}</span>
                    )}
                  </td>
                  <td>{SEVERITY_LABELS[item.severity] ?? item.severity}</td>
                  <td>{INCIDENT_STATUS_LABELS[item.status] ?? item.status}</td>
                  <td>
                    <span
                      className={
                        item.sla.state === "BREACHED"
                          ? "danger"
                          : item.sla.state === "DUE_SOON"
                            ? "warning"
                            : undefined
                      }
                    >
                      {remaining(item)}
                    </span>
                    <div className="small muted">{formatDate(item.sla.target)}</div>
                  </td>
                  <td>{formatAge(item.age_seconds)}</td>
                  <td>{item.assignee ?? <span className="muted">не назначен</span>}</td>
                  <td>
                    {item.assignee !== user.email && (
                      <button
                        type="button"
                        className="button button--tiny"
                        disabled={busy === item.incident_id}
                        onClick={() => void takeIt(item.incident_id)}
                      >
                        Взять
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
