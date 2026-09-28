import { useCallback, useEffect, useState } from "react";
import { api, type CurrentUser } from "../api/client";

interface ReportPayload {
  report: string;
  period: { from: string; to: string; days: string };
  generated_at: string;
  summary: Record<string, unknown>;
  rows: Record<string, unknown>[];
}

const REPORT_LABELS: Record<string, string> = {
  phishing_summary: "Сводка по фишингу",
  incidents: "Инциденты",
  campaigns: "Кампании",
  impersonated_identities: "Подделываемые идентичности",
  employee_reporting: "Обращения сотрудников",
  false_positives: "Ложные срабатывания и исключения",
  provider_availability: "Доступность источников",
  indicators: "Индикаторы",
  audit: "Журнал аудита",
};

const SUMMARY_LABELS: Record<string, string> = {
  analyses: "Проверок",
  employee_reports: "Обращений сотрудников",
  incidents_created: "Создано инцидентов",
  active_campaigns: "Активных кампаний",
  total: "Всего",
  confirmed: "Подтверждено",
  false_positives: "Ложных срабатываний",
  mean_minutes_to_triage: "Среднее время до триажа, мин",
  mean_minutes_to_remediate: "Среднее время до реагирования, мин",
  exceptions_total: "Исключений всего",
  exceptions_active: "Действующих исключений",
  exceptions_without_expiry: "Бессрочных исключений",
  signals_suppressed_in_period: "Подавлено сигналов за период",
  reporters: "Сотрудников сообщили",
  total_reports: "Всего обращений",
  providers: "Источников",
  largest: "Крупнейшая кампания",
  confirmed_malicious: "Подтверждённо вредоносных",
  total_signals: "Сигналов",
};

function formatSummaryValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function ReportsPage({ user }: { user: CurrentUser }) {
  const [available, setAvailable] = useState<string[]>([]);
  const [selected, setSelected] = useState("phishing_summary");
  const [days, setDays] = useState(7);
  const [report, setReport] = useState<ReportPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const canExport = user.permissions.includes("export:data");

  useEffect(() => {
    void api
      .reportList()
      .then((data) => setAvailable(data.reports ?? []))
      .catch(() => setAvailable([]));
  }, []);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setReport((await api.report(selected, days)) as ReportPayload);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось построить отчёт");
    } finally {
      setBusy(false);
    }
  }, [selected, days]);

  useEffect(() => {
    void load();
  }, [load]);

  function downloadCsv() {
    // The export is audited server-side; the browser just follows the link.
    window.location.href = api.reportCsvUrl(selected, days);
  }

  const columns = report && report.rows.length > 0 ? Object.keys(report.rows[0]!) : [];

  return (
    <div className="page">
      <h1>Отчёты</h1>

      <div className="filters card">
        <select value={selected} onChange={(e) => setSelected(e.target.value)}>
          {available.map((name) => (
            <option key={name} value={name}>
              {REPORT_LABELS[name] ?? name}
            </option>
          ))}
        </select>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
          <option value={7}>7 дней</option>
          <option value={30}>30 дней</option>
          <option value={90}>90 дней</option>
        </select>
        <button type="button" className="button" disabled={busy} onClick={() => void load()}>
          Обновить
        </button>
        {canExport && (
          <button type="button" className="button button--primary" onClick={downloadCsv}>
            Выгрузить CSV
          </button>
        )}
      </div>

      {error && <div className="error">{error}</div>}

      {report && (
        <>
          <section className="card">
            <h2>{REPORT_LABELS[report.report] ?? report.report}</h2>
            <div className="tiles">
              {Object.entries(report.summary)
                .filter(([key]) => key !== "note")
                .map(([key, value]) => (
                  <div className="tile" key={key}>
                    <div className="tile__value">{formatSummaryValue(value)}</div>
                    <div className="tile__label">{SUMMARY_LABELS[key] ?? key}</div>
                  </div>
                ))}
            </div>
            {typeof report.summary.note === "string" && (
              <p className="notice notice--info">{report.summary.note}</p>
            )}
          </section>

          <section className="card">
            <table className="table table--compact">
              <thead>
                <tr>
                  {columns.map((column) => (
                    <th key={column}>{column}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.rows.map((row, index) => (
                  <tr key={index}>
                    {columns.map((column) => (
                      <td key={column}>{formatSummaryValue(row[column])}</td>
                    ))}
                  </tr>
                ))}
                {report.rows.length === 0 && (
                  <tr>
                    <td colSpan={Math.max(columns.length, 1)} className="muted">
                      Данных за период нет
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
