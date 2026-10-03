import { useCallback, useEffect, useState } from "react";
import { api, type CurrentUser, type ReanalysisJob } from "../api/client";
import { RISK_LABELS, formatDate } from "../types";

/**
 * Historical re-evaluation (ТЗ 1.0.3B §23).
 *
 * Re-running a month of mail through new rules is the single operation most able to flood an
 * organisation with alarms about messages people dealt with weeks ago. The page is built around
 * keeping it an analysis: a dry run by default, a visible ceiling, a progress figure, and pause
 * and cancel that take effect between slices rather than by killing a worker.
 */

const STATE_LABELS: Record<string, string> = {
  QUEUED: "в очереди",
  RUNNING: "выполняется",
  PAUSED: "приостановлено",
  CANCELLED: "отменено",
  COMPLETED: "завершено",
  FAILED: "ошибка",
};

export function ReevaluationPage({ user }: { user: CurrentUser }) {
  const [jobs, setJobs] = useState<ReanalysisJob[]>([]);
  const [days, setDays] = useState(7);
  const [dryRun, setDryRun] = useState(true);
  const [maxMessages, setMaxMessages] = useState(2000);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const canRun = user.permissions.includes("detection:replay");

  const load = useCallback(() => {
    void api
      .reanalysisJobs()
      .then(setJobs)
      .catch((e) => setError(e instanceof Error ? e.message : "Ошибка загрузки"));
  }, []);

  useEffect(load, [load]);

  const act = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось выполнить действие");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <h1>Переоценка истории</h1>
      <p className="muted small">
        Прогон уже проанализированной почты через действующий пакет правил. По умолчанию — без
        применения: ответ остаётся предложением, пока человек не решит иначе. Уведомления и
        реагирование не выполняются никогда, что бы ни показали новые вердикты.
      </p>

      {canRun && (
        <section className="card">
          <div className="card__header">
            <h2>Новое задание</h2>
          </div>
          <div className="form-row">
            <label>
              Период
              <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
                <option value={1}>последние сутки</option>
                <option value={7}>7 дней</option>
                <option value={30}>30 дней</option>
                <option value={90}>90 дней</option>
              </select>
            </label>
            <label>
              Предел писем
              <input
                type="number"
                min={1}
                max={20000}
                value={maxMessages}
                onChange={(e) => setMaxMessages(Number(e.target.value))}
              />
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={dryRun}
                onChange={(e) => setDryRun(e.target.checked)}
              />
              Без применения (dry run)
            </label>
            <button
              type="button"
              className="button button--primary"
              disabled={busy}
              onClick={() =>
                void act(() =>
                  api.createReanalysisJob({
                    days,
                    dry_run: dryRun,
                    max_messages: maxMessages,
                  }),
                )
              }
            >
              Создать
            </button>
          </div>
          {!dryRun && (
            <div className="notice notice--warning">
              Задание изменит сохранённые вердикты. Прежние значения остаются в ревизиях анализа,
              но карточки писем начнут показывать новые — убедитесь, что этого и хотели.
            </div>
          )}
        </section>
      )}

      {error && <div className="error">{error}</div>}

      <section className="card">
        <div className="card__header">
          <h2>Задания</h2>
        </div>
        {jobs.length === 0 ? (
          <p className="muted">Заданий нет.</p>
        ) : (
          jobs.map((job) => (
            <article key={job.job_id} className="card">
              <div className="card__header">
                <h3>
                  {formatDate(job.window_from)} — {formatDate(job.window_to)}
                </h3>
                <span className="tag">{STATE_LABELS[job.state] ?? job.state}</span>
              </div>
              <ul className="inline-list small">
                <li>{job.dry_run ? "без применения" : "с применением"}</li>
                <li>
                  обработано {job.processed} из {job.total_messages}
                </li>
                <li>
                  прогресс:{" "}
                  {job.progress === null ? "—" : `${Math.round(job.progress * 100)}%`}
                </li>
                <li>изменилось вердиктов: {job.verdict_changed}</li>
                <li>повышено: {job.newly_suspicious}</li>
                <li>понижено: {job.newly_cleared}</li>
                <li>запросил: {job.requested_by}</li>
              </ul>

              {canRun && (
                <div className="actions">
                  {(job.state === "QUEUED" || job.state === "PAUSED") && (
                    <button
                      type="button"
                      className="button button--tiny"
                      disabled={busy}
                      onClick={() => void act(() => api.runReanalysisJob(job.job_id))}
                    >
                      {job.state === "PAUSED" ? "Продолжить" : "Запустить"}
                    </button>
                  )}
                  {job.state === "RUNNING" && (
                    <button
                      type="button"
                      className="button button--tiny"
                      disabled={busy}
                      onClick={() => void act(() => api.pauseReanalysisJob(job.job_id))}
                    >
                      Приостановить
                    </button>
                  )}
                  {job.state !== "COMPLETED" && job.state !== "CANCELLED" && (
                    <button
                      type="button"
                      className="button button--tiny button--danger"
                      disabled={busy}
                      onClick={() => void act(() => api.cancelReanalysisJob(job.job_id))}
                    >
                      Отменить
                    </button>
                  )}
                </div>
              )}

              {job.sample.length > 0 && (
                <table className="table table--compact">
                  <thead>
                    <tr>
                      <th>Тема</th>
                      <th>Было</th>
                      <th>Стало</th>
                    </tr>
                  </thead>
                  <tbody>
                    {job.sample.slice(0, 20).map((row, index) => (
                      <tr key={`${String(row.message_id)}-${index}`}>
                        <td>{String(row.subject || "—")}</td>
                        <td>{RISK_LABELS[String(row.before)] ?? String(row.before)}</td>
                        <td className={row.escalated ? "danger" : undefined}>
                          {RISK_LABELS[String(row.after)] ?? String(row.after)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </article>
          ))
        )}
      </section>
    </div>
  );
}
