import { useEffect, useState } from "react";
import { ApiError, pilotApi, type PilotMetrics, type PilotReadiness } from "../api/client";

/**
 * Пилот реального потока (MSP 1.3P). Страница только читает.
 *
 * Итог вычисляется сервером и вручную не назначается. Здесь нет ни одной кнопки, которая включала бы контроль или
 * принимала решение: решения о фазах, подтверждения среды и остановки ведутся по API и runbook, а контроли переключаются
 * на странице «Принуждение» под четыре глаза. Отсутствующее значение (нет знаменателя) показывается как «—», а не как ноль.
 */

const DECISION_LABEL: Record<string, string> = {
  NOT_READY: "Не готово",
  READY_WITH_WARNINGS: "Готово с замечаниями",
  READY_FOR_MSP_1_4: "Готово к MSP 1.4",
};

function pct(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `${(value * 100).toFixed(2)} %`;
}

function num(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : String(value);
}

function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return error instanceof Error ? error.message : "Неизвестная ошибка";
}

export function PilotPage() {
  const [ready, setReady] = useState<PilotReadiness | null>(null);
  const [metrics, setMetrics] = useState<PilotMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([pilotApi.readiness(), pilotApi.metrics()])
      .then(([r, m]) => {
        setReady(r);
        setMetrics(m);
        setError(null);
      })
      .catch((e) => setError(errorText(e)));
  }, []);

  if (error) return <p role="alert">{error}</p>;
  if (!ready || !metrics) return <p>Загрузка…</p>;

  const s = metrics.sample;
  return (
    <div>
      <h1>Пилот реального потока</h1>
      <p>
        <strong>{ready.warning}</strong>
      </p>

      <section>
        <h2>Итог: {DECISION_LABEL[ready.decision] ?? ready.decision}</h2>
        {ready.stopped ? <p role="alert">Есть открытая остановка: все фазы закрыты.</p> : null}
        {ready.decision_reasons.length > 0 ? <p>Причины: {ready.decision_reasons.join(", ")}</p> : null}
        <p>Итог вычисляется и вручную не назначается. При нуле реальных писем он всегда «Не готово».</p>
      </section>

      <section>
        <h2>Выборка</h2>
        <table>
          <tbody>
            <tr>
              <td>Уникальных реальных писем</td>
              <td>
                {s.real_unique} из {metrics.targets.real_unique}
              </td>
            </tr>
            <tr>
              <td>Просмотрено реальных</td>
              <td>
                {s.real_reviewed} из {metrics.targets.reviewed_real}
              </td>
            </tr>
            <tr>
              <td>Из ящика безопасности (смещённая выборка, не засчитывается)</td>
              <td>{s.biased_real_security_mailbox}</td>
            </tr>
            <tr>
              <td>Загружено аналитиком / учения (не засчитываются)</td>
              <td>
                {s.imported_analyst_upload} / {s.drills}
              </td>
            </tr>
            <tr>
              <td>Лабораторные сканирования (не засчитываются)</td>
              <td>{metrics.synthetic_lab_scans}</td>
            </tr>
            <tr>
              <td>Непроверенных на 1000 (неизвестно / не проверялось)</td>
              <td>
                {num(s.unknown_per_1000)} / {num(s.unscannable_per_1000)}
              </td>
            </tr>
            <tr>
              <td>Критических ложных</td>
              <td>{metrics.critical_fp}</td>
            </tr>
            <tr>
              <td>Покрытие просмотра применённых отказов / карантина</td>
              <td>
                {pct(metrics.applied.applied_rejects_review_coverage)} /{" "}
                {pct(metrics.applied.applied_quarantines_review_coverage)}
              </td>
            </tr>
          </tbody>
        </table>
        <p>
          Источники реальной выборки:{" "}
          {Object.keys(s.real_by_source).length === 0
            ? "—"
            : Object.entries(s.real_by_source)
                .map(([k, v]) => `${k}: ${v}`)
                .join(", ")}
        </p>
      </section>

      <section>
        <h2>Фазы</h2>
        <table>
          <thead>
            <tr>
              <th>Фаза</th>
              <th>Решение</th>
              <th>Можно принять GO</th>
              <th>Мешает</th>
            </tr>
          </thead>
          <tbody>
            {ready.phases.map((p) => (
              <tr key={p.phase}>
                <td>{p.phase}</td>
                <td>
                  {p.decision
                    ? `${p.decision.state} (${p.decision.approvals.length}/${p.decision.required_roles.length})`
                    : "нет"}
                </td>
                <td>{p.go_possible ? "да" : "нет"}</td>
                <td>{p.blocking.length === 0 ? "—" : p.blocking.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Контроли по реальной выборке</h2>
        <table>
          <thead>
            <tr>
              <th>Контроль</th>
              <th>Состояние</th>
              <th>Готовность</th>
              <th>Просмотрено / ложных</th>
              <th>Доля / граница Вильсона</th>
            </tr>
          </thead>
          <tbody>
            {ready.controls.map((c) => (
              <tr key={c.control}>
                <td>{c.control}</td>
                <td>{c.state}</td>
                <td>{c.blocked_by_gap ? "BLOCKED_BY_GAP" : c.pilot_readiness}</td>
                <td>
                  {c.real_reviewed_rejects} / {c.real_confirmed_fp}
                </td>
                <td>
                  {pct(c.statistics.observed_fp_rate)} / {pct(c.statistics.wilson_upper_95)} (n=
                  {c.statistics.sample_size}; без ошибок до порога нужно {c.statistics.sample_for_zero_failures})
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Подтверждения среды</h2>
        <table>
          <thead>
            <tr>
              <th>Условие</th>
              <th>Вход в фазу</th>
              <th>Статус</th>
              <th>Ссылка на доказательство</th>
            </tr>
          </thead>
          <tbody>
            {ready.attestations.map((a) => (
              <tr key={a.key}>
                <td>{a.title}</td>
                <td>{a.phase}</td>
                <td>{a.status}</td>
                <td>{a.evidence_ref || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
