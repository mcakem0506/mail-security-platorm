import { useCallback, useEffect, useState } from "react";
import {
  api,
  type CurrentUser,
  type DetectionRelease,
  type RuleCandidate,
} from "../api/client";
import { formatDate } from "../types";

/**
 * Candidate rule packs and detection releases (ТЗ 1.0.3B §10–§12, §24).
 *
 * A candidate is a pointer to a rule pack, not a copy of its rules: packs go through code
 * review, and one stored in the database could ship without anyone reading the diff. What this
 * page shows is the review — what the pack changes, what the golden corpus said about it, who
 * looked at it, and whether it may be released.
 */

const CANDIDATE_STATE_LABELS: Record<string, string> = {
  DRAFT: "черновик",
  READY_FOR_REVIEW: "на ревью",
  CHANGES_REQUESTED: "возвращён на доработку",
  APPROVED: "утверждён",
  PUBLISHED: "выпущен",
  REJECTED: "отклонён",
};

function ratio(value: unknown): string {
  return typeof value === "number" ? `${(value * 100).toFixed(1)}%` : "—";
}

function delta(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value > 0 ? `+${value}` : String(value);
}

export function ReleasesPage({ user }: { user: CurrentUser }) {
  const [candidates, setCandidates] = useState<RuleCandidate[]>([]);
  const [releases, setReleases] = useState<DetectionRelease[]>([]);
  const [name, setName] = useState("");
  const [source, setSource] = useState("rules");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const canEdit = user.permissions.includes("detection:edit");
  const canReview = user.permissions.includes("detection:review");
  const canPublish = user.permissions.includes("detection:publish");

  const load = useCallback(() => {
    const fail = (e: unknown) => setError(e instanceof Error ? e.message : "Ошибка загрузки");
    void api.candidates().then(setCandidates).catch(fail);
    void api.releases().then(setReleases).catch(fail);
  }, []);

  useEffect(load, [load]);

  const act = async (action: () => Promise<unknown>, message: string) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      setNotice(message);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось выполнить действие");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <h1>Выпуски детектирования</h1>

      {error && <div className="error">{error}</div>}
      {notice && <div className="notice notice--info">{notice}</div>}

      <section className="card">
        <div className="card__header">
          <h2>Кандидатские пакеты</h2>
        </div>
        <p className="muted small">
          Кандидат — это указатель на пакет правил, а не копия правил в базе. Правила проходят
          ревью кода; пакет, лежащий в базе, можно было бы выпустить, не показав диффа никому.
          Здесь хранится ревью: что меняется, что показал прогон по золотому корпусу, кто
          смотрел и можно ли выпускать.
        </p>

        {canEdit && (
          <div className="form-row">
            <label>
              Название
              <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            <label>
              Каталог с правилами
              <input type="text" value={source} onChange={(e) => setSource(e.target.value)} />
            </label>
            <button
              type="button"
              className="button"
              disabled={busy || name.trim().length < 3}
              onClick={() =>
                void act(
                  () => api.createCandidate({ name: name.trim(), source: source.trim() }),
                  "Кандидат создан и проверен.",
                )
              }
            >
              Создать
            </button>
          </div>
        )}

        {candidates.length === 0 ? (
          <p className="muted">Кандидатов нет.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Название</th>
                <th>Состояние</th>
                <th>Изменения</th>
                <th>Прогон по корпусу</th>
                <th>Автор / ревьюер</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {candidates.map((candidate) => (
                <tr key={candidate.candidate_id}>
                  <td>
                    {candidate.name}
                    <div className="small muted hash">{candidate.source}</div>
                  </td>
                  <td>
                    <span className="tag">
                      {CANDIDATE_STATE_LABELS[candidate.state] ?? candidate.state}
                    </span>
                    {candidate.critical_change && (
                      <div className="small danger">
                        критическое изменение — автор не может утвердить сам
                      </div>
                    )}
                  </td>
                  <td className="small">
                    + {candidate.added_rules.length} · ~ {candidate.changed_rules.length} · −{" "}
                    {candidate.removed_rules.length}
                    {candidate.critical_reasons.length > 0 && (
                      <ul className="inline-list">
                        {candidate.critical_reasons.slice(0, 3).map((reason) => (
                          <li key={reason}>{reason}</li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td className="small">
                    {candidate.benchmarked_at ? (
                      <>
                        precision {ratio(candidate.benchmark.precision)} · recall{" "}
                        {ratio(candidate.benchmark.recall)}
                        <div className="muted">
                          гейт:{" "}
                          {candidate.benchmark.gate_passed === true
                            ? "пройден"
                            : candidate.benchmark.gate_passed === false
                              ? "заблокирован"
                              : "—"}
                        </div>
                        {Array.isArray(candidate.benchmark.broken_cases) &&
                          (candidate.benchmark.broken_cases as string[]).length > 0 && (
                            <div className="danger">
                              ломает: {(candidate.benchmark.broken_cases as string[]).join(", ")}
                            </div>
                          )}
                      </>
                    ) : (
                      <span className="muted">не прогонялся</span>
                    )}
                  </td>
                  <td className="small">
                    {candidate.author}
                    {candidate.reviewer && <div className="muted">{candidate.reviewer}</div>}
                  </td>
                  <td>
                    <div className="actions">
                      {canEdit && candidate.state === "DRAFT" && (
                        <>
                          <button
                            type="button"
                            className="button button--tiny"
                            disabled={busy}
                            onClick={() =>
                              void act(
                                () => api.benchmarkCandidate(candidate.candidate_id),
                                "Прогон выполнен.",
                              )
                            }
                          >
                            Прогнать
                          </button>
                          <button
                            type="button"
                            className="button button--tiny"
                            disabled={busy || !candidate.benchmarked_at}
                            onClick={() =>
                              void act(
                                () => api.submitCandidate(candidate.candidate_id),
                                "Отправлено на ревью.",
                              )
                            }
                          >
                            На ревью
                          </button>
                        </>
                      )}
                      {canReview && candidate.state === "READY_FOR_REVIEW" && (
                        <>
                          <button
                            type="button"
                            className="button button--tiny"
                            disabled={busy}
                            onClick={() =>
                              void act(
                                () =>
                                  api.reviewCandidate(candidate.candidate_id, {
                                    approve: true,
                                    comment: window.prompt("Комментарий к утверждению:") ?? "",
                                  }),
                                "Кандидат утверждён.",
                              )
                            }
                          >
                            Утвердить
                          </button>
                          <button
                            type="button"
                            className="button button--tiny button--danger"
                            disabled={busy}
                            onClick={() => {
                              const comment = window.prompt("Что доработать (обязательно):");
                              if (!comment?.trim()) return;
                              void act(
                                () =>
                                  api.reviewCandidate(candidate.candidate_id, {
                                    approve: false,
                                    comment,
                                  }),
                                "Возвращено на доработку.",
                              );
                            }}
                          >
                            На доработку
                          </button>
                        </>
                      )}
                      {canPublish && candidate.state === "APPROVED" && (
                        <button
                          type="button"
                          className="button button--tiny button--primary"
                          disabled={busy}
                          onClick={() =>
                            void act(
                              () =>
                                api.publishRelease({ candidate_id: candidate.candidate_id }),
                              "Релиз опубликован.",
                            )
                          }
                        >
                          Выпустить
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <div className="card__header">
          <h2>Релизы</h2>
          {canPublish && (
            <button
              type="button"
              className="button button--ghost"
              disabled={busy}
              onClick={() => void act(() => api.publishRelease({}), "Релиз опубликован.")}
            >
              Выпустить текущий пакет
            </button>
          )}
        </div>
        <p className="muted small">
          Манифест фиксирует все версии, от которых зависит вердикт: те же правила на другом
          парсере — не то же самое детектирование. Известные пробелы входят в релиз: выпуск с
          тремя принятыми ограничениями — не то же, что выпуск без них.
        </p>
        {releases.length === 0 ? (
          <p className="muted">Релизов нет.</p>
        ) : (
          releases.map((release) => (
            <article key={release.release_id} className="card">
              <div className="card__header">
                <h3>{release.version}</h3>
                <span className="muted small">{formatDate(release.published_at)}</span>
              </div>
              <table className="table table--compact">
                <tbody>
                  <tr>
                    <th>Датасет</th>
                    <td>
                      {release.dataset_version} ({release.dataset_checksum.slice(0, 16)}…)
                    </td>
                  </tr>
                  <tr>
                    <th>Парсер / движок риска</th>
                    <td>
                      {release.parser_version} / {release.risk_engine_version}
                    </td>
                  </tr>
                  <tr>
                    <th>Коммит</th>
                    <td className="hash">{release.commit_sha.slice(0, 12) || "—"}</td>
                  </tr>
                  <tr>
                    <th>Правила: новые / изменённые / удалённые</th>
                    <td>
                      {release.new_rules.length} / {release.changed_rules.length} /{" "}
                      {release.removed_rules.length}
                    </td>
                  </tr>
                  <tr>
                    <th>Δ precision / recall</th>
                    <td>
                      {delta(release.metric_deltas.precision)} /{" "}
                      {delta(release.metric_deltas.recall)}
                    </td>
                  </tr>
                  <tr>
                    <th>Известные пробелы</th>
                    <td>
                      {release.known_limitations.length === 0
                        ? "нет"
                        : release.known_limitations
                            .map((gap) => String(gap.gap_id))
                            .join(", ")}
                    </td>
                  </tr>
                  <tr>
                    <th>Утвердил / выпустил</th>
                    <td>
                      {release.approved_by || "—"} / {release.published_by}
                    </td>
                  </tr>
                </tbody>
              </table>
            </article>
          ))
        )}
      </section>
    </div>
  );
}
