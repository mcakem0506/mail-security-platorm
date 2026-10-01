import { useCallback, useEffect, useState } from "react";
import { api, type AnalystClassification, type CurrentUser } from "../api/client";
import { INCIDENT_STATUS_LABELS, SEVERITY_LABELS, formatDate } from "../types";

interface Incident {
  incident_id: string;
  number: number;
  title: string;
  summary: string;
  status: string;
  severity: string;
  confidence: string;
  assigned_to: string | null;
  opened_by: string | null;
  affected_users: string[];
  message_count: number;
  indicator_count: number;
  created_at: string;
  triaged_at: string | null;
  remediated_at: string | null;
  closed_at: string | null;
  timeline: { at: string; event: string; actor: string; detail: string }[];
}

interface Note {
  note_id: string;
  author: string;
  body: string;
  created_at: string;
}

/**
 * Analyst classification (ТЗ 1.0.3 §22, §23, §34).
 *
 * This is where every quality metric in the product comes from, which is why the form asks for
 * more than a verdict: naming the rules that produced a false positive is what turns "the
 * platform was wrong" into something a rule owner can act on. Closing a case as harmless
 * requires a reason, because that is the decision most likely to be re-read after an incident.
 */
const CLASSIFICATIONS: { value: AnalystClassification; label: string }[] = [
  { value: "CONFIRMED_PHISHING", label: "Подтверждён фишинг" },
  { value: "CONFIRMED_BEC", label: "Подтверждён BEC" },
  { value: "CONFIRMED_MALWARE", label: "Подтверждено ВПО" },
  { value: "SPAM", label: "Нежелательная почта" },
  { value: "LEGITIMATE", label: "Легитимное письмо" },
  { value: "FALSE_POSITIVE", label: "Ложное срабатывание" },
  { value: "BENIGN_SIMULATION", label: "Учебная рассылка" },
  { value: "UNKNOWN", label: "Не удалось определить" },
];

/** Verdicts meaning "nothing was wrong with this message". */
const BENIGN: AnalystClassification[] = ["LEGITIMATE", "FALSE_POSITIVE", "BENIGN_SIMULATION"];

const ROOT_CAUSES = [
  { value: "MISSING_FACT", label: "признак не извлечён" },
  { value: "MISSING_RULE", label: "нет подходящего правила" },
  { value: "PARSER_FAILURE", label: "не разобрано письмо или вложение" },
  { value: "PROVIDER_FAILURE", label: "не ответил внешний источник" },
  { value: "RULE_FAILURE", label: "правило есть, но не сработало" },
  { value: "RISK_AGGREGATION_FAILURE", label: "признаков хватало, но баллов — нет" },
  { value: "UNKNOWN", label: "причина не установлена" },
];

function ClassificationPanel({
  incidentId,
  onChanged,
}: {
  incidentId: string;
  onChanged: () => void;
}) {
  const [classification, setClassification] = useState<AnalystClassification>("CONFIRMED_PHISHING");
  const [comment, setComment] = useState("");
  const [rules, setRules] = useState("");
  const [confidence, setConfidence] = useState<"high" | "medium" | "low">("high");
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const benign = BENIGN.includes(classification);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.classifyIncident(incidentId, {
        classification,
        comment: comment.trim(),
        confidence,
        offending_rules: rules
          .split(/[\s,]+/)
          .map((value) => value.trim())
          .filter(Boolean),
      });
      const text = await api.employeeFeedback(incidentId);
      setFeedback(text.text);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось сохранить классификацию");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div className="card__header">
        <h3>Классификация аналитика</h3>
      </div>
      <p className="muted small">
        Из решений аналитика считаются все метрики качества. Инцидент, закрытый без
        классификации, выпадает из статистики молча.
      </p>
      <div className="form-row">
        <label>
          Решение
          <select
            value={classification}
            onChange={(e) => setClassification(e.target.value as AnalystClassification)}
          >
            {CLASSIFICATIONS.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Уверенность
          <select
            value={confidence}
            onChange={(e) => setConfidence(e.target.value as "high" | "medium" | "low")}
          >
            <option value="high">высокая</option>
            <option value="medium">средняя</option>
            <option value="low">низкая</option>
          </select>
        </label>
      </div>
      {benign && (
        <label>
          Правила, давшие ложное срабатывание
          <input
            type="text"
            value={rules}
            placeholder="например: BEC-014 SND-030"
            onChange={(e) => setRules(e.target.value)}
          />
          <span className="muted small">
            Необязательно, но именно это превращает «платформа ошиблась» в задачу владельцу
            правила.
          </span>
        </label>
      )}
      <label>
        Комментарий{benign ? " (обязателен)" : ""}
        <textarea rows={3} value={comment} onChange={(e) => setComment(e.target.value)} />
      </label>
      {error && <p className="error">{error}</p>}
      <button
        type="button"
        className="button button--primary"
        disabled={busy}
        onClick={() => void submit()}
      >
        Сохранить решение
      </button>
      {feedback && (
        <div className="notice notice--info">
          <strong>Формулировка для сотрудника:</strong>
          <p>{feedback}</p>
          <p className="muted small">
            Текст предлагается для проверки, а не отправляется автоматически. Платформа может
            сообщить, что угроз не обнаружено, но не может утверждать, что их нет.
          </p>
        </div>
      )}
    </div>
  );
}

/** Reporting a miss (ТЗ 1.0.3 §26): the platform cannot find its own false negatives. */
function MissedDetectionPanel({ incidentId }: { incidentId: string }) {
  const [open, setOpen] = useState(false);
  const [rootCause, setRootCause] = useState("MISSING_RULE");
  const [expected, setExpected] = useState("");
  const [comment, setComment] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    try {
      await api.reportMissedDetection({
        incident_id: incidentId,
        source: "ANALYST",
        root_cause: rootCause,
        expected_detection: expected.trim(),
        comment: comment.trim(),
      });
      setDone(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось зарегистрировать пропуск");
    }
  }

  if (!open) {
    return (
      <button type="button" className="button button--ghost" onClick={() => setOpen(true)}>
        Сообщить о пропущенном детекте
      </button>
    );
  }

  return (
    <div className="card">
      <div className="card__header">
        <h3>Пропущенный детект</h3>
      </div>
      <p className="muted small">
        Платформа не может обнаружить собственные пропуски, поэтому такая запись — единственный
        след того, что пропуск был. Укажите слой, который не сработал: от этого зависит, кто и
        где будет исправлять.
      </p>
      <label>
        Причина
        <select value={rootCause} onChange={(e) => setRootCause(e.target.value)}>
          {ROOT_CAUSES.map((item) => (
            <option key={item.value} value={item.value}>
              {item.label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Что должно было сработать
        <input type="text" value={expected} onChange={(e) => setExpected(e.target.value)} />
      </label>
      <label>
        Комментарий
        <textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} />
      </label>
      {error && <p className="error">{error}</p>}
      {done ? (
        <p className="tag tag--ok">Пропуск зарегистрирован</p>
      ) : (
        <button type="button" className="button" onClick={() => void submit()}>
          Зарегистрировать
        </button>
      )}
    </div>
  );
}

function IncidentDetail({ incident, canManage, onChanged }: { incident: Incident; canManage: boolean; onChanged: () => void }) {
  const [notes, setNotes] = useState<Note[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadNotes = useCallback(async () => {
    try {
      setNotes((await api.incidentNotes(incident.incident_id)) as unknown as Note[]);
    } catch {
      setNotes([]);
    }
  }, [incident.incident_id]);

  useEffect(() => {
    void loadNotes();
  }, [loadNotes]);

  async function changeStatus(status: string) {
    setBusy(true);
    setError(null);
    try {
      await api.updateIncident(incident.incident_id, { status });
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось изменить статус");
    } finally {
      setBusy(false);
    }
  }

  async function addNote() {
    if (!draft.trim()) return;
    setBusy(true);
    try {
      await api.addNote(incident.incident_id, draft.trim());
      setDraft("");
      await loadNotes();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось добавить заметку");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>
        #{incident.number} {incident.title}
      </h2>
      <p>{incident.summary}</p>
      <ul className="inline-list">
        <li>
          Статус: <strong>{INCIDENT_STATUS_LABELS[incident.status] ?? incident.status}</strong>
        </li>
        <li>
          Важность: <strong>{SEVERITY_LABELS[incident.severity] ?? incident.severity}</strong>
        </li>
        <li>Писем: {incident.message_count}</li>
        <li>Индикаторов: {incident.indicator_count}</li>
        <li>Затронуто пользователей: {incident.affected_users.length}</li>
      </ul>

      {canManage && (
        <div className="actions">
          {["TRIAGE", "INVESTIGATING", "CONFIRMED_PHISHING", "CONFIRMED_BEC", "FALSE_POSITIVE", "CLOSED"].map(
            (status) => (
              <button
                key={status}
                type="button"
                className="button button--tiny"
                disabled={busy || incident.status === status}
                onClick={() => void changeStatus(status)}
              >
                {INCIDENT_STATUS_LABELS[status]}
              </button>
            ),
          )}
        </div>
      )}
      {error && <p className="error">{error}</p>}

      <h3>Хронология</h3>
      <ul className="timeline">
        {incident.timeline.map((entry, index) => (
          <li key={`${entry.at}-${index}`}>
            <span className="muted">{formatDate(entry.at)}</span> — {entry.event}
            {entry.detail && <span className="muted"> ({entry.detail})</span>}
            <span className="muted"> · {entry.actor}</span>
          </li>
        ))}
      </ul>

      <h3>Заметки аналитика</h3>
      <ul className="notes">
        {notes.map((note) => (
          <li key={note.note_id}>
            <div className="muted">
              {note.author} · {formatDate(note.created_at)}
            </div>
            <div>{note.body}</div>
          </li>
        ))}
        {notes.length === 0 && <li className="muted">Заметок нет</li>}
      </ul>
      {canManage && (
        <>
          <ClassificationPanel incidentId={incident.incident_id} onChanged={onChanged} />
          <MissedDetectionPanel incidentId={incident.incident_id} />
        </>
      )}

      {canManage && (
        <div className="note-form">
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="Добавить заметку к расследованию"
            rows={3}
          />
          <button type="button" className="button" disabled={busy} onClick={() => void addNote()}>
            Добавить
          </button>
        </div>
      )}
    </section>
  );
}

export function IncidentsPage({ user }: { user: CurrentUser }) {
  const [items, setItems] = useState<Incident[]>([]);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canManage = user.permissions.includes("manage:incidents");

  const load = useCallback(async () => {
    try {
      const data = await api.incidents({ limit: 100 });
      const list = data.items as unknown as Incident[];
      setItems(list);
      setSelected((current) =>
        current ? list.find((item) => item.incident_id === current.incident_id) ?? null : null,
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Ошибка загрузки");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="page">
      <h1>Инциденты</h1>
      {error && <div className="error">{error}</div>}
      <section className="card">
        <table className="table">
          <thead>
            <tr>
              <th>#</th>
              <th>Название</th>
              <th>Статус</th>
              <th>Важность</th>
              <th>Писем</th>
              <th>Создан</th>
            </tr>
          </thead>
          <tbody>
            {items.map((incident) => (
              <tr
                key={incident.incident_id}
                className={selected?.incident_id === incident.incident_id ? "row--selected" : ""}
                onClick={() => setSelected(incident)}
              >
                <td>{incident.number}</td>
                <td>{incident.title}</td>
                <td>{INCIDENT_STATUS_LABELS[incident.status] ?? incident.status}</td>
                <td>
                  <span className={`tag tag--${incident.severity}`}>
                    {SEVERITY_LABELS[incident.severity] ?? incident.severity}
                  </span>
                </td>
                <td>{incident.message_count}</td>
                <td>{formatDate(incident.created_at)}</td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  Инцидентов нет
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      {selected && <IncidentDetail incident={selected} canManage={canManage} onChanged={() => void load()} />}
    </div>
  );
}
