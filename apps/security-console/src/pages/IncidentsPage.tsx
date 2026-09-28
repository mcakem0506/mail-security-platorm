import { useCallback, useEffect, useState } from "react";
import { api, type CurrentUser } from "../api/client";
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
