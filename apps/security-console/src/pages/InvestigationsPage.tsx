import { type FormEvent, useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type MessageSummary, type Paginated } from "../api/client";
import { RISK_LABELS, formatDate } from "../types";

const EMPTY_FILTERS = {
  sender: "",
  recipient: "",
  subject: "",
  verdict: "",
  domain: "",
  sha256: "",
  url: "",
};

const PAGE_SIZE = 50;

export function InvestigationsPage() {
  const [filters, setFilters] = useState({ ...EMPTY_FILTERS });
  const [result, setResult] = useState<Paginated<MessageSummary> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [offset, setOffset] = useState(0);

  const search = useCallback(
    async (nextOffset: number, activeFilters: typeof EMPTY_FILTERS) => {
      setBusy(true);
      setError(null);
      try {
        const data = await api.searchMessages({
          ...activeFilters,
          limit: PAGE_SIZE,
          offset: nextOffset,
        });
        setResult(data);
        setOffset(nextOffset);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Ошибка поиска");
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  useEffect(() => {
    void search(0, EMPTY_FILTERS);
  }, [search]);

  function submit(event: FormEvent) {
    event.preventDefault();
    void search(0, filters);
  }

  return (
    <div className="page">
      <h1>Расследования</h1>
      <form className="filters card" onSubmit={submit}>
        <input
          placeholder="Отправитель"
          value={filters.sender}
          onChange={(e) => setFilters({ ...filters, sender: e.target.value })}
        />
        <input
          placeholder="Получатель"
          value={filters.recipient}
          onChange={(e) => setFilters({ ...filters, recipient: e.target.value })}
        />
        <input
          placeholder="Тема"
          value={filters.subject}
          onChange={(e) => setFilters({ ...filters, subject: e.target.value })}
        />
        <input
          placeholder="Домен"
          value={filters.domain}
          onChange={(e) => setFilters({ ...filters, domain: e.target.value })}
        />
        <input
          placeholder="SHA-256 вложения"
          value={filters.sha256}
          onChange={(e) => setFilters({ ...filters, sha256: e.target.value })}
        />
        <input
          placeholder="URL"
          value={filters.url}
          onChange={(e) => setFilters({ ...filters, url: e.target.value })}
        />
        <select
          value={filters.verdict}
          onChange={(e) => setFilters({ ...filters, verdict: e.target.value })}
        >
          <option value="">Любой вердикт</option>
          {Object.entries(RISK_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <button type="submit" className="button button--primary" disabled={busy}>
          Искать
        </button>
        <button
          type="button"
          className="button button--ghost"
          onClick={() => {
            setFilters({ ...EMPTY_FILTERS });
            void search(0, EMPTY_FILTERS);
          }}
        >
          Сбросить
        </button>
      </form>

      {error && <div className="error">{error}</div>}

      {result && (
        <section className="card">
          <p className="muted">Найдено: {result.total}</p>
          <table className="table">
            <thead>
              <tr>
                <th>Получено</th>
                <th>Отправитель</th>
                <th>Тема</th>
                <th>Вердикт</th>
                <th>Получателей</th>
                <th>Признаки</th>
              </tr>
            </thead>
            <tbody>
              {result.items.map((item) => (
                <tr key={item.message_id}>
                  <td>{formatDate(item.received_at)}</td>
                  <td>
                    <div>{item.sender_display_name}</div>
                    <code className="muted">{item.sender_address}</code>
                  </td>
                  <td>
                    <Link to={`/messages/${item.message_id}`}>{item.subject || "(без темы)"}</Link>
                  </td>
                  <td>
                    {item.classification ? (
                      <span className={`badge badge--${item.classification.toLowerCase()}`}>
                        {RISK_LABELS[item.classification]}
                      </span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>{item.recipient_count}</td>
                  <td>
                    {item.has_attachments && <span className="tag">вложения</span>}
                    {item.url_count > 0 && <span className="tag">ссылок: {item.url_count}</span>}
                    {item.reported_by && (
                      <span className="tag tag--reported">сообщение от сотрудника</span>
                    )}
                  </td>
                </tr>
              ))}
              {result.items.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    Ничего не найдено
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          <div className="pager">
            <button
              type="button"
              className="button"
              disabled={offset === 0 || busy}
              onClick={() => void search(Math.max(0, offset - PAGE_SIZE), filters)}
            >
              Назад
            </button>
            <button
              type="button"
              className="button"
              disabled={offset + PAGE_SIZE >= result.total || busy}
              onClick={() => void search(offset + PAGE_SIZE, filters)}
            >
              Вперёд
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
