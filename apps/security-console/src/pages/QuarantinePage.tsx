import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  enforcementApi,
  type CurrentUser,
  type QuarantinePreview,
  type QuarantineRow,
} from "../api/client";
import { formatDate } from "../types";

/**
 * Карантин (MSP 1.3, ТЗ 1.3 §63).
 *
 * Аналитик видит отправителя, получателей, время, причину, версию политики, срок хранения и безопасный предпросмотр.
 * Предпросмотр отдаёт сервер: заголовки, обрезанный текст без HTML и список вложений; ссылки обезврежены. Здесь
 * нет ни ссылки на скачивание письма, ни открытия вложений: исходное письмо из консоли не извлекается.
 *
 * Выпуск идёт в два шага, когда причина серьёзна (вредоносное, фишинг): запрос подаёт один человек, согласует другой.
 * Страница не скрывает отказ сервера: если второй человек не тот, кто запросил, она покажет ответ как есть.
 */

const STATE_LABEL: Record<string, string> = {
  QUARANTINED: "в карантине",
  RELEASE_PENDING: "выпуск ожидает",
  RELEASED: "выпущено",
  DELETED: "удалено",
  EXPIRED: "срок истёк",
  ERROR: "ошибка",
};

function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return error instanceof Error ? error.message : "Неизвестная ошибка";
}

export function QuarantinePage({ user }: { user: CurrentUser }) {
  const can = (permission: string) => user.permissions.includes(permission);
  const [state, setState] = useState("");
  const [query, setQuery] = useState("");
  const [rows, setRows] = useState<QuarantineRow[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ id: string; data: QuarantinePreview } | null>(null);

  const load = useCallback(() => {
    enforcementApi
      .quarantine({ state: state || undefined, q: query || undefined })
      .then((r) => {
        setRows(r.items);
        setCounts(r.counts);
        setError(null);
      })
      .catch((e) => setError(errorText(e)));
  }, [state, query]);
  useEffect(load, [load]);

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      load();
    } catch (e) {
      setError(errorText(e));
    }
  };

  const show = async (id: string) => {
    try {
      setPreview({ id, data: await enforcementApi.preview(id) });
    } catch (e) {
      setError(errorText(e));
    }
  };

  return (
    <div className="page">
      <h1>Карантин</h1>
      <div className="notice notice--warning" role="alert">
        Письма хранятся зашифрованными и недоступны вне этой страницы. MSP 1.3 IS NOT APPROVED FOR GLOBAL PRODUCTION
        MX CUTOVER; пользовательского портала карантина в этом этапе нет.
      </div>
      {error && (
        <div className="notice notice--warning" role="alert">
          {error}
        </div>
      )}
      <div className="tiles">
        {Object.entries(counts).map(([k, v]) => (
          <div className="tile" key={k}>
            <div className="tile__label">{STATE_LABEL[k] ?? k}</div>
            <div className="tile__value">{v}</div>
          </div>
        ))}
      </div>
      <div className="filters">
        <select aria-label="Состояние" value={state} onChange={(e) => setState(e.target.value)}>
          <option value="">все</option>
          {Object.keys(STATE_LABEL).map((s) => (
            <option key={s} value={s}>{STATE_LABEL[s]}</option>
          ))}
        </select>
        <input aria-label="Поиск" placeholder="отправитель или тема" value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>Время</th>
            <th>Отправитель</th>
            <th>Получатели</th>
            <th>Тема</th>
            <th>Причина</th>
            <th>Хранится до</th>
            <th>Состояние</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>{formatDate(r.quarantined_at)}</td>
              <td>{r.sender}</td>
              <td>{r.recipients.join(", ")}</td>
              <td>{r.subject}</td>
              <td className="small">{r.reason_codes.join(", ")}<div className="muted">политика {r.policy_version}</div></td>
              <td>{formatDate(r.expires_at)}</td>
              <td>
                {STATE_LABEL[r.state] ?? r.state}
                {r.release_requested_by && <div className="muted small">запросил {r.release_requested_by}{r.release_approved_by ? `, согласовал ${r.release_approved_by}` : ""}</div>}
              </td>
              <td>
                <button className="button button--tiny" onClick={() => show(r.id)}>Предпросмотр</button>
                {can("quarantine:release") && r.state === "QUARANTINED" && (
                  <button className="button button--tiny" onClick={() => act(() => enforcementApi.release(r.id, "request"))}>
                    Запросить выпуск
                  </button>
                )}
                {can("quarantine:release") && r.state === "RELEASE_PENDING" && !r.release_approved_by && (
                  <>
                    <button className="button button--tiny button--primary" onClick={() => act(() => enforcementApi.release(r.id, "approve"))}>Согласовать</button>
                    <button className="button button--tiny" onClick={() => act(() => enforcementApi.release(r.id, "cancel"))}>Отменить</button>
                  </>
                )}
                {can("quarantine:delete") && ["QUARANTINED", "RELEASE_PENDING"].includes(r.state) && (
                  <button className="button button--tiny button--danger" onClick={() => act(() => enforcementApi.deleteItem(r.id, "удалено из консоли"))}>
                    Удалить
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && <p className="muted">В карантине ничего нет.</p>}
      {preview && (
        <section className="card" aria-label="Предпросмотр">
          <div className="card__header">
            <h2>Безопасный предпросмотр</h2>
            <button className="button button--tiny" onClick={() => setPreview(null)}>Закрыть</button>
          </div>
          <table className="table table--compact">
            <tbody>
              {Object.entries(preview.data.headers).map(([k, v]) => (
                <tr key={k}><th>{k}</th><td>{v}</td></tr>
              ))}
            </tbody>
          </table>
          <pre className="preview-text">{preview.data.text}</pre>
          {preview.data.attachments.length > 0 && (
            <p>Вложения (не открываются): {preview.data.attachments.map((a) => a.name).join(", ")}</p>
          )}
          <p className="muted">Активное содержимое удалено, ссылки обезврежены.</p>
        </section>
      )}
    </div>
  );
}
