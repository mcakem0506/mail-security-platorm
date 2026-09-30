import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  api,
  type AnalysisDetail,
  type Signal,
  type UpstreamProtection,
} from "../api/client";
import { RISK_LABELS, SEVERITY_LABELS, formatDate } from "../types";

interface AttachmentRow {
  attachment_id: string;
  filename: string;
  detected_type: string;
  size_bytes: number;
  sha256: string;
  depth: number;
  is_archive: boolean;
  encrypted: boolean;
  flags: string[];
  downloadable: boolean;
  scan_result: Record<string, unknown>;
}

interface MessageDetail {
  message: Record<string, unknown>;
  headers: { name: string; value: string }[];
  recipients: { address: string; kind: string; display_name: string }[];
  attachments: AttachmentRow[];
  urls: { url: string; context: string }[];
  auth_summary: Record<string, unknown>;
  /** Set when Authentication-Results were present but not believed (ТЗ 1.0.1 §4.4). */
  auth_note: string | null;
  preview_available: boolean;
}

const GATEWAY_VERDICT_LABELS: Record<string, string> = {
  MALICIOUS: "Обнаружено вредоносное содержимое",
  PHISHING: "Обнаружен фишинг",
  SPAM: "Отнесено к спаму",
  SUSPICIOUS: "Подозрительно",
  CLEAN_OBSERVED: "Обнаружений нет",
  UNKNOWN: "Вердикт не прочитан",
  ERROR: "Ошибка проверки",
};

const TRUST_STATE_LABELS: Record<string, string> = {
  trusted: "подтверждено цепочкой доставки",
  unverified_chain: "не подтверждено цепочкой доставки",
  unknown_gateway: "шлюз не используется организацией",
  topology_mismatch: "узел найден не на своём месте в цепочке",
  untrusted_source: "источник события не разрешён",
};

const CONFLICT_LABELS: Record<string, string> = {
  GATEWAY_MALICIOUS_PLATFORM_LOW: "Шлюз обнаружил угрозу, платформа — нет",
  GATEWAY_CLEAN_PLATFORM_HIGH: "Шлюз ничего не нашёл, платформа считает письмо опасным",
  GATEWAY_DISAGREEMENT: "Шлюзы дали разные вердикты",
  HEADER_API_MISMATCH: "Заголовки и API шлюза расходятся",
};

/**
 * Upstream Protection (ТЗ 1.0.2 §24).
 *
 * Shows what the gateway said *and* whether that can be believed. An untrusted verdict is
 * rendered struck through with the reason attached, because the important fact about a copied
 * gateway header is not what it claims but that it could not be verified.
 */
function UpstreamProtectionCard({ messageId }: { messageId: string }) {
  const [data, setData] = useState<UpstreamProtection | null>(null);

  useEffect(() => {
    let active = true;
    api
      .upstreamProtection(messageId)
      .then((result) => {
        if (active) setData(result);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [messageId]);

  if (!data || (!data.present && data.conflicts.length === 0)) {
    return null;
  }

  return (
    <section className="card">
      <h2>Upstream Protection</h2>
      <table className="table table--compact">
        <thead>
          <tr>
            <th>Шлюз</th>
            <th>Движок</th>
            <th>Вердикт</th>
            <th>Угроза</th>
            <th>Оценка</th>
            <th>Доверие</th>
            <th>Время</th>
          </tr>
        </thead>
        <tbody>
          {data.evidence.map((item, index) => (
            <tr key={`${item.provider_id}-${item.category}-${index}`}>
              <td>{item.provider_id}</td>
              <td>{item.category || item.engine || "—"}</td>
              <td className={item.trusted ? undefined : "muted struck"}>
                {GATEWAY_VERDICT_LABELS[item.verdict] ?? item.verdict}
              </td>
              <td>{item.threat_name || "—"}</td>
              <td>{item.score === null ? "—" : item.score}</td>
              <td>
                <span className={item.trusted ? "tag tag--ok" : "tag tag--flag"}>
                  {TRUST_STATE_LABELS[item.trust_state] ?? item.trust_state}
                </span>
                {!item.trusted && item.trust_reason && (
                  <div className="muted small">{item.trust_reason}</div>
                )}
              </td>
              <td>{formatDate(item.observed_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {data.conflicts.length > 0 && (
        <div className="conflicts">
          <h3>Расхождения источников</h3>
          <ul>
            {data.conflicts.map((conflict) => (
              <li key={conflict.conflict_id}>
                <strong>{CONFLICT_LABELS[conflict.kind] ?? conflict.kind}</strong>
                <div className="muted">{conflict.summary}</div>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="muted">{data.note}</p>
    </section>
  );
}

/**
 * Safe mail preview (ТЗ 22.3).
 *
 * Two independent layers: the server sanitises the HTML, and it is rendered inside a sandboxed
 * iframe with a restrictive CSP and no allow-scripts / allow-same-origin. Links are not
 * clickable — URLs are listed separately as copyable text.
 */
function SafePreview({ messageId }: { messageId: string }) {
  const [html, setHtml] = useState<string | null>(null);
  const [text, setText] = useState<string | null>(null);
  const [warning, setWarning] = useState("");
  const [urls, setUrls] = useState<{ url: string; context: string }[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [shown, setShown] = useState(false);

  const load = useCallback(async () => {
    try {
      const preview = await api.preview(messageId);
      setHtml(preview.sanitized_html);
      setText(preview.plain_text);
      setUrls(preview.urls);
      setWarning(preview.warning);
      setShown(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось загрузить содержимое");
    }
  }, [messageId]);

  if (!shown) {
    return (
      <section className="card">
        <h2>Содержимое письма</h2>
        <p className="muted">
          Содержимое открывается по явному действию аналитика. Просмотр фиксируется в журнале аудита.
        </p>
        <button type="button" className="button" onClick={() => void load()}>
          Показать безопасный просмотр
        </button>
        {error && <p className="error">{error}</p>}
      </section>
    );
  }

  const document = `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<style>body{font:13px/1.5 "Segoe UI",sans-serif;color:#201f1e;margin:8px}a{color:inherit;text-decoration:underline dotted;pointer-events:none}</style>
</head><body>${html ?? ""}</body></html>`;

  return (
    <section className="card">
      <h2>Содержимое письма</h2>
      <p className="notice notice--info">{warning}</p>
      {html ? (
        <iframe
          title="Безопасный просмотр письма"
          className="preview-frame"
          sandbox=""
          srcDoc={document}
          referrerPolicy="no-referrer"
        />
      ) : (
        <pre className="preview-text">{text || "(пусто)"}</pre>
      )}
      {urls.length > 0 && (
        <>
          <h3>Ссылки в письме</h3>
          <ul className="url-list">
            {urls.map((item) => (
              <li key={`${item.context}:${item.url}`}>
                <code>{item.url}</code>
                <span className="muted"> — {item.context}</span>
                <button
                  type="button"
                  className="button button--tiny"
                  onClick={() => void navigator.clipboard.writeText(item.url)}
                >
                  Копировать
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function SignalTable({ signals }: { signals: Signal[] }) {
  const active = signals.filter((s) => !s.suppressed);
  const suppressed = signals.filter((s) => s.suppressed);
  return (
    <section className="card">
      <h2>Сигналы детектирования</h2>
      <table className="table">
        <thead>
          <tr>
            <th>Правило</th>
            <th>Категория</th>
            <th>Важность</th>
            <th>Обоснование</th>
            <th>Доказательства</th>
          </tr>
        </thead>
        <tbody>
          {active.map((signal) => (
            <tr key={signal.signal_id}>
              <td>
                <code>{signal.rule_id}</code>
                <span className="muted"> v{signal.rule_version}</span>
                {signal.hard && <span className="tag tag--hard">hard</span>}
              </td>
              <td>{signal.category}</td>
              <td>
                <span className={`tag tag--${signal.severity}`}>
                  {SEVERITY_LABELS[signal.severity] ?? signal.severity}
                </span>
              </td>
              <td>
                <strong>{signal.title}</strong>
                <div className="muted">{signal.explanation}</div>
              </td>
              <td>
                <pre className="evidence">{JSON.stringify(signal.evidence, null, 1)}</pre>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {suppressed.length > 0 && (
        <>
          <h3>Подавлено исключениями</h3>
          <ul>
            {suppressed.map((signal) => (
              <li key={signal.signal_id}>
                <code>{signal.rule_id}</code> {signal.title} —{" "}
                <span className="muted">{signal.suppressed_by}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

export function MessagePage() {
  const { messageId = "" } = useParams();
  const [detail, setDetail] = useState<MessageDetail | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showHeaders, setShowHeaders] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const data = (await api.message(messageId)) as unknown as MessageDetail;
        if (!cancelled) setDetail(data);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Ошибка загрузки");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [messageId]);

  if (error) return <div className="error">{error}</div>;
  if (!detail) return <div className="muted">Загрузка…</div>;

  const message = detail.message as Record<string, string | number | null>;

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>{String(message.subject || "(без темы)")}</h1>
          <p className="muted">
            {String(message.sender_display_name || "")} &lt;{String(message.sender_address || "")}&gt; ·{" "}
            {formatDate(String(message.received_at || ""))}
          </p>
        </div>
        {message.classification && (
          <span className={`badge badge--${String(message.classification).toLowerCase()}`}>
            {RISK_LABELS[String(message.classification)] ?? String(message.classification)}
            {message.score !== null && ` · ${message.score}`}
          </span>
        )}
      </div>

      <UpstreamProtectionCard messageId={messageId} />

      <section className="card">
        <h2>Аутентификация отправителя</h2>
        {Object.keys(detail.auth_summary).length === 0 ? (
          <p className="muted">
            Заголовки Authentication-Results отсутствуют — результаты проверок недоступны.
            Отсутствие данных не означает, что письмо безопасно.
          </p>
        ) : (
          <ul className="inline-list">
            {Object.entries(detail.auth_summary).map(([method, result]) => (
              <li key={method}>
                <span className="muted">{method.toUpperCase()}: </span>
                <strong>{String(result)}</strong>
              </li>
            ))}
          </ul>
        )}
        {detail.auth_note && <p className="warning">{detail.auth_note}</p>}
      </section>

      {detail.preview_available && <SafePreview messageId={messageId} />}

      {detail.attachments.length > 0 && (
        <section className="card">
          <h2>Вложения</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Файл</th>
                <th>Тип</th>
                <th>Размер</th>
                <th>SHA-256</th>
                <th>Признаки</th>
                <th>Проверка</th>
              </tr>
            </thead>
            <tbody>
              {detail.attachments.map((attachment) => (
                <tr key={attachment.attachment_id}>
                  <td>
                    {attachment.depth > 0 && <span className="muted">↳ </span>}
                    {attachment.filename}
                  </td>
                  <td>{attachment.detected_type}</td>
                  <td>{(attachment.size_bytes / 1024).toFixed(1)} КБ</td>
                  <td>
                    <code className="hash">{attachment.sha256.slice(0, 16)}…</code>
                  </td>
                  <td>
                    {attachment.flags.map((flag) => (
                      <span key={flag} className="tag tag--flag">
                        {flag}
                      </span>
                    ))}
                  </td>
                  <td>
                    {attachment.scan_result && "malicious" in attachment.scan_result
                      ? attachment.scan_result.malicious
                        ? "Обнаружено"
                        : "Не обнаружено"
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted">
            Скачивание опасных типов файлов требует отдельного подтверждения и фиксируется в аудите.
          </p>
        </section>
      )}

      {analysis && <SignalTable signals={analysis.signals} />}
      {!analysis && (
        <section className="card">
          <button
            type="button"
            className="button"
            onClick={() => {
              const jobId = String(message.job_id || "");
              if (jobId) void api.analysisDetail(jobId).then(setAnalysis).catch(() => undefined);
            }}
          >
            Показать сигналы детектирования
          </button>
        </section>
      )}

      <section className="card">
        <h2>
          Заголовки{" "}
          <button type="button" className="button button--tiny" onClick={() => setShowHeaders(!showHeaders)}>
            {showHeaders ? "Скрыть" : "Показать"}
          </button>
        </h2>
        {showHeaders && (
          <table className="table table--compact">
            <tbody>
              {detail.headers.map((header, index) => (
                <tr key={`${header.name}-${index}`}>
                  <td className="header-name">{header.name}</td>
                  <td className="header-value">{header.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <Link to="/investigations" className="button button--ghost">
        ← К расследованиям
      </Link>
    </div>
  );
}
