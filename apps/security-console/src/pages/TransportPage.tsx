import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  transportApi,
  type CurrentUser,
  type TransportCertificate,
  type TransportAlert,
  type TransportConfigVersion,
  type TransportMessage,
  type TransportNode,
  type TransportQueueSummary,
  type TransportRecipientsStatus,
  type TransportRoutes,
} from "../api/client";
import { formatDate } from "../types";

/**
 * Транспорт почты (ТЗ 1.1 §43).
 *
 * Страница показывает, что происходит с почтой на границе организации, и позволяет менять то, что
 * на неё влияет. Три решения в устройстве:
 *
 * Первое: предупреждение о том, что этап не одобрен для переключения MX, висит на каждой вкладке,
 * а не только на обзоре. Оператор открывает «Конфигурацию» по прямой ссылке, и именно там он
 * способен совершить то, о чём предупреждение.
 *
 * Второе: письма показаны без содержимого. Очередь и список копий нужны, чтобы найти письмо, а не
 * чтобы читать чужую почту; открытие письма для разбора идёт через расследования и пишется в аудит.
 *
 * Третье: «нет данных» не рисуется как «хорошо». Узел без сигнала — «не отвечает», справочник без
 * загрузки — «закрыт», возраст, которого нет, — «—». Нулевая очередь на молчащем узле выглядела бы
 * как здоровая система, и ровно тогда, когда она неисправна.
 */

type Tab = "overview" | "queue" | "nodes" | "routes" | "recipients" | "tls" | "config";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Обзор" },
  { id: "queue", label: "Очередь и письма" },
  { id: "nodes", label: "Узлы" },
  { id: "routes", label: "Маршруты" },
  { id: "recipients", label: "Получатели" },
  { id: "tls", label: "TLS" },
  { id: "config", label: "Конфигурация" },
];

const NODE_STATE: Record<string, { label: string; cls: string }> = {
  UP: { label: "работает", cls: "badge badge--low_risk" },
  DRAINING: { label: "слив", cls: "badge badge--suspicious" },
  DOWN: { label: "не отвечает", cls: "badge badge--malicious" },
  UNKNOWN: { label: "нет сигнала", cls: "badge badge--unknown" },
};

const PRESSURE_LABEL: Record<string, string> = {
  NORMAL: "норма",
  PRESSURE: "давление",
  CRITICAL: "критично",
  DRAINING: "слив",
  UNKNOWN: "нет данных",
};

const FRESHNESS_LABEL: Record<string, { label: string; cls: string }> = {
  FRESH: { label: "свежий", cls: "badge badge--low_risk" },
  STALE_GRACE: { label: "устарел, в пределах допуска", cls: "badge badge--suspicious" },
  STALE_HARD: { label: "устарел: приём закрыт", cls: "badge badge--malicious" },
};

const CERT_STATE: Record<string, { label: string; cls: string }> = {
  OK: { label: "действителен", cls: "badge badge--low_risk" },
  EXPIRING: { label: "скоро истекает", cls: "badge badge--suspicious" },
  EXPIRED: { label: "истёк", cls: "badge badge--malicious" },
  UNKNOWN: { label: "неизвестно", cls: "badge badge--unknown" },
};

const CONFIG_STATUS: Record<string, string> = {
  DRAFT: "черновик (не прошёл проверку)",
  VALIDATED: "проверена",
  ACTIVE: "действует",
  SUPERSEDED: "заменена",
  ROLLED_BACK: "откатана",
  FAILED: "ошибка",
};

const NOT_FOR_PRODUCTION = "MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER";

function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return error instanceof Error ? error.message : "Неизвестная ошибка";
}

function age(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds < 120) return `${Math.round(seconds)} с`;
  if (seconds < 7200) return `${Math.round(seconds / 60)} мин`;
  return `${(seconds / 3600).toFixed(1)} ч`;
}

export function TransportPage({ user }: { user: CurrentUser }) {
  const [tab, setTab] = useState<Tab>("overview");
  const can = (permission: string) => user.permissions.includes(permission);

  return (
    <div className="page">
      <h1>Транспорт почты</h1>
      <div className="notice notice--warning" role="alert">
        <strong>{NOT_FOR_PRODUCTION}.</strong> Шлюз пока не принимает боевую почту организации.
        Переключение MX-записей этим этапом не предусмотрено и автоматически не выполняется.
      </div>
      <div className="tabs" role="tablist">
        {TABS.map((item) => (
          <button
            key={item.id}
            role="tab"
            aria-selected={tab === item.id}
            className={tab === item.id ? "tab tab--active" : "tab"}
            onClick={() => setTab(item.id)}
          >
            {item.label}
          </button>
        ))}
      </div>
      {tab === "overview" && <Overview />}
      {tab === "queue" && <QueueTab />}
      {tab === "nodes" && <NodesTab canDrain={can("gateway:node:drain")} canFlush={can("gateway:queue:admin")} />}
      {tab === "routes" && <RoutesTab canRead={can("gateway:config:read")} />}
      {tab === "recipients" && <RecipientsTab canSync={can("gateway:recipient:sync")} />}
      {tab === "tls" && <TlsTab />}
      {tab === "config" && (
        <ConfigTab
          canRead={can("gateway:config:read")}
          canValidate={can("gateway:config:validate")}
          canActivate={can("gateway:config:activate")}
          canRollback={can("gateway:config:rollback")}
        />
      )}
    </div>
  );
}

function useLoad<T>(load: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const reload = useCallback(() => {
    setLoading(true);
    load()
      .then((result) => {
        setData(result);
        setError(null);
      })
      .catch((e) => setError(errorText(e)))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(reload, [reload]);
  return { data, error, loading, reload };
}

function Problem({ error }: { error: string | null }) {
  return error ? (
    <div className="notice notice--warning" role="alert">
      {error}
    </div>
  ) : null;
}

const ALERT_CLASS: Record<string, string> = {
  CRITICAL: "badge badge--malicious",
  WARNING: "badge badge--suspicious",
  INFO: "badge badge--unknown",
};

const ALERT_LABEL: Record<string, string> = {
  CRITICAL: "критично",
  WARNING: "внимание",
  INFO: "к сведению",
};

/**
 * Тревоги вычисляются из состояния узлов, а не хранятся: узел вернулся в норму — тревога исчезла
 * сама. «К сведению» отделено от остальных намеренно: это не сбой, а непроверенное место
 * (проба не настроена), и показывать его зелёным значило бы выдавать неизвестное за хорошее.
 */
function Alerts({ items }: { items: TransportAlert[] }) {
  const loud = items.filter((a) => a.severity !== "INFO");
  const info = items.filter((a) => a.severity === "INFO");
  return (
    <section className="card">
      <h2>Тревоги</h2>
      {loud.length === 0 && <p className="muted">Тревог нет.</p>}
      {loud.length > 0 && (
        <table className="table">
          <tbody>
            {loud.map((a, index) => (
              <tr key={`${a.code}-${a.node_id}-${index}`}>
                <td>
                  <span className={ALERT_CLASS[a.severity] ?? "badge"}>{ALERT_LABEL[a.severity] ?? a.severity}</span>
                </td>
                <td>
                  {a.title}
                  {a.detail && <div className="muted small">{a.detail}</div>}
                </td>
                <td className="muted small">{a.node_name || a.node_id.slice(0, 8)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {info.length > 0 && (
        <details>
          <summary className="muted small">Не проверяется ({info.length})</summary>
          <ul>
            {info.map((a, index) => (
              <li key={`${a.code}-${a.node_id}-${index}`} className="muted small">
                {a.title} {a.node_name && `— ${a.node_name}`}
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}

function Overview() {
  const summary = useLoad<TransportQueueSummary>(() => transportApi.queueSummary());
  const alerts = useLoad<{ items: TransportAlert[] }>(() => transportApi.alerts());
  const recipients = useLoad<TransportRecipientsStatus>(() => transportApi.recipientsStatus());
  const tls = useLoad<{ items: TransportCertificate[] }>(() => transportApi.tls());
  const s = summary.data;
  const problemCerts = (tls.data?.items ?? []).filter((c) => c.state === "EXPIRED" || c.state === "EXPIRING");
  return (
    <>
      <Problem error={summary.error || recipients.error || tls.error || alerts.error} />
      {alerts.data && <Alerts items={alerts.data.items} />}
      {s && (
        <section className="card">
          <h2>Состояние</h2>
          <table className="table table--compact">
            <tbody>
              <tr>
                <th>Узлы</th>
                <td>
                  работает {s.nodes_up} из {s.nodes_total}
                  {s.nodes_down > 0 && (
                    <span className="badge badge--malicious" style={{ marginLeft: 8 }}>
                      не отвечают: {s.nodes_down}
                    </span>
                  )}
                  {s.nodes_total === 0 && <span className="muted"> — ни один узел не присылал сигнал</span>}
                </td>
              </tr>
              <tr>
                <th>Писем в очереди</th>
                <td>{s.queue_messages}</td>
              </tr>
              <tr>
                <th>Давление</th>
                <td>{PRESSURE_LABEL[s.pressure] || s.pressure}</td>
              </tr>
              <tr>
                <th>Копий, ожидающих анализа</th>
                <td>{s.unanalysed_copies}</td>
              </tr>
            </tbody>
          </table>
        </section>
      )}
      {recipients.data && (
        <section className="card">
          <h2>Справочник получателей</h2>
          <p>
            <span className={look(FRESHNESS_LABEL, recipients.data.freshness).cls}>
              {look(FRESHNESS_LABEL, recipients.data.freshness).label}
            </span>{" "}
            · адресов: {recipients.data.recipient_count} · возраст: {age(recipients.data.age_seconds)}
          </p>
          {recipients.data.closed && (
            <p className="notice notice--warning">
              Справочник безнадёжно устарел: узлы отвечают отправителям временным отказом. Почта не
              теряется, но и не принимается, пока справочник не обновят.
            </p>
          )}
        </section>
      )}
      {problemCerts.length > 0 && (
        <section className="card">
          <h2>Сертификаты требуют внимания</h2>
          <ul>
            {problemCerts.map((c) => (
              <li key={c.fingerprint}>
                {c.usage}: <span className={look(CERT_STATE, c.state).cls}>{look(CERT_STATE, c.state).label}</span>
                {c.not_after && <> · до {formatDate(c.not_after)}</>}
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}

function QueueTab() {
  const [direction, setDirection] = useState("");
  const messages = useLoad(() => transportApi.messages({ direction: direction || undefined, limit: 50 }), [direction]);
  return (
    <section className="card">
      <h2>Копии писем, снятые шлюзом</h2>
      <p className="muted small">
        Содержимого здесь нет намеренно: список нужен, чтобы найти письмо. Разбор самого письма
        выполняется в разделе «Письма» и записывается в журнал аудита.
      </p>
      <div className="form-row">
        <label>
          Направление{" "}
          <select value={direction} onChange={(e) => setDirection(e.target.value)}>
            <option value="">все</option>
            <option value="INBOUND">входящие</option>
            <option value="OUTBOUND">исходящие</option>
          </select>
        </label>
      </div>
      <Problem error={messages.error} />
      {messages.data && messages.data.items.length === 0 && <p className="muted">Копий пока нет.</p>}
      {messages.data && messages.data.items.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Получено</th>
              <th>Направление</th>
              <th>Message-ID</th>
              <th>Размер</th>
              <th>Состояние</th>
              <th>Повторов</th>
            </tr>
          </thead>
          <tbody>
            {messages.data.items.map((m: TransportMessage) => (
              <tr key={m.id}>
                <td>{formatDate(m.collected_at)}</td>
                <td>{m.direction}</td>
                <td>
                  <code>{m.internet_message_id || "—"}</code>
                </td>
                <td>{m.size_bytes}</td>
                <td>{m.state}</td>
                <td>{m.duplicate_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function NodesTab({ canDrain, canFlush }: { canDrain: boolean; canFlush: boolean }) {
  const nodes = useLoad(() => transportApi.nodes());
  const [message, setMessage] = useState<string | null>(null);

  const act = async (node: TransportNode, drain: boolean) => {
    const question = drain
      ? `Слить узел «${node.name}»? Он перестанет принимать новую почту (отправители получат временный отказ и повторят позже). Уже принятые письма будут доставлены.`
      : `Вернуть узел «${node.name}» в работу?`;
    if (!window.confirm(question)) return;
    try {
      await (drain ? transportApi.drain(node.id) : transportApi.resume(node.id));
      setMessage(
        drain
          ? "Команда слива отправлена. Узел исполнит её при ближайшем опросе панели."
          : "Команда возврата в работу отправлена.",
      );
      nodes.reload();
    } catch (e) {
      setMessage(errorText(e));
    }
  };

  const flush = async (node: TransportNode) => {
    if (!window.confirm(`Повторить доставку отложенной почты на узле «${node.name}»? Письма не удаляются и не меняются.`)) return;
    try {
      await transportApi.flush(node.id);
      setMessage("Команда отправлена. Узел исполнит её при ближайшем опросе панели.");
      nodes.reload();
    } catch (e) {
      setMessage(errorText(e));
    }
  };

  return (
    <section className="card">
      <h2>Узлы</h2>
      <Problem error={nodes.error} />
      {message && <p className="notice notice--info">{message}</p>}
      {nodes.data && nodes.data.items.length === 0 && <p className="muted">Ни один узел не регистрировался.</p>}
      {nodes.data && nodes.data.items.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Узел</th>
              <th>Роль</th>
              <th>Состояние</th>
              <th>Последний сигнал</th>
              <th>Конфигурация</th>
              <th>Очередь</th>
              <th>Давление</th>
              <th>Проверки</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {nodes.data.items.map((n) => (
              <tr key={n.id}>
                <td>
                  {n.name}
                  <div className="muted small">
                    <code>{n.node_id}</code>
                  </div>
                </td>
                <td>{n.role}</td>
                <td>
                  <span className={look(NODE_STATE, n.state).cls}>{look(NODE_STATE, n.state).label}</span>
                  {n.drain_requested && <div className="muted small">запрошен слив: {n.drain_requested_by}</div>}
                </td>
                <td>{n.last_heartbeat_at ? formatDate(n.last_heartbeat_at) : "—"}</td>
                <td>
                  <code>{n.config_version || "—"}</code>
                </td>
                <td>{n.state === "UP" || n.state === "DRAINING" ? n.queue_messages : "—"}</td>
                <td>{PRESSURE_LABEL[n.pressure] || n.pressure}</td>
                <td className="small">
                  <div>Exchange: {tri(n.exchange_ok)}</div>
                  <div>Открытый релей: {n.open_relay_safe === null ? "не проверялось" : n.open_relay_safe ? "закрыт" : "ОТКРЫТ"}</div>
                  <div>Конфигурация: {n.config_drift === null ? "не проверялось" : n.config_drift ? "ИЗМЕНЕНА вручную" : "как назначено"}</div>
                  <div>
                    Сборщик копий:{" "}
                    {n.collector_report_age === null
                      ? "не отчитывается"
                      : `отчёт ${Math.round(n.collector_report_age)} с назад`}
                  </div>
                  {Object.entries(n.probes).map(([key, probe]) =>
                    probe.ok === false ? (
                      <div key={key} className="muted">
                        {key.replace("exchange:", "")}: сбой на уровне {probe.failed_layer || "?"}
                      </div>
                    ) : null,
                  )}
                </td>
                <td>
                  {canFlush && (
                    <button className="button button--tiny" onClick={() => void flush(n)} disabled={n.flush_requested}>
                      {n.flush_requested ? "Повтор запрошен" : "Повторить доставку"}
                    </button>
                  )}
                  {canDrain &&
                    (n.drain_requested ? (
                      <button className="button button--tiny" onClick={() => void act(n, false)}>
                        Вернуть в работу
                      </button>
                    ) : (
                      <button className="button button--tiny button--danger" onClick={() => void act(n, true)}>
                        Слить
                      </button>
                    ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function RoutesTab({ canRead }: { canRead: boolean }) {
  const routes = useLoad<TransportRoutes>(() => (canRead ? transportApi.routes() : Promise.reject(new Error("Нет права на просмотр конфигурации"))));
  const r = routes.data;
  return (
    <section className="card">
      <h2>Маршруты доставки</h2>
      <Problem error={routes.error} />
      {r && r.version === null && <p className="muted">Действующей конфигурации нет.</p>}
      {r && r.version !== null && (
        <>
          <p className="muted small">Версия конфигурации: {r.version}</p>
          <table className="table">
            <thead>
              <tr>
                <th>Маршрут</th>
                <th>TLS</th>
                <th>Цели (по приоритету)</th>
              </tr>
            </thead>
            <tbody>
              {r.routes.map((route) => (
                <tr key={route.name}>
                  <td>{route.name}</td>
                  <td>{route.tls}</td>
                  <td>
                    {route.targets.map((t) => (
                      <div key={`${t.host}:${t.port}`}>
                        <code>
                          {t.host}:{t.port}
                        </code>{" "}
                        <span className="muted small">приоритет {t.priority}</span>
                      </div>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>Домены приёма</h3>
          <ul>
            {r.relay_domains.map((d) => (
              <li key={d.domain}>
                {d.domain} → {d.route}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function RecipientsTab({ canSync }: { canSync: boolean }) {
  const status = useLoad<TransportRecipientsStatus>(() => transportApi.recipientsStatus());
  const [format, setFormat] = useState<"csv" | "json">("csv");
  const [content, setContent] = useState("");
  const [confirmShrink, setConfirmShrink] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    try {
      const out = await transportApi.syncRecipients({ format, content, source: "console", confirm_shrink: confirmShrink });
      setResult({
        ok: true,
        text: `Принято адресов: ${out.recipient_count}; отброшено строк: ${out.rejected_count}; конфликтов псевдонимов: ${out.conflict_count}.${
          out.activated_version ? ` Применена версия конфигурации ${out.activated_version}.` : ""
        }`,
      });
      setContent("");
      setConfirmShrink(false);
      status.reload();
    } catch (e) {
      setResult({ ok: false, text: `Справочник не принят: ${errorText(e)}` });
      status.reload();
    } finally {
      setBusy(false);
    }
  };

  const s = status.data;
  return (
    <>
      <section className="card">
        <h2>Справочник получателей</h2>
        <Problem error={status.error} />
        {s && (
          <>
            <p>
              <span className={look(FRESHNESS_LABEL, s.freshness).cls}>{look(FRESHNESS_LABEL, s.freshness).label}</span> · адресов:{" "}
              {s.recipient_count} · возраст: {age(s.age_seconds)}
            </p>
            {s.last_sync ? (
              <p className="muted small">
                Последняя попытка: {formatDate(s.last_sync.started_at)} — {s.last_sync.status}
                {s.last_sync.reason && ` (${s.last_sync.reason})`}; было {s.last_sync.previous_count}, в выгрузке{" "}
                {s.last_sync.recipient_count}.
              </p>
            ) : (
              <p className="muted small">Справочник ни разу не загружался.</p>
            )}
          </>
        )}
      </section>
      {canSync && (
        <section className="card">
          <h2>Обновить справочник</h2>
          <p className="muted small">
            Пустую выгрузку и выгрузку, в которой адресов стало вдвое меньше, система не примет:
            скорее сломалась выгрузка, чем уволилась половина организации. Действующий справочник
            при отказе остаётся как был.
          </p>
          <div className="form-row">
            <label>
              Формат{" "}
              <select value={format} onChange={(e) => setFormat(e.target.value as "csv" | "json")}>
                <option value="csv">CSV: address,kind,aliases</option>
                <option value="json">JSON</option>
              </select>
            </label>
          </div>
          <textarea
            rows={8}
            style={{ width: "100%" }}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder={"address,kind,aliases\nivan@corp.example,USER,i.petrov@corp.example"}
          />
          <div className="form-row">
            <label>
              <input type="checkbox" checked={confirmShrink} onChange={(e) => setConfirmShrink(e.target.checked)} /> Я
              проверил(а): сокращение справочника настоящее
            </label>
          </div>
          <button className="button button--primary" disabled={busy || !content.trim()} onClick={() => void submit()}>
            Загрузить
          </button>
          {result && (
            <p className={result.ok ? "notice notice--info" : "notice notice--warning"} role="status">
              {result.text}
            </p>
          )}
        </section>
      )}
    </>
  );
}

function TlsTab() {
  const tls = useLoad(() => transportApi.tls());
  return (
    <section className="card">
      <h2>Сертификаты</h2>
      <p className="muted small">Хранятся только сведения о сертификате; закрытые ключи панели недоступны.</p>
      <Problem error={tls.error} />
      {tls.data && tls.data.items.length === 0 && <p className="muted">Сведений о сертификатах узлы пока не присылали.</p>}
      {tls.data && tls.data.items.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Назначение</th>
              <th>Субъект</th>
              <th>Издатель</th>
              <th>Действителен до</th>
              <th>Состояние</th>
            </tr>
          </thead>
          <tbody>
            {tls.data.items.map((c) => (
              <tr key={c.fingerprint}>
                <td>{c.usage}</td>
                <td>{c.subject}</td>
                <td>{c.issuer}</td>
                <td>
                  {c.not_after ? formatDate(c.not_after) : "—"}
                  {c.days_left !== null && <div className="muted small">осталось дней: {Math.floor(c.days_left)}</div>}
                </td>
                <td>
                  <span className={look(CERT_STATE, c.state).cls}>{look(CERT_STATE, c.state).label}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function ConfigTab(props: { canRead: boolean; canValidate: boolean; canActivate: boolean; canRollback: boolean }) {
  const versions = useLoad<{ items: TransportConfigVersion[] }>(() =>
    props.canRead ? transportApi.versions() : Promise.reject(new Error("Нет права на просмотр конфигурации")),
  );
  const [spec, setSpec] = useState("");
  const [note, setNote] = useState("");
  const [outcome, setOutcome] = useState<{ ok: boolean; text: string; errors: string[] } | null>(null);

  const validate = async () => {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(spec) as Record<string, unknown>;
    } catch {
      setOutcome({ ok: false, text: "Описание не является корректным JSON", errors: [] });
      return;
    }
    try {
      const result = await transportApi.validateConfig(parsed, note);
      setOutcome({
        ok: Boolean(result.ok),
        text: result.ok ? `Версия ${result.version} проверена. Она ещё не применена.` : `Версия ${result.version} не прошла проверку.`,
        errors: result.errors,
      });
      versions.reload();
    } catch (e) {
      setOutcome({ ok: false, text: errorText(e), errors: [] });
    }
  };

  const activate = async (v: TransportConfigVersion) => {
    if (!window.confirm(`Применить версию ${v.version}? Узлы начнут работать по ней при ближайшем опросе.`)) return;
    try {
      await transportApi.activateConfig(v.version);
      setOutcome({ ok: true, text: `Версия ${v.version} назначена действующей.`, errors: [] });
    } catch (e) {
      setOutcome({ ok: false, text: errorText(e), errors: [] });
    }
    versions.reload();
  };

  const rollback = async (v: TransportConfigVersion) => {
    if (!window.confirm(`Вернуться на версию ${v.version}? Действующая версия будет помечена как откатанная.`)) return;
    try {
      await transportApi.rollbackConfig(v.version);
      setOutcome({ ok: true, text: `Возврат на версию ${v.version} выполнен.`, errors: [] });
    } catch (e) {
      setOutcome({ ok: false, text: errorText(e), errors: [] });
    }
    versions.reload();
  };

  return (
    <>
      <section className="card">
        <h2>Версии конфигурации</h2>
        <Problem error={versions.error} />
        {versions.data && versions.data.items.length === 0 && <p className="muted">Версий ещё нет.</p>}
        {versions.data && versions.data.items.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>№</th>
                <th>Состояние</th>
                <th>Автор</th>
                <th>Создана</th>
                <th>Применена</th>
                <th>Примечание</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {versions.data.items.map((v) => (
                <tr key={v.version}>
                  <td>{v.version}</td>
                  <td>
                    {CONFIG_STATUS[v.status] || v.status}
                    {v.errors.length > 0 && (
                      <ul className="small">
                        {v.errors.map((e) => (
                          <li key={e}>{e}</li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td>{v.created_by}</td>
                  <td>{formatDate(v.created_at)}</td>
                  <td>{v.activated_at ? `${formatDate(v.activated_at)} (${v.activated_by})` : "—"}</td>
                  <td>{v.note}</td>
                  <td>
                    {props.canActivate && v.status === "VALIDATED" && (
                      <button className="button button--tiny button--primary" onClick={() => void activate(v)}>
                        Применить
                      </button>
                    )}
                    {props.canRollback && (v.status === "SUPERSEDED" || v.status === "ROLLED_BACK") && (
                      <button className="button button--tiny" onClick={() => void rollback(v)}>
                        Вернуться
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      {props.canValidate && (
        <section className="card">
          <h2>Проверить новую конфигурацию</h2>
          <p className="muted small">
            Описание проверяется теми же правилами, по которым его проверит узел. Проверка ничего не
            применяет: применение — отдельное действие с подтверждением.
          </p>
          <textarea
            rows={10}
            style={{ width: "100%", fontFamily: "monospace" }}
            value={spec}
            onChange={(e) => setSpec(e.target.value)}
            placeholder="Описание топологии в формате JSON"
          />
          <div className="form-row">
            <label>
              Примечание <input value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
            </label>
          </div>
          <button className="button button--primary" disabled={!spec.trim()} onClick={() => void validate()}>
            Проверить
          </button>
          {outcome && (
            <div className={outcome.ok ? "notice notice--info" : "notice notice--warning"} role="status">
              {outcome.text}
              {outcome.errors.length > 0 && (
                <ul>
                  {outcome.errors.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </section>
      )}
    </>
  );
}

/** Подпись состояния с запасным вариантом: неизвестное значение показывается как есть, а не роняет страницу. */
function look(map: Record<string, { label: string; cls: string }>, key: string): { label: string; cls: string } {
  return map[key] ?? { label: key, cls: "badge badge--unknown" };
}

/** Тройное состояние проверки: неизвестное не выдаётся ни за «хорошо», ни за «плохо». */
function tri(value: boolean | null): string {
  if (value === null) return "не проверялось";
  return value ? "доступен" : "НЕДОСТУПЕН";
}
