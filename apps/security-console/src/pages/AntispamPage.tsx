import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  antispamApi,
  type AuthConflict,
  type AuthDistribution,
  type CurrentUser,
  type DkimKeyRow,
  type PolicySimulation,
  type ReputationProviderRow,
  type ReputationView,
  type SpamPolicyRow,
  type SpamScanRow,
  type SpamSummary,
  type SpamValidation,
} from "../api/client";
import { formatDate } from "../types";

/**
 * Анти-спам, аутентификация и репутация (MSP 1.2, ТЗ 1.2 §35).
 *
 * Три решения в устройстве страницы:
 *
 * Первое: «класс спама» и «вердикт безопасности» показаны отдельными колонками и нигде не сложены в
 * одно число. SPAM + LOW_RISK и NOT_SPAM + HIGH_RISK одинаково допустимы, и оператор должен видеть обе оси.
 *
 * Второе: у репутации нет оценки без объяснения. Число без причин выглядело бы как приговор, а
 * положительная история не отключает ни одного жёсткого сигнала — об этом сказано на самой странице.
 *
 * Третье: предупреждение о теневом режиме висит на каждой вкладке. Ничего из показанного здесь не
 * отклоняет, не удаляет и не помещает в карантин письмо: действие MTA всегда «только наблюдение».
 */

type Tab = "overview" | "auth" | "reputation" | "policy" | "dkim" | "providers";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Спам: обзор" },
  { id: "auth", label: "Аутентификация" },
  { id: "reputation", label: "Репутация" },
  { id: "policy", label: "Симулятор политики" },
  { id: "dkim", label: "Подпись DKIM" },
  { id: "providers", label: "Провайдеры" },
];

const CLASS_LABEL: Record<string, string> = {
  NOT_SPAM: "не спам",
  BULK: "рассылка",
  SUSPECTED_SPAM: "подозрение на спам",
  SPAM: "спам",
  HIGH_CONFIDENCE_SPAM: "спам (высокая уверенность)",
  UNKNOWN: "нет данных",
};

const RESULT_CLASS: Record<string, string> = {
  PASS: "badge badge--low_risk",
  FAIL: "badge badge--malicious",
  SOFTFAIL: "badge badge--suspicious",
  NEUTRAL: "badge badge--unknown",
  NONE: "badge badge--unknown",
  TEMPERROR: "badge badge--suspicious",
  PERMERROR: "badge badge--suspicious",
  UNKNOWN: "badge badge--unknown",
};

const APPROVAL_LABEL: Record<string, string> = {
  DRAFT: "черновик (отключён политикой)",
  PENDING_APPROVAL: "ждёт второго человека",
  APPROVED: "одобрен",
  REJECTED: "отклонён",
  SUSPENDED: "приостановлен",
};

const KEY_STATUS_LABEL: Record<string, string> = {
  GENERATED: "создан",
  DNS_PENDING: "ждёт публикации в DNS",
  READY: "запись проверена",
  ACTIVE: "действует",
  RETIRING: "выводится (перекрытие)",
  RETIRED: "выведен",
  FAILED: "ошибка",
};

function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return error instanceof Error ? error.message : "Неизвестная ошибка";
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

export function AntispamPage({ user }: { user: CurrentUser }) {
  const [tab, setTab] = useState<Tab>("overview");
  const can = (permission: string) => user.permissions.includes(permission);

  return (
    <div className="page">
      <h1>Анти-спам и аутентификация</h1>
      <div className="notice notice--warning" role="alert">
        <strong>Теневой режим MSP 1.2.</strong> Ничего из показанного здесь не отклоняет, не удаляет и не
        помещает в карантин письма: реальное действие MTA — «только наблюдение». MSP 1.2 IS NOT APPROVED FOR
        PRODUCTION MX CUTOVER.
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
      {tab === "auth" && <AuthTab canReview={can("auth:conflict:review")} />}
      {tab === "reputation" && <ReputationTab />}
      {tab === "policy" && (
        <PolicyTab canEdit={can("spam:policy:edit")} canApprove={can("spam:policy:approve")} canSimulate={can("spam:simulate")} />
      )}
      {tab === "dkim" && (
        <DkimTab
          canRead={can("dkim:read")}
          canGenerate={can("dkim:key:generate")}
          canActivate={can("dkim:key:activate")}
          canRetire={can("dkim:key:retire")}
        />
      )}
      {tab === "providers" && <ProvidersTab canManage={can("reputation:provider:manage")} />}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
function Bars({ data }: { data: Record<string, number> }) {
  const max = Math.max(1, ...Object.values(data));
  return (
    <table className="table">
      <tbody>
        {Object.entries(data).map(([label, value]) => (
          <tr key={label}>
            <td>{label}</td>
            <td style={{ width: "60%" }}>
              <div style={{ background: "var(--accent, #3b6ea5)", height: 10, width: `${(value / max) * 100}%` }} />
            </td>
            <td>{value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Overview() {
  const summary = useLoad<SpamSummary>(() => antispamApi.summary(24));
  const messages = useLoad<{ items: SpamScanRow[] }>(() => antispamApi.messages({ limit: 20 }));
  const validation = useLoad<SpamValidation>(() => antispamApi.validation());
  const s = summary.data;
  return (
    <div>
      <Problem error={summary.error ?? messages.error ?? validation.error} />
      {s && (
        <>
          <section className="card">
            <h2>За {s.window_hours} ч</h2>
            <p>
              Проанализировано писем: <strong>{s.analyzed}</strong>. Применённое действие: <strong>{s.applied_action}</strong>.
              Принуждение: <strong>{s.enforcement_enabled ? "включено" : "выключено"}</strong>.
            </p>
            <div className="grid">
              <div>
                <h3>Классы спама</h3>
                <Bars data={Object.fromEntries(Object.entries(s.spam_classes).map(([k, v]) => [CLASS_LABEL[k] ?? k, v]))} />
              </div>
              <div>
                <h3>Предложения сканера (не исполняются)</h3>
                <Bars data={s.suggested_actions} />
              </div>
              <div>
                <h3>Гистограмма оценок</h3>
                <Bars data={s.score_histogram} />
              </div>
            </div>
          </section>
          <section className="card">
            <h2>Символы и списки</h2>
            <p>Срабатываний провайдеров репутации: <strong>{s.rbl_hits}</strong>.</p>
            <table className="table">
              <thead>
                <tr>
                  <th>Символ</th>
                  <th>Писем</th>
                </tr>
              </thead>
              <tbody>
                {s.top_symbols.map(([name, count]) => (
                  <tr key={name}>
                    <td>{name}</td>
                    <td>{count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <section className="card">
            <h2>Ложные срабатывания и пропуски</h2>
            <p>
              Просмотрено аналитиками: <strong>{s.false_positive_metrics.reviewed}</strong>; ложных срабатываний на 1000:{" "}
              <strong>{s.false_positive_metrics.spam_fp_per_1000}</strong> (нижняя граница, пока просмотрена не вся выборка);
              пропусков спама: <strong>{s.false_positive_metrics.spam_fn}</strong>.
            </p>
            {validation.data && (
              <p className={validation.data.reject_safety.ready_for_discussion ? "" : "muted"}>
                Допуск к обсуждению отказа в MSP 1.3: {validation.data.reject_safety.ready_for_discussion ? "достаточно данных" : "пока нет"}
                {validation.data.reject_safety.reasons.length > 0 && <> — {validation.data.reject_safety.reasons.join("; ")}</>}
              </p>
            )}
          </section>
          <section className="card">
            <h2>Здоровье сканера</h2>
            {s.health.length === 0 && <p className="muted">Узлы не присылали состояние сканера.</p>}
            <table className="table">
              <tbody>
                {s.health.map((h) => {
                  const r = h.rspamd as Record<string, unknown> | null;
                  return (
                    <tr key={h.node_id}>
                      <td>{h.node_id.slice(0, 8)}</td>
                      <td>{r ? (r.up ? "Rspamd работает" : "Rspamd не отвечает") : "нет данных"}</td>
                      <td>{r ? (r.redis_up === false ? "Redis недоступен" : "Redis в порядке") : ""}</td>
                      <td>{r ? `конфигурация: ${String(r.drift ?? "UNKNOWN")}` : ""}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </section>
        </>
      )}
      <section className="card">
        <h2>Последние письма</h2>
        <table className="table">
          <thead>
            <tr>
              <th>Письмо</th>
              <th>Класс спама</th>
              <th>Вердикт безопасности</th>
              <th>SPF / DKIM / DMARC</th>
              <th>Оценка</th>
              <th>Предложено / применено</th>
            </tr>
          </thead>
          <tbody>
            {(messages.data?.items ?? []).map((m) => (
              <tr key={m.id}>
                <td title={formatDate(m.received_at)}>{m.message_id}</td>
                <td>{CLASS_LABEL[m.spam_class] ?? m.spam_class}</td>
                <td>{m.security_verdict ?? "—"}</td>
                <td>
                  <span className={RESULT_CLASS[m.spf ?? "NONE"]}>{m.spf ?? "—"}</span>{" "}
                  <span className={RESULT_CLASS[m.dkim ?? "NONE"]}>{m.dkim ?? "—"}</span>{" "}
                  <span className={RESULT_CLASS[m.dmarc ?? "NONE"]}>{m.dmarc ?? "—"}</span>
                </td>
                <td>{m.score.toFixed(1)}</td>
                <td>
                  {m.suggested_action} → {m.applied_action}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
function AuthTab({ canReview }: { canReview: boolean }) {
  const dist = useLoad<AuthDistribution>(() => antispamApi.authDistribution(24));
  const conflicts = useLoad<{ items: AuthConflict[] }>(() => antispamApi.conflicts());
  const [message, setMessage] = useState<string | null>(null);
  const decide = async (id: string, disposition: string) => {
    try {
      await antispamApi.reviewConflict(id, disposition);
      setMessage(null);
      conflicts.reload();
    } catch (e) {
      setMessage(errorText(e));
    }
  };
  const d = dist.data;
  return (
    <div>
      <Problem error={dist.error ?? conflicts.error ?? message} />
      {d && (
        <section className="card">
          <h2>Распределение результатов за {d.window_hours} ч</h2>
          <p className="muted">
            Недоступный DNS даёт TEMPERROR (недостающее свидетельство), а не FAIL. Неполных проверок: {d.incomplete};
            провалов выравнивания: {d.alignment_failures}; расхождений с вышестоящим шлюзом: {d.conflicts}.
          </p>
          <div className="grid">
            {Object.entries(d.distributions).map(([method, values]) => (
              <div key={method}>
                <h3>{method.toUpperCase()}</h3>
                <Bars data={values} />
              </div>
            ))}
          </div>
          <h3>Домены с провалом DMARC</h3>
          <table className="table">
            <tbody>
              {d.top_failing_domains.map(([domain, count]) => (
                <tr key={domain}>
                  <td>{domain}</td>
                  <td>{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
      <section className="card">
        <h2>Расхождения: вышестоящий шлюз и MSP</h2>
        <p className="muted">
          Расхождение не скрывается и не разрешается в чью-то пользу. Чистый вердикт вышестоящего шлюза риск MSP не снижает.
        </p>
        <table className="table">
          <thead>
            <tr>
              <th>Вид</th>
              <th>Вышестоящий</th>
              <th>MSP</th>
              <th>Решение</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(conflicts.data?.items ?? []).map((c) => (
              <tr key={c.id}>
                <td>{c.kind}</td>
                <td>{c.upstream_value}</td>
                <td>{c.msp_value}</td>
                <td>{c.disposition}</td>
                <td>
                  {canReview &&
                    ["EXPECTED", "REAL_PROBLEM", "FALSE_ALARM"].map((value) => (
                      <button key={value} className="btn btn--small" onClick={() => decide(c.id, value)}>
                        {value}
                      </button>
                    ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
function ReputationTab() {
  const [kind, setKind] = useState<"ip" | "domain">("ip");
  const [value, setValue] = useState("");
  const [view, setView] = useState<ReputationView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const look = async () => {
    try {
      setView(kind === "ip" ? await antispamApi.ipReputation(value.trim()) : await antispamApi.domainReputation(value.trim()));
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  };
  return (
    <section className="card">
      <h2>Локальная репутация</h2>
      <p className="muted">
        Положительная история никогда не отключает вредоносное вложение, BEC, имитацию домена и совпадение с TI. Репутация
        затухает со временем. Числа без объяснения не показываются.
      </p>
      <Problem error={error} />
      <div className="row">
        <select value={kind} onChange={(e) => setKind(e.target.value as "ip" | "domain")}>
          <option value="ip">IP-адрес</option>
          <option value="domain">Домен</option>
        </select>
        <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="203.0.113.5 или example.com" />
        <button className="btn" onClick={look} disabled={!value.trim()}>
          Показать
        </button>
      </div>
      {view && (
        <div>
          <p>
            Уровень: <strong>{view.tier}</strong>, оценка {view.score} из 100{" "}
            {view.known ? `(наблюдений: ${view.message_count ?? 0})` : "(ещё не наблюдался)"}
          </p>
          <ul>
            {view.explanations.map((text) => (
              <li key={text}>{text}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------------------------
function PolicyTab({ canEdit, canApprove, canSimulate }: { canEdit: boolean; canApprove: boolean; canSimulate: boolean }) {
  const policies = useLoad(() => antispamApi.policies());
  const [spam, setSpam] = useState("6");
  const [suspected, setSuspected] = useState("4");
  const [simulation, setSimulation] = useState<PolicySimulation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      setError(null);
      policies.reload();
    } catch (e) {
      setError(errorText(e));
    }
  };
  const NEXT: Record<string, string> = { DRAFT: "SHADOW", SHADOW: "VALIDATION", VALIDATION: "APPROVED", APPROVED: "ACTIVE_SHADOW" };
  return (
    <div>
      <Problem error={policies.error ?? error} />
      <section className="card">
        <h2>Кандидаты политики</h2>
        <p className="muted">
          Состояния: DRAFT → SHADOW → VALIDATION → APPROVED → ACTIVE_SHADOW. Состояния «принуждение» нет. Одобряет не тот, кто правил.
        </p>
        <table className="table">
          <thead>
            <tr>
              <th>Версия</th>
              <th>Состояние</th>
              <th>Пороги</th>
              <th>Правил / одобрил</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(policies.data?.items ?? []).map((p: SpamPolicyRow) => (
              <tr key={p.id}>
                <td>{p.version}</td>
                <td>{p.state}</td>
                <td>{p.thresholds ? Object.entries(p.thresholds).map(([k, v]) => `${k}=${v}`).join(", ") : ""}</td>
                <td>
                  {p.edited_by} / {p.approved_by || "—"}
                </td>
                <td>
                  {canSimulate && (
                    <button className="btn btn--small" onClick={() => act(async () => setSimulation(await antispamApi.simulate(p.id)))}>
                      Симулировать
                    </button>
                  )}
                  {NEXT[p.state] && NEXT[p.state] !== "APPROVED" && NEXT[p.state] !== "ACTIVE_SHADOW" && canEdit && (
                    <button className="btn btn--small" onClick={() => act(() => antispamApi.transition(p.id, NEXT[p.state] ?? ""))}>
                      → {NEXT[p.state]}
                    </button>
                  )}
                  {p.state === "VALIDATION" && canApprove && (
                    <button className="btn btn--small" onClick={() => act(() => antispamApi.transition(p.id, "APPROVED"))}>
                      Одобрить
                    </button>
                  )}
                  {p.state === "APPROVED" && canApprove && (
                    <button className="btn btn--small" onClick={() => act(() => antispamApi.activateShadow(p.id))}>
                      Включить в теневом режиме
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {canEdit && (
          <div className="row">
            <label>
              подозрение от <input value={suspected} onChange={(e) => setSuspected(e.target.value)} size={4} />
            </label>
            <label>
              спам от <input value={spam} onChange={(e) => setSpam(e.target.value)} size={4} />
            </label>
            <button
              className="btn"
              onClick={() => act(() => antispamApi.createPolicy({ suspected: Number(suspected), spam: Number(spam) }))}
            >
              Создать кандидата
            </button>
          </div>
        )}
      </section>
      {simulation && (
        <section className="card">
          <h2>Что изменилось бы</h2>
          <p>
            Оценено писем: {simulation.evaluated}; изменилось бы действие: {simulation.changed}. Применённое действие —{" "}
            <strong>{simulation.applied_action}</strong>: поток почты симулятором не затрагивается.
          </p>
          <table className="table">
            <thead>
              <tr>
                <th>Письмо</th>
                <th>Оценка</th>
                <th>Класс сейчас → у кандидата</th>
                <th>Предложение сейчас → гипотеза</th>
              </tr>
            </thead>
            <tbody>
              {simulation.items.map((item) => (
                <tr key={item.scan_id} style={item.changed ? { fontWeight: 600 } : undefined}>
                  <td>{item.message_id}</td>
                  <td>{item.score.toFixed(1)}</td>
                  <td>
                    {CLASS_LABEL[item.current_spam_class] ?? item.current_spam_class} → {CLASS_LABEL[item.candidate_spam_class] ?? item.candidate_spam_class}
                  </td>
                  <td>
                    {item.current_suggested_action} → {item.hypothetical_action}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
function DkimTab({
  canRead,
  canGenerate,
  canActivate,
  canRetire,
}: {
  canRead: boolean;
  canGenerate: boolean;
  canActivate: boolean;
  canRetire: boolean;
}) {
  const keys = useLoad(() => (canRead ? antispamApi.dkimKeys() : Promise.resolve({ items: [] as DkimKeyRow[] })), [canRead]);
  const [domain, setDomain] = useState("");
  const [selector, setSelector] = useState("");
  const [fresh, setFresh] = useState<DkimKeyRow | null>(null);
  const [error, setError] = useState<string | null>(null);
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      setError(null);
      keys.reload();
    } catch (e) {
      setError(errorText(e));
    }
  };
  if (!canRead) return <div className="notice">Нет права просмотра ключей подписи.</div>;
  return (
    <div>
      <Problem error={keys.error ?? error} />
      <section className="card">
        <h2>Ключи подписи исходящей почты</h2>
        <p className="muted">
          Подпись допускается только для лабораторного или пилотного домена и только на доверенном пути Exchange → шлюз. Активирует ключ
          другой человек, и только после проверки записи в DNS. Закрытая часть в панели не хранится.
        </p>
        <table className="table">
          <thead>
            <tr>
              <th>Домен / селектор</th>
              <th>Состояние</th>
              <th>Запись DNS</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(keys.data?.items ?? []).map((k) => (
              <tr key={k.id}>
                <td>
                  {k.domain} / {k.selector}
                </td>
                <td>
                  {KEY_STATUS_LABEL[k.status] ?? k.status} {k.failure && <span className="muted">({k.failure})</span>}
                </td>
                <td style={{ maxWidth: 360, overflowWrap: "anywhere" }}>
                  <code>{k.dns_name}</code>
                </td>
                <td>
                  {canGenerate && (k.status === "DNS_PENDING" || k.status === "READY") && (
                    <button className="btn btn--small" onClick={() => act(() => antispamApi.verifyKeyDns(k.id))}>
                      Проверить DNS
                    </button>
                  )}
                  {canActivate && k.status === "READY" && (
                    <button className="btn btn--small" onClick={() => act(() => antispamApi.activateKey(k.id))}>
                      Активировать
                    </button>
                  )}
                  {canRetire && (k.status === "ACTIVE" || k.status === "RETIRING") && (
                    <button className="btn btn--small" onClick={() => act(() => antispamApi.retireKey(k.id))}>
                      {k.status === "ACTIVE" ? "Начать вывод" : "Завершить вывод"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {canGenerate && (
          <div className="row">
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="домен подписи" />
            <input value={selector} onChange={(e) => setSelector(e.target.value)} placeholder="селектор" />
            <button
              className="btn"
              onClick={() =>
                act(async () => {
                  setFresh(await antispamApi.generateKey(domain.trim(), selector.trim()));
                })
              }
              disabled={!domain.trim() || !selector.trim()}
            >
              Создать ключ
            </button>
          </div>
        )}
      </section>
      {fresh && (
        <section className="card">
          <h2>Новый ключ: опубликуйте запись и сохраните закрытую часть</h2>
          <p>
            Запись TXT для <code>{fresh.dns_name}</code>:
          </p>
          <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{fresh.public_record}</pre>
          <p>
            Закрытая часть показывается один раз. Положите её в хранилище секретов узла по пути <code>{fresh.private_key_ref}</code> и
            закройте это окно: панель её не сохраняет.
          </p>
          <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{fresh.private_key_pem ?? ""}</pre>
          <button className="btn" onClick={() => setFresh(null)}>
            Я сохранил ключ
          </button>
        </section>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
function ProvidersTab({ canManage }: { canManage: boolean }) {
  const providers = useLoad(() => antispamApi.providers());
  const [error, setError] = useState<string | null>(null);
  const [id, setId] = useState("");
  const [zone, setZone] = useState("");
  const [name, setName] = useState("");
  const [scope, setScope] = useState("");
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      setError(null);
      providers.reload();
    } catch (e) {
      setError(errorText(e));
    }
  };
  return (
    <div>
      <Problem error={providers.error ?? error} />
      <section className="card">
        <h2>Провайдеры репутации (DNSBL)</h2>
        <p className="muted">
          Публичный список без одобренной лицензии не используется (статус «отключён политикой»). Включение уносит данные письма во внешний
          DNS: его запрашивает один человек, а одобряет другой. Секретные зоны здесь не показываются.
        </p>
        <table className="table">
          <thead>
            <tr>
              <th>Провайдер</th>
              <th>Лицензия</th>
              <th>Типы запросов</th>
              <th>Состояние</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(providers.data?.items ?? []).map((p: ReputationProviderRow) => (
              <tr key={p.id}>
                <td>
                  {p.provider_name} <code>{p.id}</code> {p.has_secret_zone && <span className="muted">(секретная зона)</span>}
                </td>
                <td>{p.license_mode}</td>
                <td>{p.query_types.join(", ")}</td>
                <td>
                  {APPROVAL_LABEL[p.approval_state] ?? p.approval_state}; статус {p.status}
                </td>
                <td>
                  {canManage && (p.approval_state === "DRAFT" || p.approval_state === "REJECTED" || p.approval_state === "SUSPENDED") && (
                    <button
                      className="btn btn--small"
                      onClick={() => act(() => antispamApi.providerAction(p.id, "request-activation", { usage_scope: scope }))}
                    >
                      Запросить включение
                    </button>
                  )}
                  {canManage && p.approval_state === "PENDING_APPROVAL" && (
                    <>
                      <button className="btn btn--small" onClick={() => act(() => antispamApi.providerAction(p.id, "approve"))}>
                        Одобрить
                      </button>
                      <button className="btn btn--small" onClick={() => act(() => antispamApi.providerAction(p.id, "reject"))}>
                        Отклонить
                      </button>
                    </>
                  )}
                  {canManage && p.approval_state === "APPROVED" && (
                    <button className="btn btn--small" onClick={() => act(() => antispamApi.providerAction(p.id, "suspend"))}>
                      Приостановить
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {canManage && (
          <div className="row">
            <input value={id} onChange={(e) => setId(e.target.value)} placeholder="идентификатор" />
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="название" />
            <input value={zone} onChange={(e) => setZone(e.target.value)} placeholder="зона DNS" />
            <input value={scope} onChange={(e) => setScope(e.target.value)} placeholder="область применения лицензии" />
            <button
              className="btn"
              disabled={!id.trim() || !zone.trim()}
              onClick={() =>
                act(() =>
                  antispamApi.createProvider({
                    id: id.trim(),
                    provider_name: name.trim() || id.trim(),
                    zone: zone.trim(),
                    query_types: ["CLIENT_IP"],
                    license_mode: "PUBLIC_NONCOMMERCIAL",
                    privacy_class: "EXTERNAL_DNS",
                  }),
                )
              }
            >
              Добавить (отключён)
            </button>
          </div>
        )}
      </section>
    </div>
  );
}
