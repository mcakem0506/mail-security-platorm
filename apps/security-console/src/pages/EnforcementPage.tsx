import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  enforcementApi,
  type CurrentUser,
  type EnforcementControl,
  type EnforcementDecisionRow,
  type EnforcementExceptionRow,
  type EnforcementIncident,
  type EnforcementSafety,
  type KillSwitchState,
} from "../api/client";
import { formatDate } from "../types";

/**
 * Принуждение (MSP 1.3, ТЗ 1.3 §62).
 *
 * Три решения в устройстве страницы:
 *
 * Первое: нет кнопки «включить принуждение». Есть восемь контролей, у каждого свои состояние и готовность, и
 * включение каждого — запрос, который подтверждает другой человек. Контроль, заблокированный известным
 * пробелом, показан как заблокированный, а кнопка запроса для него недоступна (сервер всё равно ответит 409).
 *
 * Второе: «предложено» и «применено» — разные колонки. Строка «предложено: REJECT, применено: только наблюдение»
 * — норма для канарейки; смешать эти колонки значило бы выдать предложение за отказ.
 *
 * Третье: общий выключатель всегда виден в шапке и включается без согласования, а снимается вторым человеком.
 */

type Tab = "controls" | "decisions" | "exceptions" | "safety" | "incidents";

const TABS: { id: Tab; label: string }[] = [
  { id: "controls", label: "Контроли" },
  { id: "decisions", label: "Решения" },
  { id: "exceptions", label: "Исключения" },
  { id: "safety", label: "Безопасность" },
  { id: "incidents", label: "Инциденты" },
];

const STATE_LABEL: Record<string, string> = {
  DISABLED: "выключен",
  SHADOW: "наблюдение",
  CANARY: "канарейка",
  PILOT: "пилот",
  PAUSED: "приостановлен",
  ROLLED_BACK: "откачен",
};

const READINESS_LABEL: Record<string, string> = {
  READY: "готов",
  READY_WITH_WARNINGS: "готов с предупреждениями",
  NOT_READY: "не готов",
  BLOCKED_BY_GAP: "заблокирован пробелом",
};

const READINESS_CLASS: Record<string, string> = {
  READY: "badge badge--low_risk",
  READY_WITH_WARNINGS: "badge badge--suspicious",
  NOT_READY: "badge badge--unknown",
  BLOCKED_BY_GAP: "badge badge--malicious",
};

const APPLIED_LABEL: Record<string, string> = {
  OBSERVE_ONLY: "только наблюдение",
  SMTP_REJECT: "отказ SMTP",
  SMTP_TEMPFAIL: "временный отказ",
  QUARANTINED: "в карантине",
  HELD: "удержано",
  BYPASS_BY_EXCEPTION: "обход: исключение",
  BYPASS_KILL_SWITCH: "обход: выключатель",
  BYPASS_LOCAL: "обход: локальный",
  SAFE_MODE: "безопасный режим",
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

export function EnforcementPage({ user }: { user: CurrentUser }) {
  const [tab, setTab] = useState<Tab>("controls");
  const can = (permission: string) => user.permissions.includes(permission);
  return (
    <div className="page">
      <h1>Принуждение</h1>
      <div className="notice notice--warning" role="alert">
        <strong>MSP 1.3 IS NOT APPROVED FOR GLOBAL PRODUCTION MX CUTOVER.</strong> Принуждение включается отдельно
        по каждому контролю, для ограниченной области и по согласованию двух людей. Общего переключателя нет.
      </div>
      <KillSwitchBar canUse={can("enforcement:kill_switch")} />
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
      {tab === "controls" && (
        <ControlsTab
          canCanary={can("enforcement:canary")}
          canPilot={can("enforcement:pilot")}
          canPause={can("enforcement:pause")}
          canRollback={can("enforcement:rollback")}
        />
      )}
      {tab === "decisions" && <DecisionsTab canReview={can("review:real_flow")} />}
      {tab === "exceptions" && <ExceptionsTab canCreate={can("create:exception")} canApprove={can("exception:approve")} />}
      {tab === "safety" && <SafetyTab />}
      {tab === "incidents" && <IncidentsTab />}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
function KillSwitchBar({ canUse }: { canUse: boolean }) {
  const state = useLoad<KillSwitchState>(() => enforcementApi.killSwitch());
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const s = state.data;
  const act = async (fn: () => Promise<KillSwitchState>) => {
    setError(null);
    try {
      const result = await fn();
      setMessage(result.status === "CLEAR_REQUESTED" ? "Запрос на снятие подан: нужен второй человек." : null);
      state.reload();
    } catch (e) {
      setError(errorText(e));
    }
  };
  return (
    <section className="card" aria-label="Общий выключатель">
      <Problem error={state.error ?? error} />
      {s && (
        <p>
          Общий выключатель:{" "}
          <span className={s.active ? "badge badge--malicious" : "badge badge--low_risk"}>
            {s.active ? "ВКЛЮЧЁН — принуждение остановлено" : "выключен"}
          </span>
          {s.active && (
            <>
              {" "}
              Включил {s.activated_by ?? "—"}: {s.reason}.
              {s.clear_requested_by ? ` Запрос на снятие подал ${s.clear_requested_by}.` : ""}
            </>
          )}
        </p>
      )}
      {message && <p className="muted">{message}</p>}
      {canUse && s && (
        <div className="filters">
          <input
            aria-label="Причина"
            placeholder="Причина (обязательна)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          {!s.active ? (
            <button className="button button--danger" disabled={reason.trim().length < 3} onClick={() => act(() => enforcementApi.killSwitchOn(reason))}>
              Остановить принуждение
            </button>
          ) : (
            <button className="button" disabled={reason.trim().length < 3} onClick={() => act(() => enforcementApi.killSwitchClear(reason))}>
              Снять (нужен второй человек)
            </button>
          )}
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------------------------
function ControlsTab(props: { canCanary: boolean; canPilot: boolean; canPause: boolean; canRollback: boolean }) {
  const controls = useLoad(() => enforcementApi.controls());
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<Record<string, string>>({});
  const [why, setWhy] = useState<Record<string, string>>({});

  const run = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      controls.reload();
    } catch (e) {
      setError(errorText(e));
    }
  };

  return (
    <div>
      <Problem error={controls.error ?? error} />
      <table className="table">
        <thead>
          <tr>
            <th>Контроль</th>
            <th>Состояние</th>
            <th>Готовность</th>
            <th>Причины и предупреждения</th>
            <th>Действия</th>
          </tr>
        </thead>
        <tbody>
          {(controls.data?.items ?? []).map((c: EnforcementControl) => (
            <tr key={c.id}>
              <td>
                <strong>{c.type}</strong>
                <div className="muted small">политика {c.policy_version || "—"}</div>
              </td>
              <td>
                {STATE_LABEL[c.state] ?? c.state}
                {c.activated_by && <div className="muted small">запросил {c.activated_by}, согласовал {c.approved_by}</div>}
              </td>
              <td>
                <span className={READINESS_CLASS[c.readiness_status] ?? "badge badge--unknown"}>
                  {READINESS_LABEL[c.readiness_status] ?? c.readiness_status}
                </span>
                {c.blocking_gaps.length > 0 && <div className="small">пробел: {c.blocking_gaps.join(", ")}</div>}
              </td>
              <td>
                <ul className="small">
                  {[...c.readiness_reasons, ...c.readiness_warnings].slice(0, 6).map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              </td>
              <td>
                {c.pending_request && (
                  <div className="notice notice--info">
                    Ждёт второго человека: {c.pending_request.target}, запросил {c.pending_request.requested_by}.
                    <div>{c.pending_request.justification}</div>
                    {props.canCanary && (
                      <button className="button button--tiny button--primary" onClick={() => run(() => enforcementApi.activate(c.id, c.pending_request!.target === "PILOT" ? "pilot" : "canary", { action: "approve" }))}>
                        Согласовать
                      </button>
                    )}
                  </div>
                )}
                {props.canCanary && !c.pending_request && c.blocking_gaps.length === 0 && (
                  <div className="form-row">
                    <input
                      aria-label={`Получатели канарейки ${c.type}`}
                      placeholder="получатели через запятую"
                      value={scope[c.id] ?? ""}
                      onChange={(e) => setScope({ ...scope, [c.id]: e.target.value })}
                    />
                    <input
                      aria-label={`Обоснование ${c.type}`}
                      placeholder="обоснование"
                      value={why[c.id] ?? ""}
                      onChange={(e) => setWhy({ ...why, [c.id]: e.target.value })}
                    />
                    <button
                      className="button button--tiny"
                      disabled={!c.eligibility.can_canary || !(scope[c.id] ?? "").trim()}
                      onClick={() =>
                        run(() =>
                          enforcementApi.activate(c.id, "canary", {
                            action: "request",
                            scope: { recipients: (scope[c.id] ?? "").split(",").map((x) => x.trim()).filter(Boolean) },
                            justification: why[c.id] ?? "",
                          }),
                        )
                      }
                    >
                      Запросить канарейку
                    </button>
                  </div>
                )}
                {props.canPause && ["CANARY", "PILOT"].includes(c.state) && (
                  <button className="button button--tiny button--danger" onClick={() => run(() => enforcementApi.pause(c.id, "приостановлено из консоли"))}>
                    Пауза
                  </button>
                )}
                {props.canRollback && ["CANARY", "PILOT", "PAUSED"].includes(c.state) && (
                  <button className="button button--tiny" onClick={() => run(() => enforcementApi.rollback(c.id, "откат из консоли"))}>
                    Откат
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
function DecisionsTab({ canReview }: { canReview: boolean }) {
  const [control, setControl] = useState("");
  const decisions = useLoad(() => enforcementApi.decisions(control ? { control } : {}), [control]);
  const [error, setError] = useState<string | null>(null);
  const review = async (row: EnforcementDecisionRow, outcome: "CORRECT" | "FALSE_POSITIVE", critical = false) => {
    setError(null);
    try {
      await enforcementApi.reviewDecision(row.id, outcome, critical);
      decisions.reload();
    } catch (e) {
      setError(errorText(e));
    }
  };
  return (
    <div>
      <Problem error={decisions.error ?? error} />
      <div className="filters">
        <select aria-label="Контроль" value={control} onChange={(e) => setControl(e.target.value)}>
          <option value="">все контроли</option>
          {["SPAM_REJECT", "DMARC_REJECT", "RBL_REJECT", "MALWARE_REJECT", "PHISHING_REJECT", "TEMPFAIL_ABUSE", "QUARANTINE", "OUTBOUND_BLOCK"].map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
      </div>
      <table className="table table--compact">
        <thead>
          <tr>
            <th>Время</th>
            <th>Контроль</th>
            <th>Предложено</th>
            <th>Применено</th>
            <th>Причины</th>
            <th>Политика</th>
            <th>Тайм-аут</th>
            <th>Разбор</th>
          </tr>
        </thead>
        <tbody>
          {(decisions.data?.items ?? []).map((d) => (
            <tr key={d.id}>
              <td>{formatDate(d.decided_at)}</td>
              <td>{d.control_type}</td>
              <td>{d.suggested_action || "—"}</td>
              <td>{APPLIED_LABEL[d.applied_action] ?? d.applied_action}</td>
              <td className="small">{d.reason_codes.join(", ")}</td>
              <td>{d.policy_version}</td>
              <td>{d.fail_mode_applied ?? "—"}</td>
              <td>
                {d.review_outcome ?? (
                  canReview && ["SMTP_REJECT", "QUARANTINED"].includes(d.applied_action) ? (
                    <>
                      <button className="button button--tiny" onClick={() => review(d, "CORRECT")}>верно</button>
                      <button className="button button--tiny button--danger" onClick={() => review(d, "FALSE_POSITIVE")}>ложное</button>
                      <button className="button button--tiny button--danger" onClick={() => review(d, "FALSE_POSITIVE", true)}>критическое</button>
                    </>
                  ) : (
                    "—"
                  )
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {decisions.data && decisions.data.items.length === 0 && <p className="muted">Решений пока нет.</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
function ExceptionsTab({ canCreate, canApprove }: { canCreate: boolean; canApprove: boolean }) {
  const exceptions = useLoad(() => enforcementApi.exceptions());
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ scope: "SENDER", control: "SPAM_REJECT", value: "", reason: "", hours: 168 });
  const run = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      exceptions.reload();
    } catch (e) {
      setError(errorText(e));
    }
  };
  return (
    <div>
      <Problem error={exceptions.error ?? error} />
      <p className="muted">
        Исключение всегда срочное (по умолчанию 7 дней, не больше 90) и не скрывает сигналы: меняется только применённое
        действие. Обход вредоносного, DMARC, RBL и фишинга требует второго человека.
      </p>
      {canCreate && (
        <div className="form-row">
          <select aria-label="Область" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })}>
            {["SENDER", "SENDER_DOMAIN", "RECIPIENT", "SOURCE_IP", "MESSAGE_ID", "CAMPAIGN"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <input aria-label="Контроль" value={form.control} onChange={(e) => setForm({ ...form, control: e.target.value })} />
          <input aria-label="Значение" placeholder="значение" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />
          <input aria-label="Причина" placeholder="причина" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
          <input aria-label="Срок, часов" type="number" min={1} max={2160} value={form.hours} onChange={(e) => setForm({ ...form, hours: Number(e.target.value) })} />
          <button
            className="button button--primary"
            disabled={!form.value.trim() || form.reason.trim().length < 5}
            onClick={() => run(() => enforcementApi.createException({ scope: form.scope, control: form.control, value: form.value, reason: form.reason, expires_in_hours: form.hours }))}
          >
            Создать
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Область</th>
            <th>Контроль</th>
            <th>Значение</th>
            <th>Причина</th>
            <th>Владелец</th>
            <th>До</th>
            <th>Статус</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {(exceptions.data?.items ?? []).map((x: EnforcementExceptionRow) => (
            <tr key={x.id} className={x.active ? undefined : "row--inactive"}>
              <td>{x.scope}</td>
              <td>{x.control ?? "—"}</td>
              <td>{x.value}</td>
              <td>{x.reason}</td>
              <td>{x.owner}</td>
              <td>{formatDate(x.expires_at)}</td>
              <td>{x.active ? "действует" : x.approved ? "завершено" : "ждёт второго человека"}</td>
              <td>
                {canApprove && !x.approved && (
                  <button className="button button--tiny" onClick={() => run(() => enforcementApi.approveException(x.id))}>Согласовать</button>
                )}
                {canCreate && x.active && (
                  <button className="button button--tiny button--danger" onClick={() => run(() => enforcementApi.revokeException(x.id))}>Отозвать</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
function SafetyTab() {
  const safety = useLoad<EnforcementSafety>(() => enforcementApi.safety());
  const s = safety.data;
  const pct = (v: number | null) => (v === null ? "нет данных" : `${(v * 100).toFixed(2)} %`);
  return (
    <div>
      <Problem error={safety.error} />
      {s && (
        <>
          <section className="card">
            <h2>Политика и узлы</h2>
            <p>
              Текущая политика: <strong>{s.policy?.version ?? "—"}</strong> <span className="hash">{s.policy?.checksum.slice(0, 12)}</span>
            </p>
            <table className="table table--compact">
              <thead>
                <tr><th>Узел</th><th>Контрольная сумма</th><th>Состояние</th><th>Совпадает</th><th>Локальный обход</th></tr>
              </thead>
              <tbody>
                {s.nodes.map((n) => (
                  <tr key={n.node_id}>
                    <td>{n.node_id.slice(0, 8)}</td>
                    <td className="hash">{n.policy_checksum?.slice(0, 12) ?? "—"}</td>
                    <td>{n.policy_status ?? "—"}</td>
                    <td>{n.in_sync ? "да" : "НЕТ"}</td>
                    <td>{n.local_bypass ? "ВКЛЮЧЁН" : "нет"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {s.nodes.length === 0 && <p className="muted">Узлы ещё не сообщали о принуждении.</p>}
          </section>
          <section className="card">
            <h2>Безопасность отказов по контролям</h2>
            <p className="muted">
              Нет знаменателя — «нет данных», а не 0 %. Лабораторная выборка допускает только канарейку.
            </p>
            <table className="table table--compact">
              <thead>
                <tr><th>Контроль</th><th>Состояние</th><th>Просмотрено</th><th>Ложных</th><th>Доля</th><th>Верхняя граница</th><th>Реальный поток</th><th>Готов</th></tr>
              </thead>
              <tbody>
                {s.controls.map((c) => (
                  <tr key={c.control}>
                    <td>{c.control}</td>
                    <td>{STATE_LABEL[c.state] ?? c.state}</td>
                    <td>{c.reject_safety.reviewed_rejects}</td>
                    <td>{c.reject_safety.confirmed_fp}</td>
                    <td>{pct(c.reject_safety.fp_rate)}</td>
                    <td>{pct(c.reject_safety.fp_upper_bound)}</td>
                    <td>{c.real_flow_sample ? "да" : "нет"}</td>
                    <td>{c.reject_safety.ready_for_canary ? "канарейка" : "нет"}{c.reject_safety.ready_for_pilot ? ", пилот" : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <section className="card">
            <h2>Действующие исключения и аварийные обходы</h2>
            <p>Исключений: <strong>{s.active_exceptions.length}</strong>. Узлов с локальным обходом: <strong>{s.emergency_bypass_nodes.length}</strong>.</p>
          </section>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
function IncidentsTab() {
  const incidents = useLoad(() => enforcementApi.incidents());
  return (
    <div>
      <Problem error={incidents.error} />
      <p className="muted">
        Критическое ложное срабатывание приостанавливает контроль и открывает инцидент. Контроль не включается снова, пока
        инцидент не пройдёт все этапы: сдерживание, причина, регрессионный случай, закрытие.
      </p>
      <table className="table">
        <thead>
          <tr><th>Контроль</th><th>Состояние</th><th>Название</th><th>Открыл</th><th>Причина</th><th>Регрессионный случай</th></tr>
        </thead>
        <tbody>
          {(incidents.data?.items ?? []).map((i: EnforcementIncident) => (
            <tr key={i.id}>
              <td>{i.control_type}</td>
              <td>{i.state}</td>
              <td>{i.title}</td>
              <td>{i.opened_by}</td>
              <td>{i.root_cause || "—"}</td>
              <td>{i.regression_case || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {incidents.data && incidents.data.items.length === 0 && <p className="muted">Инцидентов нет.</p>}
    </div>
  );
}
