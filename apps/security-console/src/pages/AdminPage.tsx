import { type FormEvent, useCallback, useEffect, useState } from "react";
import { api, type CurrentUser } from "../api/client";
import { formatDate } from "../types";

type Tab = "providers" | "identities" | "exceptions" | "rules" | "audit";

interface ExceptionRow {
  exception_id: string;
  exception_type: string;
  value: string;
  rule_id: string | null;
  owner_email: string;
  reason: string;
  expires_at: string | null;
  revoked_at: string | null;
  hit_count: number;
  created_at: string;
  active: boolean;
}

const EXCEPTION_TYPES: Record<string, string> = {
  trusted_sender: "Доверенный отправитель",
  trusted_domain: "Доверенный домен",
  trusted_sender_domain_pair: "Пара отправитель+домен",
  approved_delegated_service: "Разрешённый делегированный сервис",
  approved_marketing_platform: "Разрешённая рассылочная платформа",
  temporary: "Временное исключение",
  rule_suppression: "Подавление правила",
};

function ExceptionsTab({ canManage }: { canManage: boolean }) {
  const [items, setItems] = useState<ExceptionRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    exception_type: "trusted_sender",
    value: "",
    rule_id: "",
    reason: "",
    expires_at: "",
  });

  const load = useCallback(async () => {
    try {
      setItems((await api.exceptions()) as unknown as ExceptionRow[]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Ошибка загрузки");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function create(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await api.createException({
        exception_type: form.exception_type,
        value: form.value,
        rule_id: form.rule_id || null,
        reason: form.reason,
        expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null,
      });
      setForm({ ...form, value: "", reason: "", expires_at: "" });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось создать исключение");
    }
  }

  return (
    <>
      <p className="notice notice--info">
        У каждого исключения есть владелец, причина и срок действия. Создание и отзыв
        фиксируются в журнале аудита.
      </p>
      {canManage && (
        <form className="card filters" onSubmit={create}>
          <select
            value={form.exception_type}
            onChange={(e) => setForm({ ...form, exception_type: e.target.value })}
          >
            {Object.entries(EXCEPTION_TYPES).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <input
            placeholder="Значение (адрес или домен)"
            value={form.value}
            onChange={(e) => setForm({ ...form, value: e.target.value })}
            required
          />
          <input
            placeholder="ID правила (необязательно)"
            value={form.rule_id}
            onChange={(e) => setForm({ ...form, rule_id: e.target.value })}
          />
          <input
            placeholder="Причина"
            value={form.reason}
            onChange={(e) => setForm({ ...form, reason: e.target.value })}
            required
            minLength={5}
          />
          <input
            type="datetime-local"
            value={form.expires_at}
            onChange={(e) => setForm({ ...form, expires_at: e.target.value })}
          />
          <button type="submit" className="button button--primary">
            Создать
          </button>
        </form>
      )}
      {error && <div className="error">{error}</div>}
      <table className="table">
        <thead>
          <tr>
            <th>Тип</th>
            <th>Значение</th>
            <th>Правило</th>
            <th>Владелец</th>
            <th>Причина</th>
            <th>Действует до</th>
            <th>Срабатываний</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.exception_id} className={item.active ? "" : "row--inactive"}>
              <td>{EXCEPTION_TYPES[item.exception_type] ?? item.exception_type}</td>
              <td>
                <code>{item.value}</code>
              </td>
              <td>{item.rule_id ?? "—"}</td>
              <td>{item.owner_email}</td>
              <td>{item.reason}</td>
              <td>{item.expires_at ? formatDate(item.expires_at) : "бессрочно"}</td>
              <td>{item.hit_count}</td>
              <td>
                {canManage && item.active && (
                  <button
                    type="button"
                    className="button button--tiny"
                    onClick={() => void api.revokeException(item.exception_id).then(load)}
                  >
                    Отозвать
                  </button>
                )}
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={8} className="muted">
                Исключений нет
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}

function ProvidersTab() {
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  useEffect(() => {
    void api
      .providers()
      .then(setItems)
      .catch(() => setItems([]));
  }, []);
  return (
    <>
      <p className="notice notice--info">
        Ключи API задаются только через хранилище секретов на сервере и никогда не передаются
        в интерфейс.
      </p>
      <table className="table">
        <thead>
          <tr>
            <th>Провайдер</th>
            <th>Тип</th>
            <th>Состояние</th>
            <th>Режим</th>
            <th>Подробности</th>
            <th>Квота</th>
          </tr>
        </thead>
        <tbody>
          {items.map((provider) => {
            const quota = provider.quota as Record<string, number> | null;
            return (
              <tr key={String(provider.provider_id)}>
                <td>{String(provider.provider_id)}</td>
                <td>{String(provider.kind)}</td>
                <td>
                  <span className={`dot dot--${String(provider.status)}`} /> {String(provider.status)}
                </td>
                <td>{provider.mode ? String(provider.mode) : "—"}</td>
                <td className="muted">{provider.detail ? String(provider.detail) : "—"}</td>
                <td>
                  {quota
                    ? `${quota.used_day ?? 0} / ${quota.per_day_limit ?? "∞"} за сутки`
                    : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}

function RulesTab() {
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  useEffect(() => {
    void api
      .rules()
      .then(setItems)
      .catch(() => setItems([]));
  }, []);
  return (
    <table className="table table--compact">
      <thead>
        <tr>
          <th>ID</th>
          <th>Версия</th>
          <th>Название</th>
          <th>Категория</th>
          <th>Важность</th>
          <th>Уверенность</th>
          <th>Вес</th>
        </tr>
      </thead>
      <tbody>
        {items.map((rule) => (
          <tr key={String(rule.id)}>
            <td>
              <code>{String(rule.id)}</code>
              {rule.hard === true && <span className="tag tag--hard">hard</span>}
            </td>
            <td>{String(rule.version)}</td>
            <td>{String(rule.name)}</td>
            <td>{String(rule.category)}</td>
            <td>
              <span className={`tag tag--${String(rule.severity)}`}>{String(rule.severity)}</span>
            </td>
            <td>{String(rule.confidence)}</td>
            <td>{String(rule.weight)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function IdentitiesTab() {
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  useEffect(() => {
    void api
      .protectedIdentities()
      .then(setItems)
      .catch(() => setItems([]));
  }, []);
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Имя</th>
          <th>Адрес</th>
          <th>Категории</th>
          <th>Подразделение</th>
          <th>Разрешённые делегаты</th>
          <th>Активна</th>
        </tr>
      </thead>
      <tbody>
        {items.map((identity) => (
          <tr key={String(identity.identity_id)}>
            <td>{String(identity.display_name)}</td>
            <td>
              <code>{String(identity.email)}</code>
            </td>
            <td>
              {((identity.categories as string[]) ?? []).map((category) => (
                <span key={category} className="tag">
                  {category}
                </span>
              ))}
            </td>
            <td>{String(identity.department ?? "")}</td>
            <td className="muted">{((identity.approved_delegates as string[]) ?? []).join(", ")}</td>
            <td>{identity.enabled ? "да" : "нет"}</td>
          </tr>
        ))}
        {items.length === 0 && (
          <tr>
            <td colSpan={6} className="muted">
              Защищаемые идентичности не настроены
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}

function AuditTab() {
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  const [filter, setFilter] = useState("");
  useEffect(() => {
    void api
      .audit({ action: filter || undefined, limit: 200 })
      .then((data) => setItems(data.items))
      .catch(() => setItems([]));
  }, [filter]);
  return (
    <>
      <input
        placeholder="Фильтр по действию, например remediation.executed"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <table className="table table--compact">
        <thead>
          <tr>
            <th>Время</th>
            <th>Действие</th>
            <th>Пользователь</th>
            <th>Объект</th>
            <th>Результат</th>
            <th>Детали</th>
          </tr>
        </thead>
        <tbody>
          {items.map((event) => (
            <tr key={String(event.event_id)}>
              <td>{formatDate(String(event.created_at))}</td>
              <td>
                <code>{String(event.action)}</code>
              </td>
              <td>
                {String(event.actor_email)}
                <div className="muted">{String(event.actor_role)}</div>
              </td>
              <td className="muted">
                {String(event.object_type)}:{String(event.object_id).slice(0, 12)}
              </td>
              <td>{String(event.outcome)}</td>
              <td>
                <pre className="evidence">{JSON.stringify(event.detail, null, 1)}</pre>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export function AdminPage({ user }: { user: CurrentUser }) {
  const [tab, setTab] = useState<Tab>("providers");
  const canManagePolicies = user.permissions.includes("manage:policies");
  const canCreateException = user.permissions.includes("create:exception");

  const tabs: { id: Tab; label: string; visible: boolean }[] = [
    { id: "providers", label: "Провайдеры", visible: user.permissions.includes("manage:providers") },
    {
      id: "identities",
      label: "Защищаемые идентичности",
      visible: user.permissions.includes("manage:protected_identities"),
    },
    { id: "exceptions", label: "Исключения", visible: canCreateException },
    { id: "rules", label: "Правила", visible: canManagePolicies },
    { id: "audit", label: "Аудит", visible: user.permissions.includes("view:audit") },
  ];
  const visibleTabs = tabs.filter((item) => item.visible);

  return (
    <div className="page">
      <h1>Администрирование</h1>
      <nav className="tabs">
        {visibleTabs.map((item) => (
          <button
            key={item.id}
            type="button"
            className={tab === item.id ? "tab tab--active" : "tab"}
            onClick={() => setTab(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>
      <section className="card">
        {tab === "providers" && <ProvidersTab />}
        {tab === "identities" && <IdentitiesTab />}
        {tab === "exceptions" && <ExceptionsTab canManage={canCreateException} />}
        {tab === "rules" && <RulesTab />}
        {tab === "audit" && <AuditTab />}
      </section>
    </div>
  );
}
