import { useCallback, useEffect, useState } from "react";
import {
  api,
  type CurrentUser,
  type GatewayList,
  type MailGateway,
  type TrustedHop,
} from "../api/client";
import { formatDate } from "../types";

/**
 * Settings → Mail Gateways (ТЗ 1.0.2 §25).
 *
 * The page exists to make one thing obvious to an administrator: registering a gateway is not
 * the same as trusting it. A gateway with no trusted hop has its headers parsed and displayed,
 * and they are never used — because nothing proves the message went through it (ТЗ 1.0.1 §4.3).
 * The warning below is not decoration; it is the difference between a configured integration
 * and a working one.
 */

const STATE_LABELS: Record<string, string> = {
  NOT_PRESENT: "Внешний шлюз не настроен",
  HEALTHY: "Работает",
  DEGRADED: "Работает с замечаниями",
  UNAVAILABLE: "Недоступен",
};

const CAPABILITY_LABELS: Record<string, string> = {
  HEADER_VERDICT: "вердикт из заголовков",
  SYSLOG_EVENTS: "события syslog",
  MESSAGE_TRACE: "трассировка доставки",
  API_VERDICT: "вердикт через API",
  QUARANTINE_READ: "чтение карантина",
  QUARANTINE_WRITE: "запись в карантин",
  RELEASE: "выпуск из карантина",
  SENDER_BLOCK: "блокировка отправителя",
  IOC_BLOCK: "блокировка индикаторов",
  SEARCH: "поиск",
  CAMPAIGN_DATA: "данные о кампаниях",
  SANDBOX_RESULT: "результат песочницы",
  AV_RESULT: "антивирус",
  SPAM_RESULT: "антиспам",
  PHISHING_RESULT: "антифишинг",
};

const HOP_TYPE_LABELS: Record<string, string> = {
  gateway: "шлюз",
  exchange_edge: "пограничный сервер",
  exchange_mailbox: "почтовый сервер",
  relay: "релей",
};

interface Props {
  user: CurrentUser;
}

function HopList({
  gateway,
  canEdit,
  onChange,
}: {
  gateway: MailGateway;
  canEdit: boolean;
  onChange: () => void;
}) {
  const [hostname, setHostname] = useState("");
  const [networks, setNetworks] = useState("");
  const [authserv, setAuthserv] = useState("");
  const [error, setError] = useState<string | null>(null);

  const add = useCallback(async () => {
    setError(null);
    try {
      await api.addTrustedHop(gateway.gateway_id, {
        hostname: hostname.trim(),
        ip_networks: networks
          .split(",")
          .map((n) => n.trim())
          .filter(Boolean),
        authserv_ids: authserv
          .split(",")
          .map((a) => a.trim())
          .filter(Boolean),
      });
      setHostname("");
      setNetworks("");
      setAuthserv("");
      onChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось добавить узел");
    }
  }, [gateway.gateway_id, hostname, networks, authserv, onChange]);

  const remove = useCallback(
    async (hop: TrustedHop) => {
      await api.deleteTrustedHop(hop.hop_id);
      onChange();
    },
    [onChange],
  );

  return (
    <div className="hops">
      <h4>Доверенные узлы</h4>
      {gateway.trusted_hops.length === 0 ? (
        <p className="warning">
          Узлы не заданы. Заголовки этого шлюза будут показываться аналитику, но не будут
          учитываться в оценке: подтвердить, что письмо действительно проходило через шлюз,
          нечем. Укажите имя узла или его сети.
        </p>
      ) : (
        <table className="table table--compact">
          <thead>
            <tr>
              <th>Имя узла</th>
              <th>Сети</th>
              <th>authserv-id</th>
              <th>Позиция</th>
              {canEdit && <th />}
            </tr>
          </thead>
          <tbody>
            {gateway.trusted_hops.map((hop) => (
              <tr key={hop.hop_id}>
                <td>{hop.hostname || "—"}</td>
                <td>{hop.ip_networks.join(", ") || "—"}</td>
                <td>{hop.authserv_ids.join(", ") || "—"}</td>
                <td>{hop.position_in_chain ?? "любая"}</td>
                {canEdit && (
                  <td>
                    <button
                      type="button"
                      className="button button--tiny button--ghost"
                      onClick={() => void remove(hop)}
                    >
                      Удалить
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {canEdit && (
        <div className="form-row">
          <input
            type="text"
            placeholder="ksmg-01.corp.example"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
          />
          <input
            type="text"
            placeholder="10.20.0.0/24, 10.20.1.5"
            value={networks}
            onChange={(e) => setNetworks(e.target.value)}
          />
          <input
            type="text"
            placeholder="authserv-id (необязательно)"
            value={authserv}
            onChange={(e) => setAuthserv(e.target.value)}
          />
          <button type="button" className="button button--tiny" onClick={() => void add()}>
            Добавить узел
          </button>
        </div>
      )}
      {error && <p className="error">{error}</p>}
      <p className="muted small">
        authserv-id перечисляет серверы, чьи заголовки Authentication-Results разрешено читать для
        писем, прошедших через этот узел. Заголовок от любого другого сервера игнорируется.
      </p>
    </div>
  );
}

export function GatewaysPage({ user }: Props) {
  const [data, setData] = useState<GatewayList | null>(null);
  const [deadLetters, setDeadLetters] = useState<Record<string, unknown>[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [providerId, setProviderId] = useState("");
  const [providerType, setProviderType] = useState("ksmg");
  const [displayName, setDisplayName] = useState("");
  const [infraHost, setInfraHost] = useState("");
  const [infraType, setInfraType] = useState("exchange_mailbox");
  const [infraAuth, setInfraAuth] = useState("");

  const canEdit = user.permissions.includes("manage:policies");

  const load = useCallback(async () => {
    try {
      setData(await api.gateways());
      if (canEdit) {
        setDeadLetters(await api.gatewayDeadLetters().catch(() => []));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось загрузить список шлюзов");
    }
  }, [canEdit]);

  useEffect(() => {
    void load();
  }, [load]);

  const create = useCallback(async () => {
    setError(null);
    try {
      await api.createGateway({
        provider_id: providerId.trim(),
        provider_type: providerType,
        display_name: displayName.trim(),
      });
      setProviderId("");
      setDisplayName("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось добавить шлюз");
    }
  }, [providerId, providerType, displayName, load]);

  const toggle = useCallback(
    async (gateway: MailGateway) => {
      await api.updateGateway(gateway.gateway_id, {
        provider_id: gateway.provider_id,
        provider_type: gateway.provider_type,
        display_name: gateway.display_name,
        vendor: gateway.vendor,
        direction: gateway.direction,
        enabled: !gateway.enabled,
        settings: gateway.settings,
      });
      await load();
    },
    [load],
  );

  if (!data) {
    return <div className="page">{error ? <p className="error">{error}</p> : "Загрузка…"}</div>;
  }

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Почтовые шлюзы</h1>
          <p className="muted">
            Состояние: <strong>{STATE_LABELS[data.state] ?? data.state}</strong>
          </p>
        </div>
        {canEdit && (
          <button type="button" className="button" onClick={() => void api.probeGateways().then(load)}>
            Проверить возможности
          </button>
        )}
      </div>

      {data.state === "NOT_PRESENT" && (
        <section className="card">
          <p>
            Внешний почтовый шлюз не настроен. Это рабочая конфигурация: платформа анализирует
            письма самостоятельно и не зависит от наличия SEG. Шлюз можно добавить позже — он
            станет дополнительным источником сигналов.
          </p>
        </section>
      )}

      {data.gateways.map((gateway) => (
        <section className="card" key={gateway.gateway_id}>
          <div className="card__header">
            <h2>
              {gateway.display_name}{" "}
              <span className="muted">
                ({gateway.provider_type}, {gateway.direction})
              </span>
            </h2>
            <div>
              {gateway.health && (
                <span className={`tag tag--${gateway.health.status === "ok" ? "ok" : "flag"}`}>
                  {gateway.health.detail || gateway.health.status}
                </span>
              )}
              {canEdit && (
                <button
                  type="button"
                  className="button button--tiny button--ghost"
                  onClick={() => void toggle(gateway)}
                >
                  {gateway.enabled ? "Отключить" : "Включить"}
                </button>
              )}
            </div>
          </div>

          <p>
            <span className="muted">Возможности: </span>
            {gateway.capabilities.length === 0
              ? "не проверялись — нажмите «Проверить возможности»"
              : gateway.capabilities
                  .map((c) => CAPABILITY_LABELS[c] ?? c)
                  .join(", ")}
          </p>
          <p className="muted small">
            Последнее событие: {gateway.last_event_at ? formatDate(gateway.last_event_at) : "—"}
            {gateway.last_error && ` · последняя ошибка: ${gateway.last_error}`}
          </p>

          <HopList gateway={gateway} canEdit={canEdit} onChange={load} />
        </section>
      ))}

      <section className="card">
        <h2>Узлы почтовой инфраструктуры</h2>
        <p className="muted small">
          Серверы Exchange не являются шлюзами, но это доверенные узлы: именно они пишут
          Authentication-Results. Описать шлюз и забыть почтовый сервер — самая частая ошибка
          настройки: тогда каждое обычное письмо получает результаты проверки от объявленного,
          но не подтверждённого сервера.
        </p>
        {data.infrastructure_hops.length === 0 ? (
          <p className="warning">
            Узлы не описаны. Заголовки Authentication-Results читаются без проверки источника.
          </p>
        ) : (
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Имя узла</th>
                <th>Тип</th>
                <th>Сети</th>
                <th>authserv-id</th>
                {canEdit && <th />}
              </tr>
            </thead>
            <tbody>
              {data.infrastructure_hops.map((hop) => (
                <tr key={hop.hop_id}>
                  <td>{hop.hostname || "—"}</td>
                  <td>{HOP_TYPE_LABELS[hop.hop_type] ?? hop.hop_type}</td>
                  <td>{hop.ip_networks.join(", ") || "—"}</td>
                  <td>{hop.authserv_ids.join(", ") || "—"}</td>
                  {canEdit && (
                    <td>
                      <button
                        type="button"
                        className="button button--tiny button--ghost"
                        onClick={() => void api.deleteTrustedHop(hop.hop_id).then(load)}
                      >
                        Удалить
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {canEdit && (
          <div className="form-row">
            <input
              type="text"
              placeholder="mx.corp.example"
              value={infraHost}
              onChange={(e) => setInfraHost(e.target.value)}
            />
            <select value={infraType} onChange={(e) => setInfraType(e.target.value)}>
              <option value="exchange_mailbox">почтовый сервер</option>
              <option value="exchange_edge">пограничный сервер</option>
              <option value="relay">релей</option>
            </select>
            <input
              type="text"
              placeholder="authserv-id, например mx.corp.example"
              value={infraAuth}
              onChange={(e) => setInfraAuth(e.target.value)}
            />
            <button
              type="button"
              className="button button--tiny"
              onClick={() =>
                void api
                  .addInfrastructureHop({
                    hop_type: infraType,
                    hostname: infraHost.trim(),
                    authserv_ids: infraAuth
                      .split(",")
                      .map((a) => a.trim())
                      .filter(Boolean),
                  })
                  .then(() => {
                    setInfraHost("");
                    setInfraAuth("");
                    return load();
                  })
                  .catch((e) => setError(e instanceof Error ? e.message : "Не удалось добавить"))
              }
            >
              Добавить узел
            </button>
          </div>
        )}
      </section>

      {canEdit && (
        <section className="card">
          <h2>Добавить шлюз</h2>
          <div className="form-row">
            <input
              type="text"
              placeholder="идентификатор, например ksmg"
              value={providerId}
              onChange={(e) => setProviderId(e.target.value)}
            />
            <select value={providerType} onChange={(e) => setProviderType(e.target.value)}>
              {data.supported_provider_types.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
            <input
              type="text"
              placeholder="отображаемое имя"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
            <button type="button" className="button" onClick={() => void create()}>
              Добавить
            </button>
          </div>
          {error && <p className="error">{error}</p>}
          <p className="muted small">
            Секреты здесь не задаются. Доступ к API шлюза настраивается ссылкой на хранилище
            секретов, а не значением ключа.
          </p>
        </section>
      )}

      {data.available_skeletons.length > 0 && (
        <section className="card">
          <h2>Поддержка других шлюзов</h2>
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Продукт</th>
                <th>Работает сейчас</th>
                <th>Планируется через API</th>
                <th>Что нужно</th>
              </tr>
            </thead>
            <tbody>
              {data.available_skeletons.map((item) => (
                <tr key={item.provider_type}>
                  <td>{item.display_name}</td>
                  <td>{item.implemented.map((c) => CAPABILITY_LABELS[c] ?? c).join(", ")}</td>
                  <td className="muted">
                    {item.planned.map((c) => CAPABILITY_LABELS[c] ?? c).join(", ")}
                  </td>
                  <td className="muted small">{item.prerequisites.join("; ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small">
            Разбор заголовков этих продуктов реализован и работает. Интеграция через их API
            появится после получения реальной среды — заявлять работающей непроверенную
            интеграцию нельзя: «шлюз молчит» и «адаптер ничего не вернул» выглядят одинаково.
          </p>
        </section>
      )}

      {canEdit && deadLetters.length > 0 && (
        <section className="card">
          <h2>Отклонённые события</h2>
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Время</th>
                <th>Источник</th>
                <th>Причина</th>
                <th>Строка</th>
              </tr>
            </thead>
            <tbody>
              {deadLetters.map((row, index) => (
                <tr key={`${String(row.received_at)}-${index}`}>
                  <td>{formatDate(String(row.received_at))}</td>
                  <td>{String(row.source_ip)}</td>
                  <td>{String(row.reason)}</td>
                  <td>
                    <code className="small">{String(row.raw).slice(0, 120)}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small">
            События, которые платформа не приняла: неразрешённый источник, повтор, устаревшая
            отметка времени или неизвестный формат. Молча отбрасывать их нельзя — неизвестный
            формат означает пробел в интеграции, а не отсутствие событий.
          </p>
        </section>
      )}
    </div>
  );
}
