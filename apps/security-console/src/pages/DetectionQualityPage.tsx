import { useCallback, useEffect, useState } from "react";
import {
  api,
  type CurrentUser,
  type DetectionGap,
  type DetectionQuality,
  type CanaryRollout,
  type DetectionRule,
  type RuleQuality,
  type ThreatScenarioView,
} from "../api/client";
import { SEVERITY_LABELS, formatDate } from "../types";

/**
 * Detection quality, rule lifecycle, known gaps and coverage (ТЗ 1.0.3 §35, §36, §37).
 *
 * The page is built around one rule: **a metric with no data behind it is shown as "—", never
 * as a number.** A dashboard reporting 0% false positives because nobody has classified
 * anything would be read as success, and it is the single most dangerous thing this product
 * could display. The same applies to coverage: it is computed from the live rule pack, so a
 * scenario whose rules were removed turns red here instead of staying green.
 */

const TABS = [
  { id: "quality", label: "Качество" },
  { id: "rules", label: "Правила" },
  { id: "health", label: "Качество правил" },
  { id: "gaps", label: "Известные пробелы" },
  { id: "coverage", label: "Карта покрытия" },
  { id: "shadow", label: "Теневые правила" },
  { id: "canary", label: "Канареечные выпуски" },
] as const;

type TabId = (typeof TABS)[number]["id"];

const RULE_STATUS_LABELS: Record<string, string> = {
  EXPERIMENTAL: "черновик",
  SHADOW: "теневое",
  ACTIVE: "активное",
  DEGRADED: "ухудшено",
  DISABLED: "отключено",
  DEPRECATED: "устаревшее",
};

const GAP_STATUS_LABELS: Record<string, string> = {
  OPEN: "открыт",
  ACCEPTED: "принят",
  IN_PROGRESS: "в работе",
  FIXED: "закрыт",
  WONT_FIX: "не будет исправлен",
};

/** "—" for an undefined metric. Never 0, never 100%. */
const RULE_HEALTH_LABELS: Record<string, string> = {
  HEALTHY: "в норме",
  NO_DATA: "нет данных",
  NOISY: "шумит",
  REGRESSED: "ухудшилось",
  LOW_COVERAGE: "не срабатывает",
  DEGRADED: "подавляется исключениями",
};

// Health decides the colour, never the rule's fate: a control that switches itself off can be
// switched off by an unlucky week.
const RULE_HEALTH_CLASS: Record<string, string> = {
  HEALTHY: "tag tag--ok",
  NOISY: "tag tag--critical",
  REGRESSED: "tag tag--high",
  DEGRADED: "tag tag--medium",
  LOW_COVERAGE: "tag",
  NO_DATA: "tag",
};

const CANARY_STATE_LABELS: Record<string, string> = {
  ACTIVE: "идёт",
  PROMOTED: "расширен на всех",
  ABORTED: "откачен",
};

function ratio(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `${(value * 100).toFixed(1)}%`;
}

export function DetectionQualityPage({ user }: { user: CurrentUser }) {
  const [tab, setTab] = useState<TabId>("quality");
  const [days, setDays] = useState(30);
  const [quality, setQuality] = useState<DetectionQuality | null>(null);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [gaps, setGaps] = useState<DetectionGap[]>([]);
  const [scenarios, setScenarios] = useState<ThreatScenarioView[]>([]);
  const [shadow, setShadow] = useState<Record<string, unknown>[]>([]);
  const [canaries, setCanaries] = useState<CanaryRollout[]>([]);
  const [ruleQuality, setRuleQuality] = useState<RuleQuality[]>([]);
  const [versions, setVersions] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const canManage = user.permissions.includes("detection:manage");

  const load = useCallback(() => {
    setError(null);
    const fail = (e: unknown) => setError(e instanceof Error ? e.message : "Ошибка загрузки");
    void api.detectionQuality(days).then(setQuality).catch(fail);
    void api.detectionRules().then(setRules).catch(fail);
    void api.detectionGaps().then(setGaps).catch(fail);
    void api.threatScenarios().then(setScenarios).catch(fail);
    void api.shadowRules(days).then(setShadow).catch(fail);
    void api.canaries(true).then(setCanaries).catch(fail);
    void api.ruleQuality(days).then(setRuleQuality).catch(fail);
    void api.detectionVersions().then(setVersions).catch(fail);
  }, [days]);

  useEffect(load, [load]);

  const sync = async () => {
    try {
      const result = await api.syncDetectionRegistry();
      setNotice(
        `Загружено из файлов: правил ${result.rules}, пробелов ${result.gaps}, сценариев ${result.scenarios}.`,
      );
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось синхронизировать");
    }
  };

  const decide = async (ruleId: string, state: "PROMOTED" | "ABORTED") => {
    // Aborting needs a reason: the next person has to know why a rule stopped deciding.
    const note =
      state === "ABORTED"
        ? window.prompt("Причина отката (обязательно):")?.trim()
        : window.prompt("Комментарий к расширению:")?.trim() || "";
    if (state === "ABORTED" && !note) return;
    try {
      await api.decideCanary(ruleId, { state, note: note ?? "" });
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось завершить выпуск");
    }
  };

  return (
    <div className="page">
      <div className="page__header">
        <h1>Качество детектирования</h1>
        <div className="filters">
          <label>
            Период
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
              <option value={7}>7 дней</option>
              <option value={30}>30 дней</option>
              <option value={90}>90 дней</option>
            </select>
          </label>
          {canManage && (
            <button type="button" className="button button--ghost" onClick={() => void sync()}>
              Синхронизировать из файлов
            </button>
          )}
        </div>
      </div>

      {error && <div className="error">{error}</div>}
      {notice && <div className="notice notice--info">{notice}</div>}

      <div className="tabs">
        {TABS.map((item) => (
          <button
            key={item.id}
            type="button"
            className={tab === item.id ? "tab tab--active" : "tab"}
            onClick={() => setTab(item.id)}
          >
            {item.label}
          </button>
        ))}
      </div>

      {tab === "quality" && quality && (
        <>
          <div className="tiles">
            <div className="tile">
              <div className="tile__label">Проанализировано</div>
              <div className="tile__value">{quality.total_analyzed}</div>
            </div>
            <div className="tile">
              <div className="tile__label">Размечено аналитиком</div>
              <div className="tile__value">{quality.classified}</div>
            </div>
            <div className="tile">
              <div className="tile__label">Точность</div>
              <div className="tile__value">{ratio(quality.precision)}</div>
            </div>
            <div className="tile">
              <div className="tile__label">Доля ложных</div>
              <div className="tile__value">{ratio(quality.false_positive_rate)}</div>
            </div>
            <div className={quality.reported_misses ? "tile tile--high" : "tile"}>
              <div className="tile__label">Сообщённые пропуски</div>
              <div className="tile__value">{quality.reported_misses}</div>
            </div>
            <div className={quality.unscannable ? "tile tile--medium" : "tile"}>
              <div className="tile__label">Не проверено полностью</div>
              <div className="tile__value">{quality.unscannable}</div>
            </div>
            <div className="tile tile--unknown">
              <div className="tile__label">Вердикт UNKNOWN</div>
              <div className="tile__value">{quality.unknown}</div>
            </div>
            <div className={quality.open_gaps ? "tile tile--medium" : "tile"}>
              <div className="tile__label">Открытых пробелов</div>
              <div className="tile__value">{quality.open_gaps}</div>
            </div>
            <div className="tile">
              <div className="tile__label">Канареечных выпусков</div>
              <div className="tile__value">{quality.active_canaries}</div>
            </div>
            <div className={quality.overdue_canaries ? "tile tile--high" : "tile"}>
              <div className="tile__label">Просрочено решение</div>
              <div className="tile__value">{quality.overdue_canaries}</div>
            </div>
          </div>

          {quality.classified === 0 && (
            <div className="notice notice--warning">
              Ни один инцидент за период не размечен аналитиком, поэтому точность и доля ложных
              срабатываний не определены и показаны как «—». Это не ноль: посчитать их не на
              чем.
            </div>
          )}

          <section className="card">
            <div className="card__header">
              <h2>Шумные правила</h2>
            </div>
            {quality.noisy_rules.length === 0 ? (
              <p className="muted">Правил с подтверждённой долей ложных выше 30% нет.</p>
            ) : (
              <table className="table table--compact">
                <thead>
                  <tr>
                    <th>Правило</th>
                    <th>Владелец</th>
                    <th>Срабатываний</th>
                    <th>Подтверждено</th>
                    <th>Ложных</th>
                    <th>Точность</th>
                  </tr>
                </thead>
                <tbody>
                  {quality.noisy_rules.map((rule) => (
                    <tr key={String(rule.rule_id)}>
                      <td>{String(rule.rule_id)}</td>
                      <td>{String(rule.owner || "—")}</td>
                      <td>{Number(rule.triggers)}</td>
                      <td>{Number(rule.confirmed_tp)}</td>
                      <td>{Number(rule.confirmed_fp)}</td>
                      <td>{ratio(rule.precision as number | null)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <div className="columns">
            <section className="card">
              <div className="card__header">
                <h2>Молчащие правила</h2>
              </div>
              <p className="muted small">
                Активные правила, не сработавшие ни разу за период. Это не обязательно дефект:
                правило может закрывать редкий сценарий. Но правило, молчащее месяцами, стоит
                либо проверить кейсом, либо перевести в теневой режим.
              </p>
              <ul className="inline-list">
                {quality.silent_rules.length === 0 ? (
                  <li className="muted">нет</li>
                ) : (
                  quality.silent_rules.map((id) => <li key={id}>{id}</li>)
                )}
              </ul>
            </section>

            <section className="card">
              <div className="card__header">
                <h2>Правила без владельца</h2>
              </div>
              <p className="muted small">
                Активное правило без владельца некому настраивать в тот день, когда оно начнёт
                шуметь. Критерий выхода ТЗ 1.0.3 §60 — этот список должен быть пуст.
              </p>
              {quality.unowned_active_rules.length === 0 ? (
                <p className="tag tag--ok">список пуст</p>
              ) : (
                <ul className="inline-list">
                  {quality.unowned_active_rules.map((id) => (
                    <li key={id} className="danger">
                      {id}
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>

          {versions && (
            <section className="card">
              <div className="card__header">
                <h2>Версии, которыми получены вердикты</h2>
              </div>
              <p className="muted small">
                Вердикт воспроизводим только вместе с версиями, которыми он получен (ТЗ 1.0.3
                §48).
              </p>
              <table className="table table--compact">
                <tbody>
                  <tr>
                    <th>Пакет правил</th>
                    <td className="hash">{String(versions.ruleset_version)}</td>
                  </tr>
                  <tr>
                    <th>Движок риска</th>
                    <td>{String(versions.risk_engine_version)}</td>
                  </tr>
                  <tr>
                    <th>Парсер</th>
                    <td>{String(versions.parser_version)}</td>
                  </tr>
                  <tr>
                    <th>Политика обогащения</th>
                    <td>{String(versions.ti_policy_version)}</td>
                  </tr>
                  <tr>
                    <th>Правил: всего / активных / теневых</th>
                    <td>
                      {String(versions.rule_count)} / {String(versions.active_rules)} /{" "}
                      {String(versions.shadow_rules)}
                    </td>
                  </tr>
                </tbody>
              </table>
            </section>
          )}
        </>
      )}

      {tab === "rules" && (
        <section className="card">
          <div className="card__header">
            <h2>Пакет правил ({rules.length})</h2>
          </div>
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Правило</th>
                <th>Название</th>
                <th>Статус</th>
                <th>Владелец</th>
                <th>Вес</th>
                <th>Срабатываний</th>
                <th>Точность</th>
                <th>Условие</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.rule_id}>
                  <td>
                    {rule.rule_id}
                    <div className="small muted">v{rule.version}</div>
                  </td>
                  <td>{rule.title}</td>
                  <td>
                    <span className={rule.status === "ACTIVE" ? "tag tag--ok" : "tag"}>
                      {RULE_STATUS_LABELS[rule.status] ?? rule.status}
                    </span>
                    {!rule.scores && <div className="small muted">не влияет на вердикт</div>}
                  </td>
                  <td>{rule.owner || <span className="danger">не указан</span>}</td>
                  <td>{rule.weight}</td>
                  <td>{rule.trigger_count}</td>
                  <td>
                    {ratio(rule.precision)}
                    {rule.precision === null && (
                      <div className="small muted">нет решений аналитика</div>
                    )}
                  </td>
                  <td className="small">
                    <code>{rule.condition ?? "—"}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {tab === "health" && (
        <section className="card">
          <div className="card__header">
            <h2>Качество правил за период</h2>
            {canManage && (
              <button
                type="button"
                className="button button--ghost"
                onClick={() => {
                  void api
                    .snapshotRuleQuality(days)
                    .then((result) =>
                      setNotice(`Сохранён срез по ${result.snapshots} правилам.`),
                    )
                    .catch((e) =>
                      setError(e instanceof Error ? e.message : "Не удалось сохранить срез"),
                    );
                }}
              >
                Сохранить срез
              </button>
            )}
          </div>
          <p className="muted small">
            Точность показывается как «—», пока решений аналитика меньше пяти: по двум решениям
            это не измерение, а случай. Состояние здоровья — ярлык, оно никогда не отключает
            правило: контроль, выключающий себя при странных данных, может быть выключен
            неудачной неделей.
          </p>
          {ruleQuality.length === 0 ? (
            <p className="muted">За период правила не срабатывали.</p>
          ) : (
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Правило</th>
                  <th>Срабатываний</th>
                  <th>Разобрано</th>
                  <th>Подтверждено</th>
                  <th>Ложных</th>
                  <th>Точность</th>
                  <th>Писем</th>
                  <th>Инцидентов</th>
                  <th>Состояние</th>
                </tr>
              </thead>
              <tbody>
                {ruleQuality.map((row) => (
                  <tr key={row.rule_id}>
                    <td>
                      {row.rule_id}
                      <div className="small muted">v{row.rule_version}</div>
                    </td>
                    <td>{row.trigger_count}</td>
                    <td>{row.analyst_reviewed}</td>
                    <td>{row.true_positive}</td>
                    <td>{row.false_positive}</td>
                    <td>{ratio(row.precision)}</td>
                    <td>{row.affected_messages}</td>
                    <td>{row.affected_incidents}</td>
                    <td>
                      <span className={RULE_HEALTH_CLASS[row.health] ?? "tag"}>
                        {RULE_HEALTH_LABELS[row.health] ?? row.health}
                      </span>
                      {row.health_reasons.length > 0 && (
                        <div className="small muted">{row.health_reasons[0]}</div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {tab === "gaps" && (
        <section className="card">
          <div className="card__header">
            <h2>Известные пробелы детектирования</h2>
          </div>
          <p className="muted small">
            Пробел, которого нет в этом списке, ничем не отличается от пробела, о котором никто
            не знает. Поэтому список публикуется, а не скрывается (ТЗ 1.0.3 §27).
          </p>
          {gaps.length === 0 ? (
            <p className="muted">
              Реестр не загружен. Выполните синхронизацию из файлов.
            </p>
          ) : (
            gaps.map((gap) => (
              <article key={gap.gap_id} className="card">
                <div className="card__header">
                  <h3>
                    {gap.gap_id} — {gap.description}
                  </h3>
                  <span className="tag">{GAP_STATUS_LABELS[gap.status] ?? gap.status}</span>
                </div>
                <dl className="evidence">
                  <dt>Серьёзность</dt>
                  <dd>{SEVERITY_LABELS[gap.severity] ?? gap.severity}</dd>
                  <dt>Причина</dt>
                  <dd>{gap.root_cause}</dd>
                  <dt>Компенсирующая мера</dt>
                  <dd>{gap.mitigation}</dd>
                  <dt>Как планируется закрыть</dt>
                  <dd>{gap.planned_fix}</dd>
                  <dt>Владелец / релиз</dt>
                  <dd>
                    {gap.owner} / {gap.target_release}
                  </dd>
                  <dt>Сообщённых пропусков по этому пробелу</dt>
                  <dd>{gap.reported_misses}</dd>
                </dl>
              </article>
            ))
          )}
        </section>
      )}

      {tab === "coverage" && (
        <section className="card">
          <div className="card__header">
            <h2>Карта покрытия сценариев</h2>
          </div>
          <p className="muted small">
            Покрытие вычисляется из действующего пакета правил при каждом открытии страницы.
            Сценарий, у которого правила удалили, становится непокрытым здесь, а не остаётся
            зелёным (ТЗ 1.0.3 §37).
          </p>
          {scenarios.length === 0 ? (
            <p className="muted">Каталог не загружен. Выполните синхронизацию из файлов.</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Сценарий</th>
                  <th>Серьёзность</th>
                  <th>Покрытие</th>
                  <th>Активных правил</th>
                  <th>Теневых</th>
                  <th>Кейсов</th>
                  <th>Плейбук</th>
                </tr>
              </thead>
              <tbody>
                {scenarios.map((scenario) => (
                  <tr key={scenario.scenario_id}>
                    <td>
                      {scenario.title}
                      <div className="small muted">{scenario.scenario_id}</div>
                    </td>
                    <td>{SEVERITY_LABELS[scenario.severity] ?? scenario.severity}</td>
                    <td>
                      {scenario.covered ? (
                        <span className="tag tag--ok">покрыт</span>
                      ) : (
                        <span className="tag tag--critical">не покрыт</span>
                      )}
                    </td>
                    <td>{scenario.active_rules}</td>
                    <td>{scenario.shadow_rules}</td>
                    <td>{scenario.fixtures.length}</td>
                    <td className="small">{scenario.playbook}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {tab === "canary" && (
        <section className="card">
          <div className="card__header">
            <h2>Канареечные выпуски</h2>
          </div>
          <p className="muted small">
            Правило, выпущенное на часть организации. Вне области оно не выключено, а удержано:
            продолжает срабатывать и записываться, но ничего не решает — поэтому остальная часть
            организации служит контрольной группой, измеренной тем же кодом на той же почте
            (ТЗ 1.0.3 §52).
          </p>
          <p className="muted small">
            Срок — это не срабатывающий таймер. По его истечении область сохраняется: снять её
            автоматически означало бы выпустить непроверенное правило на всех, а снять правило —
            молча отключить детектирование. И то и другое — решения, поэтому срок лишь делает
            незавершённый выпуск заметным.
          </p>
          {canaries.length === 0 ? (
            <p className="muted">Канареечных выпусков нет.</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Правило</th>
                  <th>Область</th>
                  <th>Состояние</th>
                  <th>Решить до</th>
                  <th>В области</th>
                  <th>Вне области</th>
                  <th>Точность в области</th>
                  <th>Готово к расширению</th>
                  {canManage && <th />}
                </tr>
              </thead>
              <tbody>
                {canaries.map((rollout) => (
                  <tr key={`${rollout.rule_id}-${rollout.review_at}`}>
                    <td>{rollout.rule_id}</td>
                    <td className="small">
                      {rollout.scope === "PERCENT"
                        ? `${rollout.percent}% ящиков`
                        : rollout.scope_values.join(", ") || "—"}
                    </td>
                    <td>
                      <span className={rollout.state === "ACTIVE" ? "tag" : "tag tag--ok"}>
                        {CANARY_STATE_LABELS[rollout.state] ?? rollout.state}
                      </span>
                    </td>
                    <td className={rollout.overdue ? "danger" : undefined}>
                      {formatDate(rollout.review_at)}
                      {rollout.overdue && <div className="small">срок прошёл</div>}
                    </td>
                    <td>
                      {rollout.inside_triggers}
                      <div className="small muted">
                        подтверждено {rollout.inside_confirmed} · ложных{" "}
                        {rollout.inside_false_positives}
                      </div>
                    </td>
                    <td>
                      {rollout.outside_triggers}
                      <div className="small muted">удержано</div>
                    </td>
                    <td>{ratio(rollout.inside_precision)}</td>
                    <td>
                      {rollout.ready_to_promote ? (
                        <span className="tag tag--ok">да</span>
                      ) : (
                        <span className="muted small">данных недостаточно</span>
                      )}
                    </td>
                    {canManage && (
                      <td>
                        {rollout.state === "ACTIVE" && (
                          <div className="actions">
                            <button
                              type="button"
                              className="button button--tiny"
                              onClick={() => void decide(rollout.rule_id, "PROMOTED")}
                            >
                              Расширить
                            </button>
                            <button
                              type="button"
                              className="button button--tiny button--danger"
                              onClick={() => void decide(rollout.rule_id, "ABORTED")}
                            >
                              Откатить
                            </button>
                          </div>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {tab === "shadow" && (
        <section className="card">
          <div className="card__header">
            <h2>Теневые правила на реальной почте</h2>
          </div>
          <p className="muted small">
            Теневое правило срабатывает и измеряется, но ничего не меняет в вердикте. Эти
            измерения — единственное основание перевести его в активное (ТЗ 1.0.3 §11).
          </p>
          {shadow.length === 0 ? (
            <p className="muted">За период теневые правила не срабатывали.</p>
          ) : (
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Правило</th>
                  <th>Название</th>
                  <th>Владелец</th>
                  <th>Статус</th>
                  <th>Срабатываний</th>
                  <th>Последнее</th>
                  <th>Дало бы баллов</th>
                </tr>
              </thead>
              <tbody>
                {shadow.map((row) => (
                  <tr key={String(row.rule_id)}>
                    <td>{String(row.rule_id)}</td>
                    <td>{String(row.title || "—")}</td>
                    <td>{String(row.owner || "—")}</td>
                    <td>{RULE_STATUS_LABELS[String(row.status)] ?? String(row.status)}</td>
                    <td>{Number(row.matches)}</td>
                    <td>{formatDate(row.last_match_at as string | null)}</td>
                    <td>{row.would_have_scored === null ? "—" : String(row.would_have_scored)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}
    </div>
  );
}
