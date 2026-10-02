import { useState } from "react";
import { api, type SimulationResult } from "../api/client";
import { RISK_LABELS } from "../types";

/**
 * Rule simulator (ТЗ 1.0.3B §9).
 *
 * Asking what the rules would say must never change what they said, so this page creates no
 * incident, sends no notification, proposes no remediation and makes no external lookup. The
 * verdict shown is always computed from the whole rule pack even when the view is narrowed to
 * one rule: a rule's effect depends on what else fired, and a narrowed computation would answer
 * a different question from the one the analyst asked.
 */
export function SimulatorPage() {
  const [messageId, setMessageId] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    if (!messageId.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setResult(
        await api.simulateRules({
          message_id: messageId.trim(),
          rule_id: ruleId.trim() || undefined,
        }),
      );
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : "Не удалось выполнить симуляцию");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <h1>Симулятор правил</h1>
      <p className="muted small">
        Прогон сохранённого письма через действующий пакет правил. Симуляция ничего не меняет:
        не создаёт инцидент, не отправляет уведомления, не предлагает реагирование и не
        обращается к внешним источникам. Вопрос «что сказали бы правила» не должен менять то,
        что они сказали.
      </p>

      <section className="card">
        <div className="form-row">
          <label>
            Идентификатор письма
            <input
              type="text"
              value={messageId}
              placeholder="message_id из карточки расследования"
              onChange={(e) => setMessageId(e.target.value)}
            />
          </label>
          <label>
            Правило (необязательно)
            <input
              type="text"
              value={ruleId}
              placeholder="например BEC-014"
              onChange={(e) => setRuleId(e.target.value)}
            />
          </label>
          <button
            type="button"
            className="button button--primary"
            disabled={busy || !messageId.trim()}
            onClick={() => void run()}
          >
            Выполнить
          </button>
        </div>
        <p className="muted small">
          Если указано правило, в списке сигналов остаётся только оно, но вердикт по-прежнему
          считается по всему пакету: эффект правила зависит от того, что сработало рядом.
        </p>
      </section>

      {error && <div className="error">{error}</div>}

      {result && (
        <>
          <section className="card">
            <div className="card__header">
              <h2>Результат</h2>
              <span className={`badge badge--${result.classification.toLowerCase()}`}>
                {RISK_LABELS[result.classification] ?? result.classification} · {result.score}
              </span>
            </div>
            {result.missing_evidence.length > 0 && (
              <div className="notice notice--warning">
                <strong>Проверено не всё:</strong>
                <ul className="inline-list">
                  {result.missing_evidence.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
            <p className="small muted hash">Пакет правил: {result.ruleset_fingerprint}</p>
          </section>

          <section className="card">
            <div className="card__header">
              <h2>Сработавшие правила ({result.signals.length})</h2>
            </div>
            {result.signals.length === 0 ? (
              <p className="muted">Ни одно правило не сработало.</p>
            ) : (
              <table className="table table--compact">
                <thead>
                  <tr>
                    <th>Правило</th>
                    <th>Название</th>
                    <th>Серьёзность</th>
                    <th>Вес</th>
                    <th>Условие</th>
                    <th>Доказательства</th>
                  </tr>
                </thead>
                <tbody>
                  {result.signals.map((signal) => (
                    <tr key={`${signal.rule_id}-${signal.rule_version}`}>
                      <td>
                        {signal.rule_id}
                        <div className="small muted">v{signal.rule_version}</div>
                      </td>
                      <td>
                        {signal.title}
                        {signal.shadow && (
                          <div className="small muted">теневое — баллов не даёт</div>
                        )}
                        {signal.suppressed && (
                          <div className="small muted">подавлено исключением</div>
                        )}
                      </td>
                      <td>{signal.severity}</td>
                      <td>{signal.weight}</td>
                      <td className="small">
                        <code>{signal.condition ?? "—"}</code>
                      </td>
                      <td className="small">
                        <ul className="inline-list">
                          {Object.entries(signal.evidence)
                            .slice(0, 4)
                            .map(([key, value]) => (
                              <li key={key}>
                                {key}: {String(value).slice(0, 60)}
                              </li>
                            ))}
                        </ul>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="card">
            <div className="card__header">
              <h2>Признаки, извлечённые из письма</h2>
            </div>
            <p className="muted small">
              То, что правила видели. Аналитик спорит именно с этим, а не с вердиктом.
            </p>
            <ul className="inline-list small">
              {Object.entries(result.matched_facts)
                .slice(0, 80)
                .map(([key, value]) => (
                  <li key={key}>
                    <code>{key}</code>
                    {value !== true && `: ${String(value).slice(0, 50)}`}
                  </li>
                ))}
            </ul>
          </section>
        </>
      )}
    </div>
  );
}
