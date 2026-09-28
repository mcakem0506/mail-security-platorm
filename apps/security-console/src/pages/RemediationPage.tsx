import { useCallback, useEffect, useState } from "react";
import { api, type CurrentUser } from "../api/client";
import { REMEDIATION_STATE_LABELS, formatDate } from "../types";

interface Approval {
  approver: string;
  decision: string;
  comment: string;
  decided_at: string;
}

interface RemediationAction {
  action_id: string;
  action_type: string;
  state: string;
  proposed_by: string;
  reason: string;
  affected_message_count: number;
  affected_mailboxes: string[];
  required_approvals: number;
  approvals: Approval[];
  dry_run_report: Record<string, unknown>;
  rollback_supported: boolean;
  executed_at: string | null;
  executed_by: string | null;
  result: Record<string, unknown>;
  created_at: string;
}

const ACTION_LABELS: Record<string, string> = {
  locate: "Поиск сообщений",
  quarantine: "Помещение в карантин",
  delete: "Удаление",
  block_sender: "Блокировка отправителя",
  block_domain: "Блокировка домена",
  transport_rule_proposal: "Предложение транспортного правила",
  release: "Возврат из карантина",
};

/**
 * Dry-run impact report (ТЗ 20.2): the analyst sees scope, rollback capability and warnings
 * before anything is approved, and destructive actions are marked explicitly.
 */
function DryRunReport({ report }: { report: Record<string, unknown> }) {
  const warnings = (report.warnings as string[] | undefined) ?? [];
  const errors = (report.errors as string[] | undefined) ?? [];
  return (
    <div className="dry-run">
      <h4>Предварительный расчёт (dry-run)</h4>
      <ul className="inline-list">
        <li>Затронуто сообщений: {String(report.affected_messages ?? 0)}</li>
        <li>Ящиков: {((report.affected_mailboxes as string[] | undefined) ?? []).length}</li>
        <li>Откат возможен: {report.rollback_supported ? "да" : "нет"}</li>
        {report.destructive === true && <li className="danger">Необратимое действие</li>}
      </ul>
      {warnings.length > 0 && (
        <ul className="warnings">
          {warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      )}
      {errors.length > 0 && (
        <ul className="errors">
          {errors.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function RemediationPage({ user }: { user: CurrentUser }) {
  const [items, setItems] = useState<RemediationAction[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const canApprove = user.permissions.includes("approve:remediation");
  const canExecute = user.permissions.includes("execute:remediation");

  const load = useCallback(async () => {
    try {
      const data = await api.remediations({ limit: 100 });
      setItems(data.items as unknown as RemediationAction[]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Ошибка загрузки");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function decide(action: RemediationAction, decision: "approved" | "rejected") {
    setBusy(true);
    setError(null);
    try {
      await api.approveRemediation(action.action_id, decision);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось согласовать");
    } finally {
      setBusy(false);
    }
  }

  async function execute(action: RemediationAction) {
    const confirmed = window.confirm(
      `Выполнить действие «${ACTION_LABELS[action.action_type] ?? action.action_type}» ` +
        `для ${action.affected_message_count} сообщений в ${action.affected_mailboxes.length} ящиках?\n\n` +
        "Это действие изменит содержимое почтовых ящиков.",
    );
    if (!confirmed) return;
    setBusy(true);
    setError(null);
    try {
      await api.executeRemediation(action.action_id);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось выполнить");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <h1>Реагирование</h1>
      <p className="notice notice--info">
        Все действия сначала рассчитываются в режиме dry-run. Массовые операции требуют второго
        согласующего, а автор предложения не может согласовать его сам.
      </p>
      {error && <div className="error">{error}</div>}

      {items.map((action) => {
        const approved = action.approvals.filter((a) => a.decision === "approved").length;
        return (
          <section className="card" key={action.action_id}>
            <div className="page__header">
              <h2>{ACTION_LABELS[action.action_type] ?? action.action_type}</h2>
              <span className={`badge badge--${action.state.toLowerCase()}`}>
                {REMEDIATION_STATE_LABELS[action.state] ?? action.state}
              </span>
            </div>
            <p>{action.reason}</p>
            <ul className="inline-list">
              <li>Предложил: {action.proposed_by}</li>
              <li>Создано: {formatDate(action.created_at)}</li>
              <li>
                Согласований: {approved} из {action.required_approvals}
              </li>
            </ul>

            <DryRunReport report={action.dry_run_report} />

            {action.approvals.length > 0 && (
              <ul className="approvals">
                {action.approvals.map((approval) => (
                  <li key={`${approval.approver}-${approval.decided_at}`}>
                    {approval.approver}: <strong>{approval.decision}</strong>{" "}
                    <span className="muted">{formatDate(approval.decided_at)}</span>
                    {approval.comment && <div className="muted">{approval.comment}</div>}
                  </li>
                ))}
              </ul>
            )}

            <div className="actions">
              {canApprove && (action.state === "PROPOSED" || action.state === "APPROVED") && (
                <>
                  <button
                    type="button"
                    className="button button--primary"
                    disabled={busy}
                    onClick={() => void decide(action, "approved")}
                  >
                    Согласовать
                  </button>
                  <button
                    type="button"
                    className="button"
                    disabled={busy}
                    onClick={() => void decide(action, "rejected")}
                  >
                    Отклонить
                  </button>
                </>
              )}
              {canExecute && action.state === "APPROVED" && (
                <button
                  type="button"
                  className="button button--danger"
                  disabled={busy}
                  onClick={() => void execute(action)}
                >
                  Выполнить
                </button>
              )}
            </div>

            {action.executed_at && (
              <p className="muted">
                Выполнено {formatDate(action.executed_at)} пользователем {action.executed_by}
              </p>
            )}
          </section>
        );
      })}

      {items.length === 0 && <p className="muted">Запросов на реагирование нет</p>}
    </div>
  );
}
