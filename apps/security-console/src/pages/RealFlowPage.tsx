import { useCallback, useEffect, useState } from "react";
import {
  api,
  type CurrentUser,
  type GatewayReadiness,
  type RealFlowMessage,
  type RealFlowSummary,
} from "../api/client";
import { RISK_LABELS, formatDate } from "../types";

/**
 * Реальный поток (ТЗ 1.0.4 §13, §14).
 *
 * Страница отвечает на один вопрос: как детектирование ведёт себя на настоящей почте. Отсюда
 * три решения в её устройстве.
 *
 * Первое: доля, у которой нет знаменателя, показывается как «—», а не как 0%. Точность 0%
 * читается как «платформа всегда ошибается», тогда как значит «никто ещё не разбирал», и это
 * ровно то место, где интерфейс способен соврать убедительнее всего.
 *
 * Второе: recall подписан оценкой прямо в интерфейсе, а не в сноске. Полной разметки реального
 * потока не существует, и число без этой подписи читалось бы как измерение.
 *
 * Третье: очередь неопределённых писем отделена от обычной. Письмо, которое не удалось
 * проверить целиком, требует не того же, что письмо с высоким риском: по нему нет вердикта,
 * который можно подтвердить или опровергнуть, — есть пробел.
 */

const SOURCE_LABELS: Record<string, string> = {
  SECURITY_MAILBOX: "ящик безопасности",
  EWS_READONLY: "EWS только чтение",
  JOURNAL_COPY: "копия из журнала",
  GATEWAY_EVIDENCE: "свидетельство шлюза",
  ANALYST_UPLOAD: "загрузка аналитика",
};

const REASON_LABELS: Record<string, string> = {
  HIGH_RISK: "высокий риск",
  MALICIOUS: "вредоносное",
  EMPLOYEE_REPORT: "обращение сотрудника",
  GATEWAY_CONFLICT: "расхождение со шлюзом",
  QR_CODE: "QR-код",
  CANDIDATE_RULE_MATCH: "правило-кандидат",
  RANDOM_LEGITIMATE: "случайная доля легитимной почты",
  UNCERTAIN: "проверено не до конца",
};

const PII_LABELS: Record<string, string> = {
  RAW: "как пришло",
  ANONYMIZED: "обезличено автоматически",
  REVIEWED: "обезличивание проверено человеком",
  REJECTED: "проверка нашла персональные данные",
};

const PROMOTION_LABELS: Record<string, string> = {
  NOT_REQUESTED: "не предлагалось",
  REQUESTED: "подана заявка",
  APPROVED: "согласовано",
  PROMOTED: "в корпусе",
  REJECTED: "отклонено",
};

const CLASSIFICATIONS = [
  "CONFIRMED_PHISHING",
  "CONFIRMED_BEC",
  "CONFIRMED_MALWARE",
  "CONFIRMED_SPAM",
  "CONFIRMED_IMPERSONATION",
  "LEGITIMATE",
  "FALSE_POSITIVE",
  "UNKNOWN",
];

const CLASSIFICATION_LABELS: Record<string, string> = {
  CONFIRMED_PHISHING: "подтверждённый фишинг",
  CONFIRMED_BEC: "подтверждённый BEC",
  CONFIRMED_MALWARE: "подтверждённое вредоносное",
  CONFIRMED_SPAM: "подтверждённый спам",
  CONFIRMED_IMPERSONATION: "подтверждённая имитация",
  LEGITIMATE: "легитимное письмо",
  FALSE_POSITIVE: "ложное срабатывание",
  UNKNOWN: "не удалось определить",
};

const DECISION_CLASS: Record<string, string> = {
  READY_FOR_MSP_1_1: "badge badge--approved",
  READY_WITH_WARNINGS: "badge badge--proposed",
  NOT_READY: "badge badge--rejected",
};

/**
 * Доля без знаменателя — это «—», а не ноль.
 *
 * Единственное место, где интерфейс мог бы соврать молча и убедительно: 0% точности выглядит
 * как измерение, а означает отсутствие разборов.
 */
function share(value: number | null): string {
  if (value === null || value === undefined) return "—";
  return `${(value * 100).toFixed(1)}%`;
}

export function RealFlowPage({ user }: { user: CurrentUser }) {
  const [summary, setSummary] = useState<RealFlowSummary | null>(null);
  const [readiness, setReadiness] = useState<GatewayReadiness | null>(null);
  const [messages, setMessages] = useState<RealFlowMessage[]>([]);
  const [uncertain, setUncertain] = useState<RealFlowMessage[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [caseIds, setCaseIds] = useState<Record<string, string>>({});

  const canReview = user.permissions.includes("realflow:review");
  const canPromote = user.permissions.includes("realflow:promote");
  const canSeeReadiness = user.permissions.includes("readiness:read");

  const load = useCallback(() => {
    setError(null);
    void Promise.all([
      api.realFlowSummary(),
      api.realFlowMessages({ limit: 100 }),
      api.realFlowMessages({ uncertain_only: true, limit: 50 }),
      canSeeReadiness ? api.gatewayReadiness() : Promise.resolve(null),
    ])
      .then(([summaryResult, all, uncertainResult, readinessResult]) => {
        setSummary(summaryResult);
        setMessages(all);
        setUncertain(uncertainResult);
        setReadiness(readinessResult);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Ошибка загрузки"));
  }, [canSeeReadiness]);

  useEffect(load, [load]);

  const act = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось выполнить действие");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <h1>Реальный поток</h1>
      <p className="muted small">
        Как детектирование ведёт себя на настоящей почте. Синтетический корпус на этот вопрос не
        отвечает: он содержит ровно те случаи, которые мы придумали. Письма в наборе хранятся без
        темы и текста — для измерения они не нужны.
      </p>

      {error && <div className="error">{error}</div>}

      {summary && (
        <>
          <section className="card">
            <h2>Качество на реальном потоке</h2>
            <div className="tiles">
              <div className="tile">
                <div className="tile__label">Точность</div>
                <div className="tile__value">{share(summary.precision)}</div>
                <div className="muted small">
                  {summary.precision === null
                    ? "нет знаменателя: подтверждённых разборов пока нет"
                    : `по ${summary.true_positive + summary.false_positive} разборам`}
                </div>
              </div>
              <div className="tile">
                <div className="tile__label">Полнота (оценка)</div>
                <div className="tile__value">{share(summary.recall_estimate)}</div>
                <div className="muted small">
                  оценка, не измерение: полной разметки реального потока не существует
                </div>
              </div>
              <div className="tile">
                <div className="tile__label">Писем в наборе</div>
                <div className="tile__value">
                  {summary.sample.analyzed} / {summary.sample.analyzed_target}
                </div>
                <div className="muted small">цель до перехода к MSP 1.1</div>
              </div>
              <div className="tile">
                <div className="tile__label">Разобрано</div>
                <div className="tile__value">
                  {summary.sample.reviewed} / {summary.sample.reviewed_target}
                </div>
                <div className="muted small">разбор аналитика — единственная истина здесь</div>
              </div>
            </div>

            {summary.sample.high_risk_unreviewed > 0 && (
              <div className="notice notice--warning">
                Не разобрано писем с высоким риском: {summary.sample.high_risk_unreviewed}. Это не
                «ещё не дошли» — это неизвестный ответ на самый дорогой вопрос.
              </div>
            )}

            <table className="table table--compact">
              <tbody>
                <tr>
                  <th>Подтверждено верно</th>
                  <td>{summary.true_positive}</td>
                  <th>Ложных срабатываний</th>
                  <td>{summary.false_positive}</td>
                </tr>
                <tr>
                  <th>Пропусков</th>
                  <td>{summary.false_negative}</td>
                  <th>Не удалось определить</th>
                  <td>{summary.unknown}</td>
                </tr>
                <tr>
                  <th>Проверено не до конца</th>
                  <td>{summary.unscannable}</td>
                  <th>Источники</th>
                  <td>
                    {Object.entries(summary.by_source)
                      .map(([key, count]) => `${SOURCE_LABELS[key] || key}: ${count}`)
                      .join(", ") || "—"}
                  </td>
                </tr>
              </tbody>
            </table>
          </section>

          <section className="card">
            <h2>Нагрузка правил</h2>
            <p className="muted small">
              На тысячу писем, а не в штуках: абсолютное число срабатываний растёт вместе с
              объёмом почты и о правиле молчит. Отдельно — число затронутых писем: правило,
              сработавшее сто раз на одном письме и на ста разных, требует разного. Вывод
              «правило шумит» делает человек, глядя на эти числа; платформа его не делает.
            </p>
            {summary.rule_pressure.length === 0 ? (
              <p className="muted">Срабатываний на реальном потоке пока нет.</p>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>Правило</th>
                    <th>Срабатываний</th>
                    <th>На 1000 писем</th>
                    <th>Ложных</th>
                    <th>Ложных на 1000</th>
                    <th>Разных писем</th>
                  </tr>
                </thead>
                <tbody>
                  {summary.rule_pressure.map((row) => (
                    <tr key={row.rule_id}>
                      <td>
                        <code>{row.rule_id}</code>
                      </td>
                      <td>{row.triggers}</td>
                      <td>{row.triggers_per_1000_messages}</td>
                      <td>{row.false_positives}</td>
                      <td>{row.fp_per_1000_messages}</td>
                      <td>{row.distinct_messages}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="card">
            <h2>Продвижение в золотой корпус</h2>
            <p className="muted small">
              Автоматического продвижения нет. Корпус — то, по чему измеряется качество
              детектирования, и письмо, попавшее в него само, измеряло бы платформу её же мнением
              о себе. Путь: разбор → обезличивание → проверка обезличивания человеком → заявка →
              согласование другим человеком → проверка воспроизводимости → явное повышение версии
              датасета.
            </p>
            <table className="table table--compact">
              <tbody>
                {Object.entries(summary.promotion.by_state).map(([state, count]) => (
                  <tr key={state}>
                    <th>{PROMOTION_LABELS[state] || state}</th>
                    <td>{count}</td>
                  </tr>
                ))}
                <tr>
                  <th>Не воспроизвелось на обезличенной копии</th>
                  <td>{summary.promotion.not_reproducible}</td>
                </tr>
              </tbody>
            </table>
            {summary.promotion.promoted_versions.length > 0 && (
              <p className="muted small">
                Версии датасета с письмами реального потока:{" "}
                {summary.promotion.promoted_versions.join(", ")}
              </p>
            )}
          </section>
        </>
      )}

      {readiness && (
        <section className="card">
          <h2>Готовность к inline-шлюзу</h2>
          <p>
            <span className={DECISION_CLASS[readiness.decision] || "badge"}>
              {readiness.decision_label}
            </span>
          </p>
          <p className="muted small">{readiness.scope_note}</p>
          <table className="table">
            <thead>
              <tr>
                <th>Условие</th>
                <th>Обязательное</th>
                <th>Состояние</th>
                <th>Значение</th>
              </tr>
            </thead>
            <tbody>
              {readiness.checks.map((check) => (
                <tr key={check.key}>
                  <td>
                    {check.title}
                    {check.detail && <div className="muted small">{check.detail}</div>}
                  </td>
                  <td>{check.required ? "да" : "нет"}</td>
                  <td>
                    {check.state === "passed" && "выполнено"}
                    {check.state === "failed" && "не выполнено"}
                    {/* «Не проверено» — не «выполнено». Это блокирует готовность так же, как
                        провал, и в таблице должно быть видно именно как отсутствие проверки. */}
                    {check.state === "unknown" && "не проверено"}
                  </td>
                  <td>
                    <code>{JSON.stringify(check.value)}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="card">
        <h2>Неопределённые письма ({uncertain.length})</h2>
        <p className="muted small">
          Отдельная очередь, а не фильтр. По такому письму нет вердикта, который можно
          подтвердить или опровергнуть, — есть пробел: шифрование, пароль на архиве,
          нераспознанный QR-код. Решение принимается по контексту отправителя.
        </p>
        {uncertain.length === 0 ? (
          <p className="muted">Пусто.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Получено</th>
                <th>Источник</th>
                <th>Вердикт</th>
                <th>Чего не хватило</th>
              </tr>
            </thead>
            <tbody>
              {uncertain.map((row) => (
                <tr key={row.id}>
                  <td>{formatDate(row.received_at)}</td>
                  <td>{SOURCE_LABELS[row.source] || row.source}</td>
                  <td>{row.production_verdict ? RISK_LABELS[row.production_verdict] : "—"}</td>
                  <td>{row.unscannable_reasons.join(", ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <h2>Набор валидации ({messages.length})</h2>
        <table className="table">
          <thead>
            <tr>
              <th>Получено</th>
              <th>Источник</th>
              <th>Почему в выборке</th>
              <th>Вердикт тогда</th>
              <th>Разбор</th>
              <th>Персональные данные</th>
              <th>Корпус</th>
              {(canReview || canPromote) && <th>Действие</th>}
            </tr>
          </thead>
          <tbody>
            {messages.map((row) => (
              <tr key={row.id}>
                <td>{formatDate(row.received_at)}</td>
                <td>{SOURCE_LABELS[row.source] || row.source}</td>
                <td className="small">
                  {row.sampling_reasons.map((r) => REASON_LABELS[r] || r).join(", ") || "—"}
                </td>
                <td>{row.production_verdict ? RISK_LABELS[row.production_verdict] : "—"}</td>
                <td>
                  {row.analyst_classification ? (
                    <>
                      {CLASSIFICATION_LABELS[row.analyst_classification] ||
                        row.analyst_classification}
                      <div className="muted small">{row.reviewed_by}</div>
                    </>
                  ) : (
                    /* «Не разобрано» — не «верно». Пустая ячейка читалась бы как согласие. */
                    <span className="muted">не разобрано</span>
                  )}
                </td>
                <td className="small">{PII_LABELS[row.pii_status] || row.pii_status}</td>
                <td className="small">
                  {PROMOTION_LABELS[row.promotion_state] || row.promotion_state}
                  {row.promoted_dataset_version && (
                    <div className="muted small">{row.promoted_dataset_version}</div>
                  )}
                </td>
                {(canReview || canPromote) && (
                  <td>
                    {canReview && !row.analyst_classification && (
                      <select
                        disabled={busy}
                        defaultValue=""
                        onChange={(event) => {
                          const classification = event.target.value;
                          if (!classification) return;
                          void act(() =>
                            api.reviewRealFlowMessage(row.id, { classification }),
                          );
                        }}
                      >
                        <option value="">разобрать…</option>
                        {CLASSIFICATIONS.map((value) => (
                          <option key={value} value={value}>
                            {CLASSIFICATION_LABELS[value] || value}
                          </option>
                        ))}
                      </select>
                    )}
                    {canPromote &&
                      row.analyst_classification &&
                      row.promotion_state === "NOT_REQUESTED" && (
                        <div className="form-row">
                          <input
                            placeholder="номер разбора"
                            value={caseIds[row.id] || ""}
                            onChange={(event) =>
                              setCaseIds({ ...caseIds, [row.id]: event.target.value })
                            }
                          />
                          <button
                            type="button"
                            className="button button--tiny"
                            disabled={busy || !(caseIds[row.id] || "").trim()}
                            onClick={() =>
                              void act(() =>
                                api.requestRealFlowPromotion(row.id, {
                                  case_id: (caseIds[row.id] || "").trim(),
                                }),
                              )
                            }
                          >
                            предложить в корпус
                          </button>
                        </div>
                      )}
                    {canPromote && row.promotion_state === "REQUESTED" && (
                      <button
                        type="button"
                        className="button button--tiny button--primary"
                        disabled={busy}
                        onClick={() =>
                          void act(() =>
                            api.decideRealFlowPromotion(row.id, { decision: "approve" }),
                          )
                        }
                      >
                        согласовать
                      </button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
        {messages.length === 0 && (
          <p className="muted">
            Набор пуст. Это означает, что писем ещё не поступало, а не что платформа работает без
            ошибок.
          </p>
        )}
      </section>
    </div>
  );
}
