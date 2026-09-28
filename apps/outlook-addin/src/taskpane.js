/**
 * Task pane logic (ТЗ 6.2, 6.3, 6.4).
 *
 * The pane shows a status, the three to five most important reasons, a safe recommendation and
 * whether the message was handed to the security team. It never shows internal detection rules,
 * raw provider output or anything about other people's mailboxes.
 */

import { ApiClient, Status, toBase64 } from "./api.js";
import { Capability, detectCapabilities, getItemSummary, getMessageMime } from "./compatibility.js";

const API_BASE = window.MSP_API_BASE || "";
const client = new ApiClient(API_BASE);

const STATUS_PRESENTATION = {
  [Status.NOT_ANALYZED]: { label: "Не проверено", tone: "neutral" },
  [Status.QUEUED]: { label: "В очереди на проверку", tone: "neutral" },
  [Status.ANALYZING]: { label: "Идёт проверка", tone: "neutral" },
  [Status.LOW_RISK]: {
    label: "Признаков атаки не обнаружено",
    tone: "low",
    note: "Это не гарантия безопасности — сохраняйте обычную осторожность.",
  },
  [Status.SUSPICIOUS]: { label: "Подозрительное письмо", tone: "medium" },
  [Status.HIGH_RISK]: { label: "Высокий риск", tone: "high" },
  [Status.MALICIOUS]: { label: "Вредоносное письмо", tone: "critical" },
  [Status.UNKNOWN]: {
    label: "Проверка выполнена не полностью",
    tone: "unknown",
    note: "Данных недостаточно, чтобы подтвердить безопасность письма.",
  },
  [Status.PROVIDER_UNAVAILABLE]: {
    label: "Внешние источники недоступны",
    tone: "unknown",
    note: "Локальная проверка выполнена. Отсутствие обнаружения не означает безопасность.",
  },
  [Status.ERROR]: { label: "Ошибка проверки", tone: "error" },
  [Status.REPORTED]: { label: "Передано в службу ИБ", tone: "reported" },
  [Status.UNDER_INVESTIGATION]: { label: "На расследовании в службе ИБ", tone: "reported" },
  [Status.CLOSED]: { label: "Обращение закрыто", tone: "neutral" },
};

const SEVERITY_LABEL = {
  critical: "Критично",
  high: "Важно",
  medium: "Внимание",
  low: "Замечание",
  info: "Информация",
};

const state = { capabilities: null, jobId: null, busy: false };

function $(id) {
  return document.getElementById(id);
}

function setBusy(busy, message) {
  state.busy = busy;
  const spinner = $("spinner");
  if (spinner) spinner.hidden = !busy;
  const progress = $("progress-text");
  if (progress) progress.textContent = message || "";
  for (const id of ["btn-check", "btn-report", "btn-refresh"]) {
    const button = $(id);
    if (button) button.disabled = busy;
  }
}

function renderStatus(data) {
  const presentation = STATUS_PRESENTATION[data.status] || STATUS_PRESENTATION[Status.UNKNOWN];
  const badge = $("status-badge");
  badge.textContent = presentation.label;
  badge.className = `badge badge--${presentation.tone}`;

  const note = $("status-note");
  const extra = [];
  if (presentation.note) extra.push(presentation.note);
  if (data.analysis_incomplete) {
    extra.push("Часть проверок не была выполнена, вердикт может измениться.");
  }
  if (data.ti_state === "PENDING") {
    extra.push("Проверка по внешним источникам ещё выполняется.");
  }
  note.textContent = extra.join(" ");
  note.hidden = extra.length === 0;

  const recommendation = $("recommendation");
  recommendation.textContent = data.recommendation || "";
  recommendation.hidden = !data.recommendation;

  const list = $("reasons");
  list.innerHTML = "";
  const reasons = (data.reasons || []).slice(0, 5);
  for (const reason of reasons) {
    const item = document.createElement("li");
    item.className = `reason reason--${reason.severity}`;
    const title = document.createElement("div");
    title.className = "reason__title";
    title.textContent = `${SEVERITY_LABEL[reason.severity] || ""}: ${reason.title}`;
    const text = document.createElement("div");
    text.className = "reason__text";
    text.textContent = reason.explanation;
    item.append(title, text);
    list.append(item);
  }
  $("reasons-section").hidden = reasons.length === 0;

  const meta = $("meta");
  const parts = [];
  if (data.analyzed_at) {
    parts.push(`Проверено: ${new Date(data.analyzed_at).toLocaleString("ru-RU")}`);
  }
  if (data.reported_to_security) {
    parts.push("Письмо передано в службу информационной безопасности.");
  }
  meta.textContent = parts.join(" · ");
  meta.hidden = parts.length === 0;

  $("result").hidden = false;
}

function renderError(title, detail) {
  const badge = $("status-badge");
  badge.textContent = title;
  badge.className = "badge badge--error";
  $("status-note").textContent = detail || "";
  $("status-note").hidden = !detail;
  $("recommendation").hidden = true;
  $("reasons-section").hidden = true;
  $("meta").hidden = true;
  $("result").hidden = false;
}

function renderCapabilities(info) {
  const box = $("limitations");
  box.innerHTML = "";
  if (!info.limitations.length) {
    box.hidden = true;
    return;
  }
  const heading = document.createElement("div");
  heading.className = "limitations__title";
  heading.textContent = "Ограничения этого почтового клиента";
  box.append(heading);
  const list = document.createElement("ul");
  for (const limitation of info.limitations) {
    const item = document.createElement("li");
    item.textContent = limitation;
    list.append(item);
  }
  box.append(list);
  box.hidden = false;
}

async function ensureSession() {
  const session = await client.session();
  if (session.authenticated) {
    $("auth-warning").hidden = true;
    return true;
  }
  $("auth-warning").hidden = false;
  $("auth-warning").textContent = session.networkError
    ? "Сервис проверки писем недоступен. Попробуйте позже или обратитесь в службу ИБ."
    : "Требуется вход в систему проверки писем. Откройте портал безопасности и войдите.";
  return false;
}

async function submitMessage({ report }) {
  if (state.busy) return;
  setBusy(true, report ? "Передаём письмо в службу ИБ…" : "Отправляем письмо на проверку…");
  try {
    if (!(await ensureSession())) {
      return;
    }
    const summary = getItemSummary();
    const mime = state.capabilities.capabilities[Capability.MIME_ACCESS] ? await getMessageMime() : null;

    if (!mime) {
      // Fallback: the client cannot hand us the message, so the employee forwards it to the
      // security mailbox with headers preserved (ТЗ 6.5).
      showFallbackInstructions(summary);
      return;
    }

    const result = await client.submit({
      rawEmlBase64: toBase64(mime),
      mailbox: summary.mailbox,
      report,
      internetMessageId: summary.internetMessageId,
      itemId: summary.itemId,
    });

    if (!result.ok) {
      if (result.networkError) {
        renderError(
          "Сервис недоступен",
          "Не удалось связаться с сервисом проверки. Письмо можно передать в службу ИБ вручную."
        );
      } else if (result.status === 501) {
        showFallbackInstructions(summary);
      } else {
        renderError(
          "Не удалось выполнить проверку",
          (result.data && result.data.detail) || "Повторите попытку позже."
        );
      }
      return;
    }

    state.jobId = result.data.job_id;
    renderStatus(result.data);
    setBusy(true, "Выполняется анализ…");
    const final = await client.pollUntilComplete(state.jobId, { onUpdate: renderStatus });
    if (final && final.ok) {
      renderStatus(final.data);
    }
  } catch (error) {
    // A failure here must never surface as an Outlook error dialog (ТЗ 40.9).
    renderError("Не удалось выполнить проверку", "Обратитесь в службу информационной безопасности.");
  } finally {
    setBusy(false, "");
  }
}

function showFallbackInstructions(summary) {
  const mailbox = window.MSP_SECURITY_MAILBOX || "security-phishing@corp.example";
  renderError(
    "Проверка через службу ИБ",
    "Этот почтовый клиент не позволяет надстройке прочитать письмо целиком."
  );
  const box = $("fallback");
  box.innerHTML = "";
  const text = document.createElement("p");
  text.textContent =
    `Перешлите это письмо как вложение на адрес ${mailbox}. ` +
    "Важно переслать именно как вложение — так сохранятся оригинальные заголовки, " +
    "необходимые для анализа.";
  const hint = document.createElement("p");
  hint.className = "hint";
  hint.textContent = "В Outlook: Главная → Дополнительно → Переслать как вложение.";
  box.append(text, hint);
  if (summary.subject) {
    const subject = document.createElement("p");
    subject.className = "hint";
    subject.textContent = `Письмо: «${summary.subject}»`;
    box.append(subject);
  }
  box.hidden = false;
}

async function refreshResult() {
  if (!state.jobId || state.busy) return;
  setBusy(true, "Обновляем результат…");
  try {
    const result = await client.status(state.jobId);
    if (result.ok) {
      renderStatus(result.data);
    } else {
      renderError("Не удалось обновить результат", "Повторите попытку позже.");
    }
  } finally {
    setBusy(false, "");
  }
}

function initialise() {
  state.capabilities = detectCapabilities();
  renderCapabilities(state.capabilities);

  if (state.capabilities.mode === "unavailable") {
    renderError(
      "Надстройка недоступна в этом клиенте",
      "Передайте подозрительное письмо в службу ИБ вручную, переслав его как вложение."
    );
  }

  const summary = getItemSummary();
  $("subject").textContent = summary.subject || "(без темы)";
  $("sender").textContent = summary.senderName ? `${summary.senderName} <${summary.sender}>` : summary.sender;

  $("btn-check").addEventListener("click", () => submitMessage({ report: false }));
  $("btn-report").addEventListener("click", () => submitMessage({ report: true }));
  $("btn-refresh").addEventListener("click", refreshResult);

  const params = new URLSearchParams(window.location.search);
  if (params.get("action") === "report") {
    submitMessage({ report: true });
  }
}

if (typeof Office !== "undefined") {
  Office.onReady((info) => {
    if (info.host === Office.HostType.Outlook) {
      initialise();
    }
  });
}

export { initialise, renderStatus, STATUS_PRESENTATION };
