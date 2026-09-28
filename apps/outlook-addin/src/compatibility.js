/**
 * Runtime capability detection (ТЗ 6.5).
 *
 * Nothing about the client is assumed. Each capability is probed against the actual Office.js
 * runtime, and the UI states plainly what this client can and cannot do. When the full message
 * cannot be read, the add-in switches to the security mailbox fallback rather than failing.
 */

export const Capability = {
  READ_ITEM: "read_item",
  ITEM_ID: "item_id",
  MIME_ACCESS: "mime_access",
  EWS_TOKEN: "ews_token",
  INTERNET_HEADERS: "internet_headers",
  DISPLAY_NOTIFICATION: "display_notification",
  MOVE_TO_FOLDER: "move_to_folder",
};

const REQUIREMENT_SETS = ["1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10", "1.12", "1.13", "1.14"];

/** Highest supported Mailbox requirement set, or null when Office.js is unavailable. */
export function mailboxVersion() {
  if (typeof Office === "undefined" || !Office.context || !Office.context.requirements) {
    return null;
  }
  let highest = null;
  for (const version of REQUIREMENT_SETS) {
    if (Office.context.requirements.isSetSupported("Mailbox", version)) {
      highest = version;
    }
  }
  return highest;
}

function supports(version) {
  return (
    typeof Office !== "undefined" &&
    Office.context &&
    Office.context.requirements &&
    Office.context.requirements.isSetSupported("Mailbox", version)
  );
}

function hasFunction(path) {
  try {
    const parts = path.split(".");
    let current = typeof Office !== "undefined" ? Office : undefined;
    for (const part of parts) {
      if (current === undefined || current === null) return false;
      current = current[part];
    }
    return typeof current === "function";
  } catch (error) {
    return false;
  }
}

/**
 * Detect what this client actually supports.
 * @returns {{version: string|null, platform: string, capabilities: Object, mode: string, limitations: string[]}}
 */
export function detectCapabilities() {
  const version = mailboxVersion();
  const platform =
    typeof Office !== "undefined" && Office.context && Office.context.platform
      ? String(Office.context.platform)
      : "unknown";

  const capabilities = {
    [Capability.READ_ITEM]:
      typeof Office !== "undefined" && !!(Office.context && Office.context.mailbox && Office.context.mailbox.item),
    [Capability.ITEM_ID]: false,
    [Capability.MIME_ACCESS]: hasFunction("context.mailbox.item.getAllInternetHeadersAsync") && supports("1.8"),
    [Capability.EWS_TOKEN]: hasFunction("context.mailbox.getCallbackTokenAsync"),
    [Capability.INTERNET_HEADERS]: hasFunction("context.mailbox.item.getAllInternetHeadersAsync"),
    [Capability.DISPLAY_NOTIFICATION]:
      typeof Office !== "undefined" &&
      !!(Office.context && Office.context.mailbox && Office.context.mailbox.item && Office.context.mailbox.item.notificationMessages),
    [Capability.MOVE_TO_FOLDER]: false,
  };

  try {
    capabilities[Capability.ITEM_ID] = !!(
      Office.context &&
      Office.context.mailbox &&
      Office.context.mailbox.item &&
      Office.context.mailbox.item.itemId
    );
  } catch (error) {
    capabilities[Capability.ITEM_ID] = false;
  }

  const limitations = [];
  let mode = "full";

  if (!capabilities[Capability.READ_ITEM]) {
    mode = "unavailable";
    limitations.push("Надстройка не может прочитать открытое письмо в этом клиенте.");
  } else if (!capabilities[Capability.MIME_ACCESS]) {
    mode = "fallback";
    limitations.push(
      "Этот клиент не позволяет надстройке получить письмо целиком, поэтому проверка выполняется " +
        "через передачу письма в службу информационной безопасности."
    );
  }

  if (!capabilities[Capability.INTERNET_HEADERS]) {
    limitations.push("Заголовки письма недоступны напрямую — часть проверок выполняется на сервере.");
  }
  if (platform === "OfficeOnline") {
    limitations.push("В Outlook на веб-клиенте набор возможностей может отличаться от классического Outlook.");
  }
  if (platform === "iOS" || platform === "Android") {
    limitations.push(
      "В мобильном Outlook доступна только передача письма в службу ИБ: полный анализ на устройстве не выполняется."
    );
    mode = mode === "unavailable" ? mode : "fallback";
  }

  return { version, platform, capabilities, mode, limitations };
}

/**
 * Read the raw message when the client allows it.
 * Returns null when unavailable — the caller then uses the security mailbox fallback.
 */
export function getMessageMime() {
  return new Promise((resolve) => {
    try {
      const item = Office.context.mailbox.item;
      if (!item || typeof item.getAllInternetHeadersAsync !== "function") {
        resolve(null);
        return;
      }
      // Headers plus body: enough for sender integrity, URL and BEC analysis. The full MIME with
      // attachments requires EWS, which is only used when the environment has been verified.
      item.getAllInternetHeadersAsync((headersResult) => {
        if (headersResult.status !== Office.AsyncResultStatus.Succeeded) {
          resolve(null);
          return;
        }
        const headers = headersResult.value || "";
        item.body.getAsync(Office.CoercionType.Html, (bodyResult) => {
          if (bodyResult.status !== Office.AsyncResultStatus.Succeeded) {
            resolve(null);
            return;
          }
          const body = bodyResult.value || "";
          const separator = headers.endsWith("\r\n") ? "\r\n" : "\r\n\r\n";
          resolve(`${headers}${separator}${body}`);
        });
      });
    } catch (error) {
      resolve(null);
    }
  });
}

/** Basic item facts usable on every requirement set. */
export function getItemSummary() {
  try {
    const item = Office.context.mailbox.item;
    return {
      subject: item.subject || "",
      sender: item.from ? item.from.emailAddress || "" : "",
      senderName: item.from ? item.from.displayName || "" : "",
      internetMessageId: item.internetMessageId || "",
      itemId: item.itemId || "",
      mailbox: Office.context.mailbox.userProfile ? Office.context.mailbox.userProfile.emailAddress || "" : "",
    };
  } catch (error) {
    return { subject: "", sender: "", senderName: "", internetMessageId: "", itemId: "", mailbox: "" };
  }
}
