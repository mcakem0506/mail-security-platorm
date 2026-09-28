/**
 * Backend client for the add-in (ТЗ 6, 40.8).
 *
 * The add-in holds no secrets: it authenticates with the platform session cookie and a CSRF
 * token fetched from the API. A backend failure never throws into Outlook — every call resolves
 * to a state object the UI can render (ТЗ 40.9).
 */

const DEFAULT_TIMEOUT_MS = 15000;

export const Status = {
  NOT_ANALYZED: "NOT_ANALYZED",
  QUEUED: "QUEUED",
  ANALYZING: "ANALYZING",
  LOW_RISK: "LOW_RISK",
  SUSPICIOUS: "SUSPICIOUS",
  HIGH_RISK: "HIGH_RISK",
  MALICIOUS: "MALICIOUS",
  UNKNOWN: "UNKNOWN",
  PROVIDER_UNAVAILABLE: "PROVIDER_UNAVAILABLE",
  ERROR: "ERROR",
  REPORTED: "REPORTED",
  UNDER_INVESTIGATION: "UNDER_INVESTIGATION",
  CLOSED: "CLOSED",
};

export class ApiClient {
  constructor(baseUrl) {
    this.baseUrl = (baseUrl || "").replace(/\/+$/, "");
    this.csrfToken = null;
  }

  async request(path, { method = "GET", body = null, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const headers = { Accept: "application/json" };
    if (body !== null) {
      headers["Content-Type"] = "application/json";
    }
    if (this.csrfToken && method !== "GET") {
      headers["X-CSRF-Token"] = this.csrfToken;
    }
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        credentials: "include",
        signal: controller.signal,
        body: body === null ? undefined : JSON.stringify(body),
      });
      let payload = null;
      try {
        payload = await response.json();
      } catch (error) {
        payload = null;
      }
      return { ok: response.ok, status: response.status, data: payload };
    } catch (error) {
      const aborted = error && error.name === "AbortError";
      return {
        ok: false,
        status: 0,
        data: null,
        networkError: true,
        timeout: aborted,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  async session() {
    const result = await this.request("/api/v1/auth/me");
    if (result.ok && result.data) {
      this.csrfToken = result.data.csrf_token || null;
      return { authenticated: true, user: result.data };
    }
    return { authenticated: false, status: result.status, networkError: !!result.networkError };
  }

  async submit({ rawEmlBase64, mailbox, report, note, internetMessageId, itemId }) {
    const body = {
      raw_eml_base64: rawEmlBase64 || null,
      mailbox: mailbox || null,
      report_as_phishing: !!report,
      note: note || "",
    };
    if (internetMessageId) body.internet_message_id = internetMessageId;
    if (itemId) body.exchange_item_id = itemId;
    return this.request("/api/v1/analysis", { method: "POST", body, timeoutMs: 30000 });
  }

  async status(jobId) {
    return this.request(`/api/v1/analysis/${encodeURIComponent(jobId)}`);
  }

  /**
   * Poll until the analysis reaches a terminal state.
   * The add-in never blocks on Threat Intelligence: the local verdict is shown as soon as it
   * exists, and enrichment updates it later (ТЗ 35).
   */
  async pollUntilComplete(jobId, { onUpdate, intervalMs = 2000, maxAttempts = 15 } = {}) {
    const pending = new Set([Status.QUEUED, Status.ANALYZING]);
    let last = null;
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const result = await this.status(jobId);
      if (!result.ok) {
        return last || result;
      }
      last = result;
      if (onUpdate) onUpdate(result.data);
      if (!pending.has(result.data.status)) {
        const tiPending = result.data.ti_state === "PENDING";
        if (!tiPending || attempt >= 3) {
          return result;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    return last;
  }
}

/** Convert a binary string / Uint8Array into base64 without a data URL round-trip. */
export function toBase64(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}
