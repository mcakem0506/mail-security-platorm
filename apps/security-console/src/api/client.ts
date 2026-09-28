/**
 * API client for the security console.
 *
 * Authentication is the platform session cookie; the CSRF token is read from the cookie the API
 * sets and echoed in a header on every state-changing request (ТЗ 24, 30).
 */

export type RiskLevel = "LOW_RISK" | "SUSPICIOUS" | "HIGH_RISK" | "MALICIOUS" | "UNKNOWN";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Reason {
  signal_id: string;
  title: string;
  explanation: string;
  severity: Severity;
  source: string;
  observed_at: string;
  internal: boolean;
  recommendation: string | null;
}

export interface Signal {
  signal_id: string;
  rule_id: string | null;
  rule_version: number | null;
  category: string;
  title: string;
  explanation: string;
  severity: Severity;
  confidence: number;
  weight: number;
  source: string;
  evidence: Record<string, unknown>;
  hard: boolean;
  internal: boolean;
  suppressed: boolean;
  suppressed_by: string | null;
}

export interface MessageSummary {
  message_id: string;
  subject: string;
  sender_address: string;
  sender_display_name: string;
  sender_domain: string;
  recipient_count: number;
  received_at: string;
  classification: RiskLevel | null;
  score: number | null;
  has_attachments: boolean;
  url_count: number;
  source: string;
  reported_by: string | null;
  campaign_id: string | null;
}

export interface AnalysisDetail {
  job_id: string;
  message_id: string | null;
  status: string;
  state: string;
  ti_state: string;
  classification: RiskLevel;
  score: number;
  confidence: string;
  recommendation: string;
  reasons: Reason[];
  hard_signals: Reason[];
  suppressed_signals: Reason[];
  sources: string[];
  missing_evidence: string[];
  signals: Signal[];
  engine_version: string;
  risk_engine_version: string;
  duration_ms: number | null;
  campaign_id: string | null;
}

export interface Paginated<T> {
  total: number;
  limit: number;
  offset: number;
  items: T[];
}

export interface CurrentUser {
  user_id: string;
  email: string;
  display_name: string;
  role: string;
  role_label: string;
  permissions: string[];
  organization_id: string;
  csrf_token: string;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function readCookie(name: string): string | null {
  const match = document.cookie.split("; ").find((part) => part.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method || "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (method !== "GET" && method !== "HEAD") {
    const token = csrfToken || readCookie("msp_csrf");
    if (token) headers.set("X-CSRF-Token", token);
  }

  const response = await fetch(path, { ...init, headers, credentials: "include" });
  if (response.status === 204) return undefined as T;

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const detail =
      payload && typeof payload === "object" && "detail" in payload
        ? String((payload as { detail: unknown }).detail)
        : `Ошибка запроса (${response.status})`;
    throw new ApiError(response.status, detail, response.headers.get("X-Request-ID") || undefined);
  }
  return payload as T;
}

function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export const api = {
  async login(email: string, password: string) {
    const result = await request<CurrentUser & { csrf_token: string }>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setCsrfToken(result.csrf_token);
    return result;
  },

  async me() {
    const user = await request<CurrentUser>("/api/v1/auth/me");
    setCsrfToken(user.csrf_token);
    return user;
  },

  logout: () => request<void>("/api/v1/auth/logout", { method: "POST" }),

  dashboard: () => request<Record<string, unknown>>("/api/v1/dashboard"),

  searchMessages: (params: Record<string, string | number | undefined>) =>
    request<Paginated<MessageSummary>>(`/api/v1/investigations/messages${query(params)}`),

  message: (id: string) => request<Record<string, unknown>>(`/api/v1/investigations/messages/${id}`),

  preview: (id: string) =>
    request<{ message_id: string; sanitized_html: string | null; plain_text: string | null; urls: { url: string; context: string }[]; warning: string }>(
      `/api/v1/investigations/messages/${id}/preview`,
    ),

  analysisDetail: (jobId: string) => request<AnalysisDetail>(`/api/v1/analysis/${jobId}/detail`),

  indicator: (iocType: string, value: string) =>
    request<Record<string, unknown>>(
      `/api/v1/investigations/indicators/${encodeURIComponent(iocType)}/${encodeURIComponent(value)}`,
    ),

  campaigns: (params: Record<string, string | number | boolean | undefined> = {}) =>
    request<Paginated<Record<string, unknown>>>(`/api/v1/campaigns${query(params)}`),

  incidents: (params: Record<string, string | number | boolean | undefined> = {}) =>
    request<Paginated<Record<string, unknown>>>(`/api/v1/incidents${query(params)}`),

  createIncident: (body: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/v1/incidents", { method: "POST", body: JSON.stringify(body) }),

  updateIncident: (id: string, body: Record<string, unknown>) =>
    request<Record<string, unknown>>(`/api/v1/incidents/${id}`, { method: "PATCH", body: JSON.stringify(body) }),

  incidentNotes: (id: string) => request<Record<string, string>[]>(`/api/v1/incidents/${id}/notes`),

  addNote: (id: string, body: string) =>
    request<{ note_id: string }>(`/api/v1/incidents/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ body }),
    }),

  remediations: (params: Record<string, string | number | undefined> = {}) =>
    request<Paginated<Record<string, unknown>>>(`/api/v1/remediation${query(params)}`),

  proposeRemediation: (body: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/v1/remediation", { method: "POST", body: JSON.stringify(body) }),

  approveRemediation: (id: string, decision: "approved" | "rejected", comment = "") =>
    request<Record<string, unknown>>(`/api/v1/remediation/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ decision, comment }),
    }),

  executeRemediation: (id: string) =>
    request<Record<string, unknown>>(`/api/v1/remediation/${id}/execute?confirm=true`, { method: "POST" }),

  exceptions: () => request<Record<string, unknown>[]>("/api/v1/admin/exceptions"),

  createException: (body: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/v1/admin/exceptions", { method: "POST", body: JSON.stringify(body) }),

  revokeException: (id: string) =>
    request<void>(`/api/v1/admin/exceptions/${id}`, { method: "DELETE" }),

  protectedIdentities: () => request<Record<string, unknown>[]>("/api/v1/admin/protected-identities"),

  providers: () => request<Record<string, unknown>[]>("/api/v1/admin/providers"),

  rules: () => request<Record<string, unknown>[]>("/api/v1/admin/rules"),

  audit: (params: Record<string, string | number | undefined> = {}) =>
    request<Paginated<Record<string, unknown>>>(`/api/v1/admin/audit${query(params)}`),

  health: () => request<Record<string, unknown>>("/health/dependencies"),

  reportList: () => request<{ reports: string[] }>("/api/v1/reports"),

  report: (name: string, days: number) =>
    request<{
      report: string;
      period: { from: string; to: string; days: string };
      generated_at: string;
      summary: Record<string, unknown>;
      rows: Record<string, unknown>[];
    }>(`/api/v1/reports/${encodeURIComponent(name)}${query({ days })}`),

  /** CSV export URL. The download itself is audited server-side. */
  reportCsvUrl: (name: string, days: number) =>
    `/api/v1/reports/${encodeURIComponent(name)}${query({ days, format: "csv" })}`,

  notifications: (unreadOnly = false) =>
    request<{ unread: number; items: Record<string, unknown>[] }>(
      `/api/v1/notifications${query({ unread_only: unreadOnly })}`,
    ),

  markNotificationRead: (id: string) =>
    request<void>(`/api/v1/notifications/${encodeURIComponent(id)}/read`, { method: "POST" }),
};
