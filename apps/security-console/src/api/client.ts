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
  /** The analysis behind `classification`; needed to load the signals that explain it. */
  job_id: string | null;
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

/** One gateway observation about a message (ТЗ 1.0.2 §16). */
export interface GatewayEvidence {
  provider_id: string;
  provider_type: string;
  /** MALICIOUS | PHISHING | SPAM | SUSPICIOUS | CLEAN_OBSERVED | UNKNOWN | ERROR. */
  verdict: string;
  category: string;
  engine: string;
  threat_name: string;
  score: number | null;
  policy: string;
  source: string;
  /** False when the Received chain does not prove the message passed this gateway. */
  trusted: boolean;
  trust_state: string;
  trust_reason: string;
  observed_at: string;
  detail: Record<string, unknown>;
}

export interface GatewayConflict {
  conflict_id: string;
  kind: string;
  summary: string;
  providers: string[];
  detail: Record<string, unknown>;
  detected_at: string;
  resolved_at: string | null;
  resolution: string;
}

export interface UpstreamProtection {
  message_id: string;
  present: boolean;
  evidence: GatewayEvidence[];
  conflicts: GatewayConflict[];
  note: string;
}

export interface TrustedHop {
  hop_id: string;
  hop_type: string;
  hostname: string;
  ip_networks: string[];
  expected_headers: string[];
  authserv_ids: string[];
  position_in_chain: number | null;
  direction: string;
  enabled: boolean;
  gateway_id: string | null;
}

export interface MailGateway {
  gateway_id: string;
  provider_id: string;
  provider_type: string;
  display_name: string;
  vendor: string;
  direction: string;
  enabled: boolean;
  settings: Record<string, unknown>;
  capabilities: string[];
  trusted_hops: TrustedHop[];
  nodes: { hostname: string; ip_networks: string[]; role: string }[];
  last_event_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
  health?: { status: string; detail: string | null; mode: string | null };
}

export interface GatewayList {
  /** NOT_PRESENT is a valid deployment, not a failure (ТЗ 1.0.2 §31). */
  state: string;
  gateways: MailGateway[];
  /** Trusted hops belonging to no gateway: the Exchange edge and mailbox servers. */
  infrastructure_hops: TrustedHop[];
  supported_provider_types: string[];
  available_skeletons: {
    provider_type: string;
    display_name: string;
    implemented: string[];
    planned: string[];
    prerequisites: string[];
    status: string;
  }[];
  syslog_enabled: boolean;
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

  gateways: () => request<GatewayList>("/api/v1/gateways"),

  createGateway: (body: Record<string, unknown>) =>
    request<MailGateway>("/api/v1/gateways", { method: "POST", body: JSON.stringify(body) }),

  updateGateway: (id: string, body: Record<string, unknown>) =>
    request<MailGateway>(`/api/v1/gateways/${id}`, { method: "PUT", body: JSON.stringify(body) }),

  addTrustedHop: (gatewayId: string, body: Record<string, unknown>) =>
    request<TrustedHop>(`/api/v1/gateways/${gatewayId}/hops`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  addInfrastructureHop: (body: Record<string, unknown>) =>
    request<TrustedHop>("/api/v1/gateways/hops", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  deleteTrustedHop: (hopId: string) =>
    request<void>(`/api/v1/gateways/hops/${hopId}`, { method: "DELETE" }),

  probeGateways: () =>
    request<Record<string, unknown>>("/api/v1/gateways/probe", { method: "POST" }),

  gatewayDeadLetters: () =>
    request<Record<string, unknown>[]>("/api/v1/gateways/dead-letters"),

  upstreamProtection: (messageId: string) =>
    request<UpstreamProtection>(`/api/v1/gateways/messages/${messageId}`),

  resolveGatewayConflict: (conflictId: string, resolution: string) =>
    request<GatewayConflict>(
      `/api/v1/gateways/conflicts/${conflictId}/resolve?resolution=${encodeURIComponent(resolution)}`,
      { method: "POST" },
    ),

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
