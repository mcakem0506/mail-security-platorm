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

/** ТЗ 1.0.3 §17, §18: a queue row. Priority is not the risk level. */
export interface QueueItem {
  incident_id: string;
  number: number;
  title: string;
  priority: "P1" | "P2" | "P3" | "P4";
  priority_score: number;
  priority_factors: string[];
  sla: { state: string; target: string | null; remaining_seconds: number | null; timers: Record<string, number> };
  classification: string | null;
  confidence: string;
  status: string;
  severity: Severity;
  age_seconds: number;
  affected_users: string[];
  vip_involved: boolean;
  campaign_size: number;
  gateway_conflict: boolean;
  employee_report: boolean;
  assignee: string | null;
  analyst_classification: string | null;
}

export type AnalystClassification =
  | "CONFIRMED_PHISHING"
  | "CONFIRMED_BEC"
  | "CONFIRMED_MALWARE"
  | "CONFIRMED_SPAM"
  | "CONFIRMED_IMPERSONATION"
  | "LEGITIMATE"
  | "FALSE_POSITIVE"
  | "BENIGN_SIMULATION"
  | "UNKNOWN";

/**
 * ТЗ 1.0.3 §35. Every ratio here is nullable, and the console must render null as "—".
 * Showing 0% false positives because nothing has been classified would read as success.
 */
export interface DetectionQuality {
  period_start: string;
  period_end: string;
  total_analyzed: number;
  classified: number;
  confirmed_threats: number;
  confirmed_benign: number;
  precision: number | null;
  false_positive_rate: number | null;
  reported_misses: number;
  unscannable: number;
  unknown: number;
  open_gaps: number;
  shadow_rules: number;
  active_canaries: number;
  overdue_canaries: number;
  noisy_rules: Record<string, unknown>[];
  silent_rules: string[];
  unowned_active_rules: string[];
  coverage_by_scenario: Record<string, unknown>[];
}

/**
 * A rule released to part of the organisation before all of it (ТЗ 1.0.3 §52).
 *
 * `outside_*` is the control group: the same rule, on the same mail, recorded but powerless.
 * Precision is null until an analyst has judged something — an unjudged rollout showing 100%
 * would be the argument for promoting it.
 */
export interface CanaryRollout {
  rule_id: string;
  state: "ACTIVE" | "PROMOTED" | "ABORTED";
  scope: "MAILBOX" | "DEPARTMENT" | "PERCENT";
  scope_values: string[];
  percent: number;
  review_at: string;
  overdue: boolean;
  inside_triggers: number;
  outside_triggers: number;
  inside_confirmed: number;
  inside_false_positives: number;
  outside_confirmed: number;
  outside_false_positives: number;
  inside_precision: number | null;
  outside_precision: number | null;
  ready_to_promote: boolean;
}

export interface DetectionRule {
  rule_id: string;
  version: number;
  title: string;
  category: string;
  severity: Severity;
  status: "EXPERIMENTAL" | "SHADOW" | "ACTIVE" | "DEGRADED" | "DISABLED" | "DEPRECATED";
  owner: string;
  weight: number;
  scores: boolean;
  hard: boolean;
  scenarios: string[];
  condition: string | null;
  trigger_count: number;
  confirmed_tp: number;
  confirmed_fp: number;
  precision: number | null;
}

/** ТЗ 1.0.3B §8. Precision is null until enough has been judged — never 0, never 1. */
export interface RuleQuality {
  rule_id: string;
  rule_version: number;
  trigger_count: number;
  analyst_reviewed: number;
  true_positive: number;
  false_positive: number;
  unknown: number;
  suppressed: number;
  precision: number | null;
  affected_messages: number;
  affected_incidents: number;
  health: "HEALTHY" | "NO_DATA" | "NOISY" | "REGRESSED" | "LOW_COVERAGE" | "DEGRADED";
  health_reasons: string[];
}

/** ТЗ 1.0.3B §10–§12: a proposed rule pack under review. */
export interface RuleCandidate {
  candidate_id: string;
  name: string;
  description: string;
  source: string;
  state: "DRAFT" | "READY_FOR_REVIEW" | "CHANGES_REQUESTED" | "APPROVED" | "PUBLISHED" | "REJECTED";
  added_rules: string[];
  changed_rules: string[];
  removed_rules: string[];
  critical_change: boolean;
  critical_reasons: string[];
  author: string;
  reviewer: string;
  review_comment: string;
  benchmark: Record<string, unknown>;
  benchmarked_at: string | null;
  published_at: string | null;
  release_id: string | null;
  created_at: string;
}

/** ТЗ 1.0.3B §24: everything needed to reproduce what a release detected. */
export interface DetectionRelease {
  release_id: string;
  version: string;
  ruleset_fingerprint: string;
  parser_version: string;
  risk_engine_version: string;
  dataset_version: string;
  dataset_checksum: string;
  commit_sha: string;
  candidate_id: string | null;
  approved_by: string;
  published_by: string;
  metrics: Record<string, unknown>;
  metric_deltas: Record<string, number | null>;
  known_limitations: Record<string, unknown>[];
  new_rules: string[];
  changed_rules: string[];
  removed_rules: string[];
  changelog: string;
  published_at: string;
}

/** ТЗ 1.0.3B §23: a bulk re-evaluation. Dry run unless told otherwise, pausable, cancellable. */
export interface ReanalysisJob {
  job_id: string;
  state: "QUEUED" | "RUNNING" | "PAUSED" | "CANCELLED" | "COMPLETED" | "FAILED";
  dry_run: boolean;
  window_from: string;
  window_to: string;
  filters: Record<string, unknown>;
  max_messages: number;
  total_messages: number;
  processed: number;
  /** Null until the batch size is known: "not started" and "nothing to do" differ. */
  progress: number | null;
  verdict_changed: number;
  newly_suspicious: number;
  newly_cleared: number;
  sample: Record<string, unknown>[];
  requested_by: string;
  cancelled_by: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface DetectionGap {
  gap_id: string;
  category: string;
  description: string;
  root_cause: string;
  severity: Severity;
  status: string;
  owner: string;
  target_release: string;
  examples: string[];
  mitigation: string;
  planned_fix: string;
  reported_misses: number;
}

export interface ThreatScenarioView {
  scenario_id: string;
  title: string;
  category: string;
  description: string;
  severity: Severity;
  rules: string[];
  fixtures: string[];
  playbook: string;
  enabled: boolean;
  covered: boolean;
  active_rules: number;
  shadow_rules: number;
}

export interface SimulationResult {
  message_id: string;
  classification: RiskLevel;
  score: number;
  signals: {
    rule_id: string;
    rule_version: number;
    title: string;
    category: string;
    severity: string;
    weight: number;
    confidence: number;
    shadow: boolean;
    suppressed: boolean;
    condition: string | null;
    evidence: Record<string, unknown>;
  }[];
  matched_facts: Record<string, unknown>;
  missing_evidence: string[];
  ruleset_fingerprint: string;
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

  // --- ТЗ 1.0.3: очередь, классификация, качество детектирования ---------------------------
  investigationQueue: (params: { mine?: boolean; include_closed?: boolean; limit?: number } = {}) =>
    request<QueueItem[]>(`/api/v1/investigations/queue${query(params)}`),

  assignIncident: (id: string, body: { assignee_email?: string; candidates?: string[] }) =>
    request<Record<string, string>>(`/api/v1/incidents/${id}/assign`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  incidentTimeline: (id: string) =>
    request<{ at: string; event: string; detail: string }[]>(`/api/v1/incidents/${id}/timeline`),

  classifyIncident: (
    id: string,
    body: {
      classification: AnalystClassification;
      comment?: string;
      confidence?: "high" | "medium" | "low";
      offending_rules?: string[];
      offending_signals?: string[];
    },
  ) =>
    request<Record<string, unknown>>(`/api/v1/incidents/${id}/classification`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  employeeFeedback: (id: string) =>
    request<{ incident_id: string; classification: string; classified: boolean; text: string }>(
      `/api/v1/incidents/${id}/employee-feedback`,
    ),

  reportMissedDetection: (body: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/v1/detection/missed", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  detectionFeedback: (kind?: "false_positive" | "false_negative") =>
    request<Record<string, unknown>[]>(`/api/v1/detection/feedback${query({ kind })}`),

  detectionRules: (params: { status?: string; category?: string } = {}) =>
    request<DetectionRule[]>(`/api/v1/detection/rules${query(params)}`),

  syncDetectionRegistry: () =>
    request<{ rules: number; gaps: number; scenarios: number }>("/api/v1/detection/rules/sync", {
      method: "POST",
    }),

  changeRuleStatus: (ruleId: string, body: { status: string; reason: string; reviewer?: string }) =>
    request<Record<string, unknown>>(`/api/v1/detection/rules/${encodeURIComponent(ruleId)}/status`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  ruleChanges: () => request<Record<string, unknown>[]>("/api/v1/detection/rules/changes"),

  simulateRules: (body: { message_id: string; rule_id?: string }) =>
    request<SimulationResult>("/api/v1/detection/simulate", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  replayAnalysis: (jobId: string, apply = false) =>
    request<Record<string, unknown>>(`/api/v1/analysis/${jobId}/replay`, {
      method: "POST",
      body: JSON.stringify({ apply }),
    }),

  reevaluate: (body: { days: number; dry_run: boolean; limit?: number }) =>
    request<Record<string, unknown>>("/api/v1/detection/reevaluate", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  canaries: (includeDecided = false) =>
    request<CanaryRollout[]>(`/api/v1/detection/canaries${query({ include_decided: includeDecided })}`),

  startCanary: (
    ruleId: string,
    body: {
      scope: "MAILBOX" | "DEPARTMENT" | "PERCENT";
      scope_values?: string[];
      percent?: number;
      days?: number;
      reason: string;
    },
  ) =>
    request<CanaryRollout>(`/api/v1/detection/rules/${encodeURIComponent(ruleId)}/canary`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  decideCanary: (ruleId: string, body: { state: "PROMOTED" | "ABORTED"; note?: string }) =>
    request<CanaryRollout>(
      `/api/v1/detection/rules/${encodeURIComponent(ruleId)}/canary/decision`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  ruleQuality: (days = 30) =>
    request<RuleQuality[]>(`/api/v1/detection/rules/quality${query({ days })}`),

  snapshotRuleQuality: (days = 30) =>
    request<{ snapshots: number; period_days: number }>(
      `/api/v1/detection/rules/quality/snapshot${query({ days })}`,
      { method: "POST" },
    ),

  rule: (ruleId: string) =>
    request<Record<string, unknown>>(`/api/v1/detection/rules/${encodeURIComponent(ruleId)}`),

  candidates: () => request<RuleCandidate[]>("/api/v1/detection/candidates"),

  createCandidate: (body: { name: string; source: string; description?: string }) =>
    request<RuleCandidate>("/api/v1/detection/candidates", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  benchmarkCandidate: (id: string) =>
    request<Record<string, unknown>>(`/api/v1/detection/candidates/${id}/benchmark`, {
      method: "POST",
    }),

  submitCandidate: (id: string) =>
    request<RuleCandidate>(`/api/v1/detection/candidates/${id}/submit`, { method: "POST" }),

  reviewCandidate: (id: string, body: { approve: boolean; comment?: string }) =>
    request<RuleCandidate>(`/api/v1/detection/candidates/${id}/review`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  releases: () => request<DetectionRelease[]>("/api/v1/detection/releases"),

  publishRelease: (body: { candidate_id?: string; note?: string }) =>
    request<DetectionRelease>("/api/v1/detection/releases", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  reanalysisJobs: () => request<ReanalysisJob[]>("/api/v1/reanalysis/jobs"),

  createReanalysisJob: (body: {
    days?: number;
    dry_run: boolean;
    max_messages?: number;
    filters?: Record<string, string>;
  }) =>
    request<ReanalysisJob>("/api/v1/reanalysis/jobs", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  runReanalysisJob: (id: string, slices = 20) =>
    request<ReanalysisJob>(`/api/v1/reanalysis/jobs/${id}/run${query({ slices })}`, {
      method: "POST",
    }),

  pauseReanalysisJob: (id: string) =>
    request<ReanalysisJob>(`/api/v1/reanalysis/jobs/${id}/pause`, { method: "POST" }),

  cancelReanalysisJob: (id: string) =>
    request<ReanalysisJob>(`/api/v1/reanalysis/jobs/${id}/cancel`, { method: "POST" }),

  messageGraph: (messageId: string) =>
    request<{
      nodes: { id: string; kind: string; label: string; detail: Record<string, unknown> }[];
      edges: { source: string; target: string; kind: string; label: string }[];
      truncated: string[];
      complete: boolean;
    }>(`/api/v1/investigations/messages/${encodeURIComponent(messageId)}/graph`),

  relatedMessages: (messageId: string, days = 90) =>
    request<Record<string, unknown>[]>(
      `/api/v1/investigations/messages/${encodeURIComponent(messageId)}/related${query({ days })}`,
    ),

  analysisFeedback: (analysisId: string, body: Record<string, unknown>) =>
    request<Record<string, unknown>>(`/api/v1/analysis/${analysisId}/feedback`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  analysisRevisions: (analysisId: string) =>
    request<Record<string, unknown>[]>(`/api/v1/analysis/${analysisId}/revisions`),

  detectionGaps: (status?: string) =>
    request<DetectionGap[]>(`/api/v1/detection/gaps${query({ status })}`),

  updateGap: (gapId: string, body: { status: string; note?: string }) =>
    request<DetectionGap>(`/api/v1/detection/gaps/${encodeURIComponent(gapId)}/status`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  threatScenarios: () => request<ThreatScenarioView[]>("/api/v1/detection/scenarios"),

  detectionQuality: (days = 30) =>
    request<DetectionQuality>(`/api/v1/detection/quality${query({ days })}`),

  shadowRules: (days = 30) =>
    request<Record<string, unknown>[]>(`/api/v1/detection/shadow${query({ days })}`),

  detectionVersions: () => request<Record<string, unknown>>("/api/v1/detection/versions"),

  markNotificationRead: (id: string) =>
    request<void>(`/api/v1/notifications/${encodeURIComponent(id)}/read`, { method: "POST" }),
};
