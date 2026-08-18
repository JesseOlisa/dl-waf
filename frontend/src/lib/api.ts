import { getToken, logout } from "@/lib/auth";

export interface SummaryStats {
  total_requests: number;
  blocked: number;
  allowed: number;
  attacks_succeeded: number;
  detection_rate: number;
}

export interface TrafficPoint {
  timestamp: string;
  legitimate: number;
  malicious: number;
}

export interface AttackStat {
  attack_type: string;
  count: number;
}

export interface EventItem {
  event_id: number;
  timestamp: string;
  source_ip: string | null;
  http_method: string | null;
  request_uri: string | null;
  classification: number;
  confidence_score: number;
  attack_type: string | null;
  action_taken: string;
  payload_fragment: string | null;
  scenario_id: string | null;
  latency_ms: number | null;
  waf_enabled: number | null;
}

export interface EventsResponse {
  items: EventItem[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface EventFilters {
  page?: number;
  page_size?: number;
  classification?: number;
  attack_type?: string;
  start_time?: string;
  end_time?: string;
  source_ip?: string;
}

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(path, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (res.status === 401) {
    logout();
    throw new Error("Unauthorised");
  }
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<T>;
}

async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${getToken()}`,
      "Content-Type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) {
    logout();
    throw new Error("Unauthorised");
  }
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<T>;
}

function buildQs(params: Record<string, unknown>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  }
  return q.toString();
}

export const fetchSummary = () => apiFetch<SummaryStats>("/api/stats/summary");

export const fetchTraffic = (hours: number) =>
  apiFetch<TrafficPoint[]>(`/api/stats/traffic?hours=${hours}`);

export const fetchAttacks = () => apiFetch<AttackStat[]>("/api/stats/attacks");

export const fetchEvents = (filters: EventFilters = {}) => {
  const qs = buildQs(filters as Record<string, unknown>);
  return apiFetch<EventsResponse>(`/api/events${qs ? `?${qs}` : ""}`);
};

export const fetchEventById = (id: number) =>
  apiFetch<EventItem>(`/api/events/${id}`);

// ── WAF kill-switch ────────────────────────────────────────────────────────────

export interface WafStatus {
  enabled: boolean;
  updated_at: string | null;
  updated_by: string | null;
}

export interface WafAuditItem {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  note: string | null;
}

export const fetchWafStatus = () => apiFetch<WafStatus>("/api/waf/status");

export const toggleWaf = (enabled: boolean, note?: string) =>
  apiPost<WafStatus>("/api/waf/toggle", { enabled, note });

export const fetchWafAudit = (limit = 50) =>
  apiFetch<WafAuditItem[]>(`/api/waf/audit?limit=${limit}`);

// ── Attack simulation ──────────────────────────────────────────────────────────

export interface Scenario {
  id: string;
  category: string;
  title: string;
  level: number;
  description: string;
  method: string;
  target_uri: string;
  payload: string;
  param_name: string;
  expected_classification: number;
  expected_evades: boolean;
}

export interface ModelVerdict {
  label: number;
  confidence: number;
  threshold: number;
}

export interface SignatureVerdict {
  matched: boolean;
  category: string | null;
  pattern: string | null;
}

export interface Consequence {
  kind: string; // "rows" | "cookie" | "defacement" | "boolean_leak" | "none"
  title: string;
  summary: string | null;
  columns: string[] | null;
  rows: (string | number)[][] | null;
  cookie: string | null;
  defaced_html: string | null;
  detail: string | null;
}

export interface RunResult {
  scenario_id: string;
  category: string;
  title: string;
  level: number;
  waf_enabled: boolean;
  raw_request: string;
  model: ModelVerdict;
  signature: SignatureVerdict;
  final_label: number;
  blocked_by: string | null;
  latency_ms: number;
  verdict: string; // "BLOCKED" | "ALLOWED"
  outcome: string; // "attack_blocked" | "attack_succeeded" | "legitimate_allowed"
  event_id: number;
  consequence: Consequence | null;
}

export interface CampaignSummary {
  total: number;
  blocked: number;
  succeeded: number;
  legitimate_allowed: number;
}

export interface CampaignResult {
  results: RunResult[];
  summary: CampaignSummary;
}

export function blockedByLabel(blockedBy: string | null): string {
  switch (blockedBy) {
    case "both":
      return "both detection layers";
    case "model":
      return "the deep-learning model";
    case "signature":
      return "the signature layer";
    default:
      return "the WAF";
  }
}

export const fetchScenarios = () => apiFetch<Scenario[]>("/api/sim/scenarios");

export const runScenario = (scenario_id: string) =>
  apiPost<RunResult>("/api/sim/run", { scenario_id });

export const runCampaign = (include_baseline = true) =>
  apiPost<CampaignResult>("/api/sim/campaign", { include_baseline });

export const resetSim = () =>
  apiPost<{ status: string; seeded_at: string }>("/api/sim/reset");

// ── Staff workstation (open endpoints — staff traffic, not SOC-authed) ──────────

export interface StaffFieldSpec {
  name: string;
  label: string;
  type: string;
  risky: boolean;
}

export interface StaffVariant {
  id: string;
  variant_id: string;
  kind: string; // "legitimate" | "malicious"
  label: string;
  category: string;
  title: string;
  fields: Record<string, string>;
  highlight: string | null;
}

export interface StaffTask {
  id: string;
  title: string;
  icon: string;
  blurb: string;
  fields: StaffFieldSpec[];
  variants: StaffVariant[];
}

async function openFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init);
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<T>;
}

export const fetchStaffProtection = () =>
  openFetch<WafStatus>("/api/staff/protection");

export const fetchStaffTasks = () => openFetch<StaffTask[]>("/api/staff/tasks");

export const runStaffVariant = (variant_id: string) =>
  openFetch<RunResult>("/api/staff/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ variant_id }),
  });
