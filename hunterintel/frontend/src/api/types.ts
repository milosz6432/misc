export type IndicatorType = "domain" | "ip" | "url" | "hash" | "certificate" | "asn" | "email";
export type Assurance = "verified" | "provider_claim" | "inferred";
export type Verdict = "malicious" | "suspicious" | "low_risk" | "no_detections" | "unknown";
export type RunStatus =
  | "ok"
  | "no_data"
  | "not_configured"
  | "blocked"
  | "rate_limited"
  | "timeout"
  | "error";
export type Tier = "local" | "public" | "third_party" | "active";
export type Freshness = "fresh" | "aging" | "stale" | "expired";
export type Classification = "unclassified" | "benign" | "suspicious" | "malicious" | "false_positive";
export type TLP = "clear" | "green" | "amber" | "amber_strict" | "red";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Health {
  status: string;
  version: string;
  auth_required: boolean;
  redis: boolean;
  active_probes_enabled: boolean;
  default_sharing: Tier;
}

export interface ProviderInfo {
  name: string;
  display_name: string;
  description: string;
  tier: Tier;
  supported_types: IndicatorType[];
  requires_key: boolean;
  key_env: string | null;
  configured: boolean;
  homepage: string;
  terms_url: string;
  reliability: number;
  rate_limit: { requests: number; per_seconds: number } | null;
}

export interface PlanEntry {
  provider: string;
  display_name: string;
  tier: Tier;
  state: "available" | "blocked" | "not_configured";
  selected_by_default: boolean;
  reason: string | null;
  data_shared: string;
  description: string;
}

export interface IndicatorSummary {
  id: number;
  type: IndicatorType;
  subtype: string | null;
  value: string;
  tracked: boolean;
  verdict: Verdict;
  risk_score: number | null;
  confidence: number | null;
  classification: Classification;
  do_not_share: boolean;
  freshness: Freshness;
  first_seen: string;
  last_seen: string;
  expires_at: string;
  last_enriched_at: string | null;
  tags: string[];
}

export interface Classified {
  indicator: {
    type: IndicatorType;
    value: string;
    subtype: string | null;
    raw: string;
    scope: string;
    remote_lookup_allowed: boolean;
    blocked_reason: string | null;
    sensitive: boolean;
    notes: string[];
  };
  known: IndicatorSummary | null;
  plan: PlanEntry[];
}

export interface BreakdownItem {
  kind: "reputation" | "heuristic";
  source: string;
  assurance: Assurance;
  verdict: string;
  label: string;
  strength: number;
  reliability: number | null;
  freshness?: Freshness;
  freshness_factor?: number;
  weight: number;
  definitive: boolean;
}

export interface RiskFlag {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  source: string;
  assurance: Assurance;
}

export interface Assessment {
  risk_score: number | null;
  confidence: number;
  verdict: Verdict;
  freshness: Freshness;
  freshness_ratio: number;
  expires_at: string;
  breakdown: BreakdownItem[];
  risk_flags: RiskFlag[];
  sources: string[];
  conflict: boolean;
  explanation: string;
}

export interface Observation {
  id: number;
  indicator_id: number;
  provider: string;
  kind: string;
  assurance: Assurance;
  title: string;
  summary: string | null;
  data: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  seen_count: number;
  history_count?: number;
}

export interface ProviderRun {
  id?: number;
  provider: string;
  status: RunStatus;
  message: string | null;
  started_at: string;
  duration_ms: number;
  observation_count: number;
  truncated: boolean;
}

export interface IndicatorDetail extends IndicatorSummary {
  lookup_policy: { remote_lookup_allowed: boolean; blocked_reason: string | null; scope: string };
  assessment: Assessment;
  tag_details: { tag: string; sources: string[]; analyst: boolean }[];
  observations: Observation[];
  provider_runs: ProviderRun[];
  plan: PlanEntry[];
  investigations: { id: number; title: string }[];
  relationship_count: number;
}

export interface EnrichResult {
  indicator: IndicatorDetail;
  runs: { provider: string; status: RunStatus; message: string | null; duration_ms: number; observations: number; truncated: boolean }[];
  new_observations: number;
  relationships_stored: number;
}

export interface GraphNode {
  id: number;
  type: IndicatorType;
  value: string;
  label: string;
  tracked: boolean;
  is_root: boolean;
  verdict: Verdict;
  risk_score: number | null;
  classification: Classification;
  degree: number;
}

export interface GraphEdge {
  source: number;
  target: number;
  rel_type: string;
  assurance: Assurance;
  evidence: { source: string; assurance: Assurance; last_seen: string | null }[];
  attrs: Record<string, unknown>;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  root_ids: number[];
  truncated: boolean;
  stats: { nodes: number; edges: number; inferred_edges: number; max_nodes: number };
}

export interface Stats {
  indicators: { by_type: Record<string, number>; by_verdict: Record<string, number>; expired: number; total: number };
  recent_indicators: IndicatorSummary[];
  recent_failures: { provider: string; status: RunStatus; message: string | null; indicator: string; at: string }[];
  recent_investigations: { id: number; title: string; status: string; tlp: TLP; updated_at: string }[];
  providers: { configured: string[]; unconfigured: string[] };
}

export interface Paged<T> {
  total: number;
  limit: number;
  offset: number;
  items: T[];
}

export interface InvestigationRow {
  id: number;
  title: string;
  description: string;
  status: "open" | "closed";
  tlp: TLP;
  indicator_count: number;
  finding_count: number;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: number;
  investigation_id: number;
  indicator_id: number | null;
  observation_id: number | null;
  title: string;
  body: string;
  severity: Severity;
  snapshot: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface Note {
  id: number;
  investigation_id: number;
  indicator_id: number | null;
  body: string;
  author: string;
  created_at: string;
  updated_at: string;
}

export interface InvestigationDetail {
  id: number;
  title: string;
  description: string;
  status: "open" | "closed";
  tlp: TLP;
  created_at: string;
  updated_at: string;
  indicators: {
    id: number;
    type: IndicatorType;
    value: string;
    verdict: Verdict;
    risk_score: number | null;
    confidence: number | null;
    classification: Classification;
    do_not_share: boolean;
    added_at: string;
  }[];
  findings: Finding[];
  notes: Note[];
}

export interface Comparison {
  indicators: {
    id: number;
    type: IndicatorType;
    value: string;
    verdict: Verdict;
    risk_score: number | null;
    confidence: number | null;
    classification: Classification;
    tags: string[];
    attributes: Record<string, unknown>;
    facets: Record<string, string[]>;
  }[];
  shared: {
    facet: string;
    value: string;
    indicator_ids: number[];
    strength: "weak" | "medium" | "strong";
    assurance: Assurance;
    caveat: string;
  }[];
  pairwise: { a: number; b: number; shared: number; jaccard: number }[];
  note: string;
}

export interface FileHashResult {
  filename: string | null;
  size: number;
  md5: string;
  sha1: string;
  sha256: string;
  file_type: { type: string; mime: string; basis: string; note: string };
  privacy: string;
}
