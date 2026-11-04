import {
  AtSign,
  FileDigit,
  Globe,
  Link2,
  Lock,
  Network,
  ScrollText,
  ShieldCheck,
  Server,
  type LucideIcon,
} from "lucide-react";
import type {
  Assurance,
  Classification,
  Freshness,
  IndicatorType,
  RunStatus,
  Severity,
  Tier,
  TLP,
  Verdict,
} from "../api/types";
import { pretty } from "../lib/format";

const cls = (...parts: (string | false | undefined)[]) => parts.filter(Boolean).join(" ");

export const TYPE_ICON: Record<IndicatorType, LucideIcon> = {
  domain: Globe,
  ip: Server,
  url: Link2,
  hash: FileDigit,
  certificate: ScrollText,
  asn: Network,
  email: AtSign,
};

export const TYPE_COLOR: Record<IndicatorType, string> = {
  domain: "#38bdf8",
  ip: "#a78bfa",
  url: "#f472b6",
  hash: "#fb923c",
  certificate: "#2dd4bf",
  asn: "#94a3b8",
  email: "#facc15",
};

export function TypeBadge({ type }: { type: IndicatorType }) {
  const Icon = TYPE_ICON[type];
  return (
    <span className="badge border-ink-500 bg-ink-700 text-fg-muted" title={type}>
      <Icon size={12} style={{ color: TYPE_COLOR[type] }} aria-hidden />
      {type}
    </span>
  );
}

const VERDICT: Record<Verdict, { label: string; style: string }> = {
  malicious: { label: "Malicious", style: "border-danger/60 bg-danger/15 text-danger" },
  suspicious: { label: "Suspicious", style: "border-orange-400/60 bg-orange-400/10 text-orange-300" },
  low_risk: { label: "Low risk", style: "border-yellow-400/50 bg-yellow-400/10 text-yellow-300" },
  no_detections: { label: "No detections", style: "border-emerald-400/50 bg-emerald-400/10 text-emerald-300" },
  unknown: { label: "Unknown", style: "border-ink-500 bg-ink-700 text-fg-muted" },
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const v = VERDICT[verdict];
  return (
    <span
      className={cls("badge", v.style)}
      title={
        verdict === "unknown"
          ? "No determination. Unknown is not the same as safe."
          : verdict === "no_detections"
            ? "A source reported nothing malicious. Absence of detections is not proof of safety."
            : undefined
      }
    >
      {v.label}
    </span>
  );
}

const ASSURANCE: Record<Assurance, { label: string; style: string; hint: string }> = {
  verified: {
    label: "Verified",
    style: "border-verified/50 bg-verified/10 text-verified",
    hint: "Observed first-hand from the source of record, or computed locally.",
  },
  provider_claim: {
    label: "Provider claim",
    style: "border-claim/50 bg-claim/10 text-claim",
    hint: "Asserted by a third-party service. Attributed, not independently confirmed.",
  },
  inferred: {
    label: "Inferred",
    style: "border-inferred/50 bg-inferred/10 text-inferred",
    hint: "Derived by HunterIntel from other data. A lead, not proof.",
  },
};

export function AssuranceBadge({ assurance }: { assurance: Assurance }) {
  const a = ASSURANCE[assurance];
  return (
    <span className={cls("badge", a.style)} title={a.hint}>
      {a.label}
    </span>
  );
}

export const ASSURANCE_COLOR: Record<Assurance, string> = {
  verified: "#34d399",
  provider_claim: "#60a5fa",
  inferred: "#fbbf24",
};

const STATUS: Record<RunStatus, { label: string; style: string }> = {
  ok: { label: "OK", style: "border-verified/40 text-verified" },
  no_data: { label: "No data", style: "border-ink-500 text-fg-muted" },
  not_configured: { label: "Not configured", style: "border-ink-500 text-fg-dim" },
  blocked: { label: "Blocked by policy", style: "border-orange-400/50 text-orange-300" },
  rate_limited: { label: "Rate limited", style: "border-yellow-400/50 text-yellow-300" },
  timeout: { label: "Timed out", style: "border-yellow-400/50 text-yellow-300" },
  error: { label: "Error", style: "border-danger/50 text-danger" },
};

export function StatusBadge({ status }: { status: RunStatus }) {
  const s = STATUS[status];
  return <span className={cls("badge bg-transparent", s.style)}>{s.label}</span>;
}

export function TierBadge({ tier }: { tier: Tier }) {
  const map: Record<Tier, { label: string; style: string; hint: string }> = {
    local: { label: "Local", style: "text-verified border-verified/30", hint: "Nothing leaves this host." },
    public: { label: "Public source", style: "text-accent border-accent/30", hint: "Keyless public infrastructure (DNS, RDAP, CT)." },
    third_party: { label: "Third party", style: "text-orange-300 border-orange-300/30", hint: "Keyed vendor: the indicator is sent to them." },
    active: { label: "Active probe", style: "text-danger border-danger/40", hint: "Contacts the target directly." },
  };
  const t = map[tier];
  return (
    <span className={cls("badge bg-transparent", t.style)} title={t.hint}>
      {t.label}
    </span>
  );
}

export function FreshnessBadge({ freshness }: { freshness: Freshness }) {
  const map: Record<Freshness, string> = {
    fresh: "text-verified border-verified/30",
    aging: "text-fg-muted border-ink-500",
    stale: "text-yellow-300 border-yellow-400/40",
    expired: "text-danger border-danger/40",
  };
  return <span className={cls("badge bg-transparent", map[freshness])}>{freshness}</span>;
}

export function ClassBadge({ value }: { value: Classification }) {
  if (value === "unclassified") return null;
  const map: Record<Exclude<Classification, "unclassified">, string> = {
    benign: "text-emerald-300 border-emerald-400/40",
    suspicious: "text-orange-300 border-orange-400/40",
    malicious: "text-danger border-danger/50",
    false_positive: "text-fg-muted border-ink-500",
  };
  return <span className={cls("badge bg-transparent", map[value])}>analyst: {pretty(value)}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const map: Record<Severity, string> = {
    info: "text-fg-muted border-ink-500",
    low: "text-sky-300 border-sky-400/40",
    medium: "text-yellow-300 border-yellow-400/40",
    high: "text-orange-300 border-orange-400/50",
    critical: "text-danger border-danger/60",
  };
  return <span className={cls("badge bg-transparent uppercase", map[severity])}>{severity}</span>;
}

export function TlpBadge({ tlp }: { tlp: TLP }) {
  const map: Record<TLP, string> = {
    clear: "text-white",
    green: "text-[#33ff00]",
    amber: "text-[#ffc000]",
    amber_strict: "text-[#ffc000]",
    red: "text-[#ff2b2b]",
  };
  return (
    <span className={cls("badge border-ink-500 bg-black font-mono font-bold uppercase", map[tlp])}>
      TLP:{tlp.replace("_", "+")}
    </span>
  );
}

export function LockBadge() {
  return (
    <span className="badge border-orange-400/40 bg-orange-400/10 text-orange-300" title="Never sent to third parties">
      <Lock size={11} aria-hidden /> do not share
    </span>
  );
}

export function VerifiedIcon() {
  return <ShieldCheck size={14} className="text-verified" aria-hidden />;
}
