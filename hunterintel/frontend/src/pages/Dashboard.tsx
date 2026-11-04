import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Verdict } from "../api/types";
import { StatusBadge, TlpBadge } from "../components/badges";
import { IndicatorTable } from "../components/IndicatorTable";
import { Empty, ErrorBox, Spinner, Stat } from "../components/ui";
import { timeAgo } from "../lib/format";

const VERDICTS: { id: Verdict; label: string; color: string }[] = [
  { id: "malicious", label: "Malicious", color: "#f87171" },
  { id: "suspicious", label: "Suspicious", color: "#fb923c" },
  { id: "low_risk", label: "Low risk", color: "#facc15" },
  { id: "no_detections", label: "No detections", color: "#34d399" },
  { id: "unknown", label: "Unknown", color: "#617086" },
];

// Real, public, well-known indicators to try. Nothing here is a claim about maliciousness.
const EXAMPLES = [
  { label: "example.com", value: "example.com", hint: "IANA reserved domain" },
  { label: "1.1.1.1", value: "1.1.1.1", hint: "Public DNS resolver" },
  { label: "AS13335", value: "AS13335", hint: "Autonomous system" },
  {
    label: "EICAR test file (SHA-256)",
    value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    hint: "Standard anti-malware test file",
  },
];

export function Dashboard() {
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats });
  if (stats.isPending) return <Spinner />;
  if (stats.isError) return <ErrorBox error={stats.error} />;
  const s = stats.data;
  const total = s.indicators.total;
  const hot = (s.indicators.by_verdict.malicious ?? 0) + (s.indicators.by_verdict.suspicious ?? 0);

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Tracked indicators" value={total} />
        <Stat label="Malicious / suspicious" value={<span className={hot ? "text-danger" : ""}>{hot}</span>} hint="active (non-expired) only" />
        <Stat label="Expired" value={s.indicators.expired} hint="excluded from assessment" />
        <Stat
          label="Providers ready"
          value={`${s.providers.configured.length}/${s.providers.configured.length + s.providers.unconfigured.length}`}
          hint="configured and usable"
        />
      </div>

      {total === 0 && (
        <div className="card p-6">
          <h2 className="text-base font-semibold">Start an investigation</h2>
          <p className="mt-1 max-w-2xl text-xs text-fg-muted">
            Search above for a domain, IP, URL, file hash, AS number or e-mail address. You will see exactly which sources would
            receive it before anything is sent. No API keys are needed for DNS, RDAP, certificate transparency and local analysis.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {EXAMPLES.map((e) => (
              <Link key={e.value} to={`/lookup?value=${encodeURIComponent(e.value)}`} className="btn" title={e.hint}>
                {e.label}
              </Link>
            ))}
          </div>
        </div>
      )}

      {total > 0 && (
        <div className="card p-4">
          <div className="h-label mb-2">Verdict distribution (active indicators)</div>
          <div className="flex h-3 overflow-hidden rounded bg-ink-700" role="img" aria-label="Verdict distribution">
            {VERDICTS.map((v) => {
              const n = s.indicators.by_verdict[v.id] ?? 0;
              return n > 0 ? <div key={v.id} style={{ width: `${(n / Math.max(total - s.indicators.expired, 1)) * 100}%`, background: v.color }} title={`${v.label}: ${n}`} /> : null;
            })}
          </div>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-muted">
            {VERDICTS.map((v) => (
              <span key={v.id} className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={{ background: v.color }} /> {v.label} {s.indicators.by_verdict[v.id] ?? 0}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="grid gap-5 xl:grid-cols-3">
        <section className="card xl:col-span-2">
          <div className="card-h">
            <h2 className="text-sm font-semibold">Recent indicators</h2>
            <Link to="/indicators" className="text-xs text-accent hover:underline">
              all indicators
            </Link>
          </div>
          {s.recent_indicators.length === 0 ? <Empty title="Nothing here yet">Searched indicators appear here.</Empty> : <IndicatorTable items={s.recent_indicators} compact />}
        </section>

        <div className="space-y-5">
          <section className="card">
            <div className="card-h">
              <h2 className="text-sm font-semibold">Investigations</h2>
              <Link to="/investigations" className="text-xs text-accent hover:underline">
                open
              </Link>
            </div>
            {s.recent_investigations.length === 0 ? (
              <Empty title="No investigations" />
            ) : (
              <ul className="divide-y divide-ink-600/40">
                {s.recent_investigations.map((i) => (
                  <li key={i.id} className="flex items-center justify-between gap-2 px-4 py-2.5">
                    <Link to={`/investigations/${i.id}`} className="min-w-0 truncate hover:text-accent">
                      {i.title}
                    </Link>
                    <span className="flex shrink-0 items-center gap-2">
                      <TlpBadge tlp={i.tlp} />
                      <span className="text-xs text-fg-dim">{timeAgo(i.updated_at)}</span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card">
            <div className="card-h">
              <h2 className="text-sm font-semibold">Recent provider problems</h2>
            </div>
            {s.recent_failures.length === 0 ? (
              <Empty title="No recent failures" />
            ) : (
              <ul className="divide-y divide-ink-600/40 text-xs">
                {s.recent_failures.map((f, i) => (
                  <li key={i} className="space-y-1 px-4 py-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="mono">{f.provider}</span>
                      <StatusBadge status={f.status} />
                    </div>
                    <div className="text-fg-muted">{f.message}</div>
                    <div className="mono truncate text-fg-dim">{f.indicator}</div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
