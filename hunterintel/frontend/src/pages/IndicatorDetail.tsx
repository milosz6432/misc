import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BookmarkPlus, ChevronDown, ChevronRight, Play, RefreshCw, Trash2, X } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { Classification, IndicatorDetail, Observation, PlanEntry, RunStatus, Severity } from "../api/types";
import { AssuranceBadge, ClassBadge, FreshnessBadge, LockBadge, SeverityBadge, StatusBadge, TierBadge, TypeBadge, VerdictBadge } from "../components/badges";
import { DataView } from "../components/DataView";
import { GraphView } from "../components/GraphView";
import { QueryPlan, defaultSelection } from "../components/QueryPlan";
import { RiskMeter } from "../components/RiskMeter";
import { CopyButton, Empty, ErrorBox, Modal, Notice, Spinner, Tabs } from "../components/ui";
import { extractFacts } from "../lib/facts";
import { defang, formatDate, pretty, timeAgo } from "../lib/format";

type Tab = "overview" | "providers" | "graph" | "history";
const CLASSES: Classification[] = ["unclassified", "benign", "suspicious", "malicious", "false_positive"];

export function IndicatorDetailPage() {
  const id = Number(useParams().id);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("overview");
  const [modal, setModal] = useState<null | "enrich" | "investigation" | "delete">(null);

  const q = useQuery({ queryKey: ["indicator", id], queryFn: () => api.indicator(id), enabled: Number.isFinite(id) });
  const remove = useMutation({
    mutationFn: () => api.deleteIndicator(id),
    onSuccess: () => {
      void qc.invalidateQueries();
      navigate("/indicators");
    },
  });

  if (q.isPending) return <Spinner />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const ind = q.data;
  const a = ind.assessment;

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <header className="card p-4">
        <div className="flex flex-wrap items-center gap-2">
          <TypeBadge type={ind.type} />
          <VerdictBadge verdict={ind.verdict} />
          <FreshnessBadge freshness={a.freshness} />
          <ClassBadge value={ind.classification} />
          {ind.do_not_share && <LockBadge />}
          {!ind.tracked && <span className="badge border-ink-500 text-fg-dim">discovered, not adopted</span>}
        </div>
        <div className="mt-2 flex items-start gap-1">
          <h1 className="mono break-all text-lg font-semibold">{ind.value}</h1>
          <CopyButton text={ind.value} label="Copy value" />
          <button className="btn btn-ghost px-1.5 py-1 text-[11px] text-fg-muted" title="Copy defanged" onClick={() => void navigator.clipboard.writeText(defang(ind.value, ind.type))}>
            defang
          </button>
        </div>
        <div className="mt-1 flex flex-wrap gap-x-5 gap-y-1 text-xs text-fg-muted">
          <span>first seen {formatDate(ind.first_seen)}</span>
          <span>last seen {timeAgo(ind.last_seen)}</span>
          <span>expires {formatDate(ind.expires_at)}</span>
          <span>last enriched {ind.last_enriched_at ? timeAgo(ind.last_enriched_at) : "never"}</span>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="btn btn-primary" onClick={() => setModal("enrich")}>
            <Play size={13} /> Enrich…
          </button>
          <button className="btn" onClick={() => setModal("investigation")}>
            <BookmarkPlus size={13} /> Add to investigation
          </button>
          <button className="btn btn-danger ml-auto" onClick={() => setModal("delete")}>
            <Trash2 size={13} /> Delete
          </button>
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Tabs
            value={tab}
            onChange={setTab}
            tabs={[
              { id: "overview", label: "Overview" },
              { id: "providers", label: "Provider results", count: ind.observations.length },
              { id: "graph", label: "Relationships", count: ind.relationship_count },
              { id: "history", label: "History" },
            ]}
          />
          {tab === "overview" && <Overview ind={ind} />}
          {tab === "providers" && <ProviderResults ind={ind} onEnrich={() => setModal("enrich")} />}
          {tab === "graph" && <GraphTab id={ind.id} />}
          {tab === "history" && <History id={ind.id} />}
        </div>
        <aside className="space-y-4">
          <AssessmentCard ind={ind} />
          <AnalystCard ind={ind} />
        </aside>
      </div>

      {modal === "enrich" && <EnrichModal ind={ind} onClose={() => setModal(null)} />}
      {modal === "investigation" && <AddToInvestigationModal ind={ind} onClose={() => setModal(null)} />}
      {modal === "delete" && (
        <Modal title="Delete indicator?" onClose={() => setModal(null)}>
          <p className="mb-3 text-xs text-fg-muted">
            This removes the indicator with all its observations, history and relationships. Findings that referenced it are kept (with their evidence snapshots).
          </p>
          {remove.isError && <ErrorBox error={remove.error} />}
          <div className="flex gap-2">
            <button className="btn btn-danger" onClick={() => remove.mutate()} disabled={remove.isPending}>
              Delete permanently
            </button>
            <button className="btn" onClick={() => setModal(null)}>
              Cancel
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ── overview ─────────────────────────────────────────────────────────────────

function unavailable(ind: IndicatorDetail): { provider: string; status: RunStatus; message: string | null }[] {
  const out = ind.provider_runs.filter((r) => r.status !== "ok").map((r) => ({ provider: r.provider, status: r.status, message: r.message }));
  const ran = new Set(ind.provider_runs.map((r) => r.provider));
  for (const p of ind.plan) {
    if (!ran.has(p.provider) && p.state !== "available") {
      out.push({ provider: p.provider, status: p.state === "blocked" ? "blocked" : "not_configured", message: p.reason });
    }
  }
  return out;
}

function Overview({ ind }: { ind: IndicatorDetail }) {
  const facts = useMemo(() => extractFacts(ind.observations), [ind.observations]);
  const gaps = unavailable(ind);
  const notRun = ind.plan.filter((p) => p.state === "available" && !ind.provider_runs.some((r) => r.provider === p.provider));

  return (
    <div className="space-y-4">
      {!ind.lookup_policy.remote_lookup_allowed && (
        <Notice tone="warn">
          <strong>Local analysis only.</strong> {ind.lookup_policy.blocked_reason}
        </Notice>
      )}
      <section className="card">
        <div className="card-h">
          <h2 className="text-sm font-semibold">Key facts</h2>
          <span className="text-[11px] text-fg-dim">each fact shows where it came from</span>
        </div>
        {facts.length === 0 ? (
          <Empty title="No facts yet">Run an enrichment to collect evidence.</Empty>
        ) : (
          <ul className="divide-y divide-ink-600/40">
            {facts.map((f, i) => (
              <li key={i} className="grid grid-cols-[9.5rem_1fr_auto] items-start gap-3 px-4 py-2">
                <span className="pt-0.5 text-xs text-fg-muted">{f.label}</span>
                <div className="min-w-0">
                  <span className="mono break-words text-[13px]">{f.value}</span>
                  {f.note && <div className="mt-0.5 text-[11px] text-fg-dim">{f.note}</div>}
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  <span className="mono text-[11px] text-fg-dim">{f.source}</span>
                  <AssuranceBadge assurance={f.assurance} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {ind.assessment.risk_flags.length > 0 && (
        <section className="card">
          <div className="card-h">
            <h2 className="text-sm font-semibold">Risk indicators</h2>
            <span className="text-[11px] text-fg-dim">heuristics — leads, not proof</span>
          </div>
          <ul className="divide-y divide-ink-600/40">
            {ind.assessment.risk_flags.map((f) => (
              <li key={`${f.source}-${f.id}`} className="flex items-start gap-3 px-4 py-2.5">
                <SeverityBadge severity={f.severity} />
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium">{f.title}</div>
                  <div className="text-xs text-fg-muted">{f.detail}</div>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1">
                  <AssuranceBadge assurance={f.assurance} />
                  <span className="mono text-[11px] text-fg-dim">{f.source}</span>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="card">
        <div className="card-h">
          <h2 className="text-sm font-semibold">Unavailable information</h2>
          <span className="text-[11px] text-fg-dim">gaps are shown, never hidden</span>
        </div>
        {gaps.length === 0 && notRun.length === 0 ? (
          <Empty title="Every applicable source answered." />
        ) : (
          <ul className="divide-y divide-ink-600/40">
            {gaps.map((g) => (
              <li key={g.provider} className="flex flex-wrap items-center gap-3 px-4 py-2.5">
                <span className="mono w-28 shrink-0 text-xs">{g.provider}</span>
                <StatusBadge status={g.status} />
                <span className="min-w-0 flex-1 text-xs text-fg-muted">{g.message}</span>
              </li>
            ))}
            {notRun.map((p) => (
              <li key={p.provider} className="flex flex-wrap items-center gap-3 px-4 py-2.5">
                <span className="mono w-28 shrink-0 text-xs">{p.provider}</span>
                <span className="badge border-ink-500 text-fg-muted">not run yet</span>
                <span className="min-w-0 flex-1 text-xs text-fg-muted">Available — select it under “Enrich…”.</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

// ── provider results ─────────────────────────────────────────────────────────

function ProviderResults({ ind, onEnrich }: { ind: IndicatorDetail; onEnrich: () => void }) {
  const [saving, setSaving] = useState<Observation | null>(null);
  const runs = new Map(ind.provider_runs.map((r) => [r.provider, r]));
  return (
    <div className="space-y-3">
      {ind.plan.map((p) => {
        const run = runs.get(p.provider);
        const obs = ind.observations.filter((o) => o.provider === p.provider);
        return (
          <section key={p.provider} className={`card ${!run && obs.length === 0 ? "opacity-75" : ""}`}>
            <div className="card-h">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-sm font-semibold">{p.display_name}</h3>
                <TierBadge tier={p.tier} />
              </div>
              <div className="flex items-center gap-2 text-xs text-fg-dim">
                {run ? (
                  <>
                    <StatusBadge status={run.status} />
                    <span title={run.started_at}>{timeAgo(run.started_at)} · {run.duration_ms} ms</span>
                  </>
                ) : (
                  <span className="badge border-ink-500">{p.state === "available" ? "not run" : p.state.replace("_", " ")}</span>
                )}
              </div>
            </div>
            {run && run.status !== "ok" && <div className="px-4 py-2.5 text-xs text-fg-muted">{run.message}</div>}
            {!run && p.state !== "available" && <div className="px-4 py-2.5 text-xs text-fg-muted">{p.reason}</div>}
            {!run && p.state === "available" && (
              <div className="flex items-center justify-between px-4 py-2.5 text-xs text-fg-muted">
                <span>{p.description}</span>
                <button className="btn" onClick={onEnrich}>Select…</button>
              </div>
            )}
            {run?.truncated && <div className="px-4 pt-2.5 text-xs text-orange-300">Result was truncated (size or count limits).</div>}
            <div className="divide-y divide-ink-600/40">
              {obs.map((o) => (
                <ObservationRow key={o.id} o={o} onSave={() => setSaving(o)} />
              ))}
            </div>
          </section>
        );
      })}
      {saving && <SaveFindingModal ind={ind} obs={saving} onClose={() => setSaving(null)} />}
    </div>
  );
}

function ObservationRow({ o, onSave }: { o: Observation; onSave: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="px-4 py-2.5">
      <div className="flex items-start gap-2">
        <button className="mt-0.5 text-fg-muted hover:text-fg" onClick={() => setOpen(!open)} aria-expanded={open} aria-label={open ? "Collapse" : "Expand"}>
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-medium">{o.title}</span>
            <AssuranceBadge assurance={o.assurance} />
          </div>
          {o.summary && <div className="mt-0.5 break-words text-xs text-fg-muted">{o.summary}</div>}
          <div className="mt-0.5 text-[11px] text-fg-dim">
            last confirmed {timeAgo(o.last_seen)} · seen {o.seen_count}×{(o.history_count ?? 1) > 1 && ` · ${o.history_count} versions in history`}
          </div>
        </div>
        <button className="btn btn-ghost px-2 py-1 text-[11px]" onClick={onSave} title="Save as finding">
          <BookmarkPlus size={12} /> finding
        </button>
      </div>
      {open && (
        <div className="ml-6 mt-2 rounded-md border border-ink-600/70 bg-ink-900 p-3">
          <DataView data={o.data} />
        </div>
      )}
    </div>
  );
}

// ── relationships & history ──────────────────────────────────────────────────

function GraphTab({ id }: { id: number }) {
  const [depth, setDepth] = useState(2);
  const [inferred, setInferred] = useState(true);
  const g = useQuery({ queryKey: ["graph", id, depth, inferred], queryFn: () => api.graph(id, depth, inferred) });
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-xs text-fg-muted">
        <label className="flex items-center gap-2">
          Depth
          <select className="input w-auto py-1 text-xs" value={depth} onChange={(e) => setDepth(Number(e.target.value))}>
            {[1, 2, 3].map((d) => (<option key={d}>{d}</option>))}
          </select>
        </label>
        <label className="flex items-center gap-2">
          <input type="checkbox" className="accent-sky-400" checked={inferred} onChange={(e) => setInferred(e.target.checked)} />
          show inferred shared-infrastructure links
        </label>
      </div>
      {g.isPending ? <Spinner /> : g.isError ? <ErrorBox error={g.error} /> : <GraphView graph={g.data} />}
    </div>
  );
}

function History({ id }: { id: number }) {
  const obs = useQuery({ queryKey: ["history", id], queryFn: () => api.observations(id) });
  const runs = useQuery({ queryKey: ["runs", id], queryFn: () => api.runs(id) });
  const groups = useMemo(() => {
    const m = new Map<string, Observation[]>();
    for (const o of obs.data?.items ?? []) {
      const key = `${o.provider} · ${o.kind}`;
      m.set(key, [...(m.get(key) ?? []), o]);
    }
    return [...m.entries()];
  }, [obs.data]);

  return (
    <div className="space-y-4">
      <Notice>
        Observations are never overwritten. An unchanged fact only has its “last confirmed” time extended; a changed fact (a new DNS answer, a new
        verdict) becomes a new entry, so you can see how the picture evolved.
      </Notice>
      {obs.isPending ? <Spinner /> : obs.isError ? <ErrorBox error={obs.error} /> : groups.length === 0 ? <Empty title="No observations yet" /> : groups.map(([key, items]) => (
        <section key={key} className="card">
          <div className="card-h">
            <h3 className="mono text-xs">{key}</h3>
            <span className="text-[11px] text-fg-dim">{items.length} version{items.length === 1 ? "" : "s"}</span>
          </div>
          <ol className="divide-y divide-ink-600/40">
            {items.map((o, i) => (
              <HistoryItem key={o.id} o={o} current={i === 0} />
            ))}
          </ol>
        </section>
      ))}
      <section className="card">
        <div className="card-h"><h3 className="text-sm font-semibold">Provider run log</h3></div>
        {runs.data && (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr><th className="th">When</th><th className="th">Provider</th><th className="th">Status</th><th className="th">Detail</th></tr></thead>
              <tbody className="divide-y divide-ink-600/40">
                {runs.data.items.map((r, i) => (
                  <tr key={r.id ?? i}>
                    <td className="td whitespace-nowrap text-fg-muted">{formatDate(r.started_at)}</td>
                    <td className="td mono">{r.provider}</td>
                    <td className="td"><StatusBadge status={r.status} /></td>
                    <td className="td text-fg-muted">{r.message ?? `${r.observation_count} observation(s) · ${r.duration_ms} ms`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function HistoryItem({ o, current }: { o: Observation; current: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="px-4 py-2.5">
      <button className="flex w-full items-start gap-2 text-left" onClick={() => setOpen(!open)} aria-expanded={open}>
        {open ? <ChevronDown size={14} className="mt-0.5" /> : <ChevronRight size={14} className="mt-0.5" />}
        <span className="min-w-0 flex-1">
          <span className="text-[13px]">{o.summary ?? o.title}</span>
          <span className="mt-0.5 block text-[11px] text-fg-dim">
            {formatDate(o.first_seen)} → {formatDate(o.last_seen)} · confirmed {o.seen_count}×
          </span>
        </span>
        {current && <span className="badge border-accent/40 text-accent">latest</span>}
        <AssuranceBadge assurance={o.assurance} />
      </button>
      {open && (
        <div className="ml-6 mt-2 rounded-md border border-ink-600/70 bg-ink-900 p-3">
          <DataView data={o.data} />
        </div>
      )}
    </li>
  );
}

// ── side cards ───────────────────────────────────────────────────────────────

function AssessmentCard({ ind }: { ind: IndicatorDetail }) {
  const a = ind.assessment;
  return (
    <section className="card">
      <div className="card-h"><h2 className="text-sm font-semibold">Assessment</h2><VerdictBadge verdict={a.verdict} /></div>
      <div className="space-y-3 p-4">
        <div className="flex items-center justify-around">
          <RiskMeter score={a.risk_score} verdict={a.verdict} />
          <div className="text-center">
            <div className="text-2xl font-semibold tabular-nums" title={a.verdict === "unknown" ? "No determination was made, so there is nothing to be confident about." : undefined}>
              {a.verdict === "unknown" ? "—" : `${a.confidence}%`}
            </div>
            <div className="h-label">confidence</div>
          </div>
        </div>
        <p className="text-xs leading-relaxed text-fg-muted">{a.explanation}</p>
        {a.conflict && <Notice tone="warn">Sources disagree. Confidence is reduced; review each provider’s result.</Notice>}
        {a.freshness !== "fresh" && (
          <Notice tone={a.freshness === "expired" ? "danger" : "warn"}>
            Evidence is <strong>{a.freshness}</strong> (expires {formatDate(a.expires_at)}). Re-enrich to refresh it.
          </Notice>
        )}
        {a.breakdown.length > 0 && (
          <div>
            <div className="h-label mb-1.5">How this was scored</div>
            <ul className="space-y-1.5">
              {a.breakdown.map((b, i) => (
                <li key={i} className="rounded border border-ink-600/70 bg-ink-900 p-2 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="mono">{b.source}</span>
                    <span className="flex items-center gap-1.5"><AssuranceBadge assurance={b.assurance} /><span className="tabular-nums text-fg-muted">w {b.weight.toFixed(2)}</span></span>
                  </div>
                  <div className="mt-0.5 text-fg-muted">{b.label}</div>
                  <div className="mt-0.5 text-[11px] text-fg-dim">
                    {b.kind === "heuristic" ? "capped heuristic · never convicts alone" : `strength ${b.strength.toFixed(2)} × reliability ${b.reliability} × freshness ${b.freshness_factor}${b.definitive ? "" : " · not definitive"}`}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

function AnalystCard({ ind }: { ind: IndicatorDetail }) {
  const qc = useQueryClient();
  const [tag, setTag] = useState("");
  const patch = useMutation({
    mutationFn: (b: Parameters<typeof api.patchIndicator>[1]) => api.patchIndicator(ind.id, b),
    onSuccess: (d) => {
      qc.setQueryData(["indicator", ind.id], d);
      void qc.invalidateQueries({ queryKey: ["indicators"] });
    },
  });
  const addTag = (e: FormEvent) => {
    e.preventDefault();
    if (tag.trim()) patch.mutate({ add_tags: [tag.trim()] });
    setTag("");
  };
  return (
    <section className="card">
      <div className="card-h"><h2 className="text-sm font-semibold">Analyst</h2></div>
      <div className="space-y-4 p-4 text-xs">
        <label className="block text-fg-muted">
          Classification <span className="text-fg-dim">(your judgement — separate from the computed verdict)</span>
          <select className="input mt-1" value={ind.classification} onChange={(e) => patch.mutate({ classification: e.target.value as Classification })}>
            {CLASSES.map((c) => (<option key={c} value={c}>{pretty(c)}</option>))}
          </select>
        </label>
        <div>
          <div className="mb-1 text-fg-muted">Tags</div>
          <div className="flex flex-wrap gap-1.5">
            {ind.tag_details.map((t) => (
              <span key={t.tag} className={`badge ${t.analyst ? "border-accent/40 text-accent" : "border-ink-500 text-fg-muted"}`} title={`source: ${t.sources.join(", ")}`}>
                {t.tag}
                <span className="text-fg-dim">· {t.sources.join("/")}</span>
                <button aria-label={`Remove tag ${t.tag}`} onClick={() => patch.mutate({ remove_tags: [t.tag] })} className="ml-0.5 hover:text-danger"><X size={10} /></button>
              </span>
            ))}
            {ind.tag_details.length === 0 && <span className="text-fg-dim">none</span>}
          </div>
          <form onSubmit={addTag} className="mt-2 flex gap-2">
            <input className="input py-1 text-xs" placeholder="add tag" value={tag} maxLength={64} onChange={(e) => setTag(e.target.value)} aria-label="New tag" />
            <button className="btn" disabled={!tag.trim()}>Add</button>
          </form>
        </div>
        <label className="flex cursor-pointer items-start gap-2">
          <input type="checkbox" className="mt-0.5 accent-sky-400" checked={ind.do_not_share} onChange={(e) => patch.mutate({ do_not_share: e.target.checked })} />
          <span>
            <span className="text-fg">Do not share</span>
            <span className="block text-fg-dim">Only local analysis may run on this indicator. Enforced by the server, even if a provider is requested explicitly.</span>
          </span>
        </label>
        <div>
          <div className="mb-1 text-fg-muted">In investigations</div>
          {ind.investigations.length === 0 ? <span className="text-fg-dim">none</span> : (
            <ul className="space-y-0.5">{ind.investigations.map((i) => (<li key={i.id}><Link className="text-accent hover:underline" to={`/investigations/${i.id}`}>{i.title}</Link></li>))}</ul>
          )}
        </div>
        {patch.isError && <ErrorBox error={patch.error} />}
      </div>
    </section>
  );
}

// ── modals ───────────────────────────────────────────────────────────────────

function EnrichModal({ ind, onClose }: { ind: IndicatorDetail; onClose: () => void }) {
  const qc = useQueryClient();
  const plan: PlanEntry[] = ind.plan;
  const [selected, setSelected] = useState<Set<string>>(() => defaultSelection(plan));
  const [refresh, setRefresh] = useState(true);
  const run = useMutation({
    mutationFn: () => api.enrich(ind.value, [...selected], ind.type, refresh),
    onSuccess: (res) => {
      qc.setQueryData(["indicator", ind.id], res.indicator);
      void qc.invalidateQueries({ queryKey: ["graph"] });
      void qc.invalidateQueries({ queryKey: ["history"] });
      void qc.invalidateQueries({ queryKey: ["runs"] });
      void qc.invalidateQueries({ queryKey: ["stats"] });
      void qc.invalidateQueries({ queryKey: ["indicators"] });
      onClose();
    },
  });
  const sharing = plan.filter((p) => selected.has(p.provider) && p.tier !== "local" && p.state === "available");
  return (
    <Modal title="Enrich indicator" onClose={onClose}>
      <div className="max-h-[60vh] space-y-4 overflow-auto pr-1">
        <QueryPlan plan={plan} selected={selected} onChange={setSelected} />
      </div>
      <div className="mt-4 space-y-3 border-t border-ink-600/70 pt-3">
        {sharing.length > 0 ? (
          <Notice tone="warn">This indicator will be sent to: {sharing.map((p) => p.display_name).join(", ")}.</Notice>
        ) : (
          <Notice>Only local analysis will run.</Notice>
        )}
        <label className="flex items-center gap-2 text-xs text-fg-muted">
          <input type="checkbox" className="accent-sky-400" checked={refresh} onChange={(e) => setRefresh(e.target.checked)} /> bypass response cache
        </label>
        {run.isError && <ErrorBox error={run.error} />}
        <div className="flex gap-2">
          <button className="btn btn-primary" onClick={() => run.mutate()} disabled={run.isPending}>
            {run.isPending ? <RefreshCw size={13} className="animate-spin" /> : <Play size={13} />} Run
          </button>
          <button className="btn" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </Modal>
  );
}

function AddToInvestigationModal({ ind, onClose }: { ind: IndicatorDetail; onClose: () => void }) {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["investigations"], queryFn: api.investigations });
  const [target, setTarget] = useState<number | "">("");
  const add = useMutation({
    mutationFn: () => api.addMember(Number(target), { indicator_id: ind.id }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["indicator", ind.id] });
      void qc.invalidateQueries({ queryKey: ["investigations"] });
      onClose();
    },
  });
  return (
    <Modal title="Add to investigation" onClose={onClose}>
      {list.isPending ? <Spinner /> : list.isError ? <ErrorBox error={list.error} /> : list.data.items.length === 0 ? (
        <Empty title="No investigations yet"><Link to="/investigations" className="text-accent hover:underline">Create one</Link> first.</Empty>
      ) : (
        <div className="space-y-3">
          <select className="input" value={target} onChange={(e) => setTarget(e.target.value ? Number(e.target.value) : "")} aria-label="Investigation">
            <option value="">Choose…</option>
            {list.data.items.map((i) => (<option key={i.id} value={i.id}>{i.title} (TLP:{i.tlp})</option>))}
          </select>
          <p className="text-xs text-fg-dim">Adding to a TLP:RED or TLP:AMBER+STRICT investigation marks this indicator do-not-share.</p>
          {add.isError && <ErrorBox error={add.error} />}
          <button className="btn btn-primary" disabled={target === "" || add.isPending} onClick={() => add.mutate()}>Add</button>
        </div>
      )}
    </Modal>
  );
}

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

function SaveFindingModal({ ind, obs, onClose }: { ind: IndicatorDetail; obs: Observation; onClose: () => void }) {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["investigations"], queryFn: api.investigations });
  const [target, setTarget] = useState<number | "">("");
  const [title, setTitle] = useState(`${obs.title}: ${ind.value}`.slice(0, 200));
  const [severity, setSeverity] = useState<Severity>("info");
  const [body, setBody] = useState("");
  const save = useMutation({
    mutationFn: async () => {
      await api.addMember(Number(target), { indicator_id: ind.id });
      return api.addFinding(Number(target), { title, body, severity, indicator_id: ind.id, observation_id: obs.id });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["investigation"] });
      void qc.invalidateQueries({ queryKey: ["investigations"] });
      void qc.invalidateQueries({ queryKey: ["indicator", ind.id] });
      onClose();
    },
  });
  return (
    <Modal title="Save as finding" onClose={onClose}>
      <div className="space-y-3 text-xs">
        <Notice>The observation is copied into the finding as it is now — later re-enrichment will not change your evidence. <AssuranceBadge assurance={obs.assurance} /></Notice>
        <label className="block text-fg-muted">Investigation
          <select className="input mt-1" value={target} onChange={(e) => setTarget(e.target.value ? Number(e.target.value) : "")}>
            <option value="">Choose…</option>
            {list.data?.items.map((i) => (<option key={i.id} value={i.id}>{i.title}</option>))}
          </select>
        </label>
        <label className="block text-fg-muted">Title<input className="input mt-1" value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} /></label>
        <label className="block text-fg-muted">Severity
          <select className="input mt-1" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
            {SEVERITIES.map((s) => (<option key={s}>{s}</option>))}
          </select>
        </label>
        <label className="block text-fg-muted">Analyst commentary<textarea className="input mt-1 min-h-[5rem]" value={body} onChange={(e) => setBody(e.target.value)} /></label>
        {save.isError && <ErrorBox error={save.error} />}
        <button className="btn btn-primary" disabled={target === "" || !title.trim() || save.isPending} onClick={() => save.mutate()}>Save finding</button>
      </div>
    </Modal>
  );
}
