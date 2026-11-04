import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, GitCompare, Plus, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { Comparison, InvestigationDetail, Severity, TLP } from "../api/types";
import { AssuranceBadge, ClassBadge, LockBadge, SeverityBadge, TlpBadge, TypeBadge, VerdictBadge } from "../components/badges";
import { GraphView } from "../components/GraphView";
import { Empty, ErrorBox, Notice, Spinner, Tabs } from "../components/ui";
import { formatDate, pretty } from "../lib/format";
import { TLP_OPTIONS } from "./Investigations";

type Tab = "indicators" | "findings" | "notes" | "graph" | "compare";
const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

export function InvestigationDetailPage() {
  const id = Number(useParams().id);
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("indicators");
  const [defangExport, setDefangExport] = useState(true);
  const q = useQuery({ queryKey: ["investigation", id], queryFn: () => api.investigation(id), enabled: Number.isFinite(id) });

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["investigation", id] });
    void qc.invalidateQueries({ queryKey: ["investigations"] });
  };
  const patch = useMutation({
    mutationFn: (b: Parameters<typeof api.patchInvestigation>[1]) => api.patchInvestigation(id, b),
    onSuccess: (d) => {
      qc.setQueryData(["investigation", id], d);
      void qc.invalidateQueries({ queryKey: ["investigations"] });
      void qc.invalidateQueries({ queryKey: ["indicator"] });
    },
  });
  const del = useMutation({
    mutationFn: () => api.deleteInvestigation(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["investigations"] });
      navigate("/investigations");
    },
  });
  const exportReport = useMutation({ mutationFn: (f: "md" | "json" | "html") => api.downloadReport(id, f, defangExport) });

  if (q.isPending) return <Spinner />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const inv = q.data;
  const restrictive = inv.tlp === "red" || inv.tlp === "amber_strict";

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <header className="card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <TlpBadge tlp={inv.tlp} />
              <span className={`badge ${inv.status === "open" ? "border-verified/40 text-verified" : "border-ink-500 text-fg-muted"}`}>{inv.status}</span>
            </div>
            <h1 className="mt-2 text-lg font-semibold">{inv.title}</h1>
            {inv.description && <p className="mt-1 max-w-3xl whitespace-pre-wrap text-xs text-fg-muted">{inv.description}</p>}
            <p className="mt-1 text-[11px] text-fg-dim">created {formatDate(inv.created_at)} · updated {formatDate(inv.updated_at)}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select className="input w-auto py-1 text-xs" value={inv.tlp} aria-label="TLP" onChange={(e) => patch.mutate({ tlp: e.target.value as TLP })}>
              {TLP_OPTIONS.map((t) => (<option key={t.id} value={t.id}>TLP:{t.id.replace("_", "+").toUpperCase()}</option>))}
            </select>
            <button className="btn" onClick={() => patch.mutate({ status: inv.status === "open" ? "closed" : "open" })}>{inv.status === "open" ? "Close" : "Reopen"}</button>
            <button className="btn btn-danger" onClick={() => window.confirm("Delete this investigation? Indicators are kept.") && del.mutate()}><Trash2 size={13} /> Delete</button>
          </div>
        </div>
        {restrictive && (
          <div className="mt-3"><Notice tone="warn">At TLP:{inv.tlp.replace("_", "+").toUpperCase()} every indicator in this investigation is marked <strong>do-not-share</strong>: only local analysis may run on it.</Notice></div>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-ink-600/70 pt-3">
          <span className="h-label mr-1">Export report</span>
          {(["md", "html", "json"] as const).map((f) => (
            <button key={f} className="btn" disabled={exportReport.isPending} onClick={() => exportReport.mutate(f)}><Download size={12} /> {f === "md" ? "Markdown" : f.toUpperCase()}</button>
          ))}
          <label className="ml-2 flex items-center gap-2 text-xs text-fg-muted" title="Markdown and HTML only; JSON always keeps raw values">
            <input type="checkbox" className="accent-sky-400" checked={defangExport} onChange={(e) => setDefangExport(e.target.checked)} /> defang indicators
          </label>
        </div>
        {(patch.isError || del.isError || exportReport.isError) && <ErrorBox error={patch.error ?? del.error ?? exportReport.error} />}
      </header>

      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "indicators", label: "Indicators", count: inv.indicators.length },
          { id: "findings", label: "Findings", count: inv.findings.length },
          { id: "notes", label: "Notes", count: inv.notes.length },
          { id: "graph", label: "Graph" },
          { id: "compare", label: "Compare" },
        ]}
      />
      {tab === "indicators" && <IndicatorsTab inv={inv} onChange={refresh} />}
      {tab === "findings" && <FindingsTab inv={inv} onChange={refresh} />}
      {tab === "notes" && <NotesTab inv={inv} onChange={refresh} />}
      {tab === "graph" && <GraphTab id={inv.id} />}
      {tab === "compare" && <CompareTab inv={inv} />}
    </div>
  );
}

// ── indicators ───────────────────────────────────────────────────────────────

function IndicatorsTab({ inv, onChange }: { inv: InvestigationDetail; onChange: () => void }) {
  const [value, setValue] = useState("");
  const add = useMutation({
    mutationFn: () => api.addMember(inv.id, { value: value.trim() }),
    onSuccess: () => {
      setValue("");
      onChange();
    },
  });
  const remove = useMutation({ mutationFn: (iid: number) => api.removeMember(inv.id, iid), onSuccess: onChange });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (value.trim()) add.mutate();
  };
  return (
    <div className="space-y-3">
      <form onSubmit={submit} className="flex gap-2">
        <input className="input" value={value} onChange={(e) => setValue(e.target.value)} placeholder="Add an indicator (not enriched until you open it and choose providers)" aria-label="Indicator to add" spellCheck={false} />
        <button className="btn btn-primary shrink-0" disabled={!value.trim() || add.isPending}><Plus size={13} /> Add</button>
      </form>
      {(add.isError || remove.isError) && <ErrorBox error={add.error ?? remove.error} />}
      <div className="card overflow-x-auto">
        {inv.indicators.length === 0 ? <Empty title="No indicators in this investigation" /> : (
          <table className="w-full text-[13px]">
            <thead className="border-b border-ink-600/70"><tr><th className="th">Indicator</th><th className="th">Verdict</th><th className="th text-right">Risk</th><th className="th text-right">Conf.</th><th className="th">Added</th><th className="th" /></tr></thead>
            <tbody className="divide-y divide-ink-600/40">
              {inv.indicators.map((i) => (
                <tr key={i.id} className="hover:bg-ink-700/40">
                  <td className="td"><div className="flex flex-wrap items-center gap-2"><TypeBadge type={i.type} /><Link className="mono break-all hover:text-accent" to={`/indicators/${i.id}`}>{i.value.length > 70 ? i.value.slice(0, 66) + "…" : i.value}</Link>{i.do_not_share && <LockBadge />}<ClassBadge value={i.classification} /></div></td>
                  <td className="td"><VerdictBadge verdict={i.verdict} /></td>
                  <td className="td text-right tabular-nums">{i.risk_score ?? <span className="text-fg-dim">n/a</span>}</td>
                  <td className="td text-right tabular-nums">{i.confidence !== null ? `${i.confidence}%` : "—"}</td>
                  <td className="td text-xs text-fg-muted">{formatDate(i.added_at)}</td>
                  <td className="td text-right"><button className="btn btn-ghost px-1.5 py-1 text-fg-dim hover:text-danger" aria-label={`Remove ${i.value}`} onClick={() => remove.mutate(i.id)}><Trash2 size={13} /></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── findings ─────────────────────────────────────────────────────────────────

function FindingsTab({ inv, onChange }: { inv: InvestigationDetail; onChange: () => void }) {
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [severity, setSeverity] = useState<Severity>("info");
  const [indicatorId, setIndicatorId] = useState<number | "">("");
  const add = useMutation({
    mutationFn: () => api.addFinding(inv.id, { title: title.trim(), body, severity, indicator_id: indicatorId === "" ? undefined : indicatorId }),
    onSuccess: () => {
      setTitle("");
      setBody("");
      onChange();
    },
  });
  const del = useMutation({ mutationFn: (fid: number) => api.deleteFinding(inv.id, fid), onSuccess: onChange });
  const byId = new Map(inv.indicators.map((i) => [i.id, i]));
  return (
    <div className="space-y-4">
      <form className="card space-y-3 p-4 text-xs" onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
        <div className="grid gap-3 md:grid-cols-[1fr_9rem_14rem]">
          <label className="text-fg-muted">Title<input className="input mt-1" value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} /></label>
          <label className="text-fg-muted">Severity<select className="input mt-1" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>{SEVERITIES.map((s) => (<option key={s}>{s}</option>))}</select></label>
          <label className="text-fg-muted">Indicator<select className="input mt-1" value={indicatorId} onChange={(e) => setIndicatorId(e.target.value ? Number(e.target.value) : "")}><option value="">(none)</option>{inv.indicators.map((i) => (<option key={i.id} value={i.id}>{i.value.slice(0, 40)}</option>))}</select></label>
        </div>
        <label className="block text-fg-muted">Details<textarea className="input mt-1 min-h-[4rem]" value={body} onChange={(e) => setBody(e.target.value)} /></label>
        {add.isError && <ErrorBox error={add.error} />}
        <div className="flex items-center gap-3"><button className="btn btn-primary" disabled={!title.trim() || add.isPending}>Add finding</button><span className="text-fg-dim">To attach evidence, use “finding” on an observation in the indicator’s Provider results tab.</span></div>
      </form>
      {inv.findings.length === 0 ? <div className="card"><Empty title="No findings yet" /></div> : inv.findings.map((f) => {
        const snap = f.snapshot as { assurance?: "verified" | "provider_claim" | "inferred"; provider?: string; kind?: string; summary?: string | null; last_seen?: string };
        const ind = f.indicator_id ? byId.get(f.indicator_id) : undefined;
        return (
          <article key={f.id} className="card p-4">
            <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={f.severity} /><h3 className="font-medium">{f.title}</h3><button className="btn btn-ghost ml-auto px-1.5 py-1 text-fg-dim hover:text-danger" aria-label="Delete finding" onClick={() => del.mutate(f.id)}><Trash2 size={13} /></button></div>
            {ind && <div className="mono mt-1 break-all text-xs text-fg-muted">{ind.value}</div>}
            {f.body && <p className="mt-2 whitespace-pre-wrap text-xs">{f.body}</p>}
            {snap.kind && (
              <div className="mt-2 rounded-md border border-ink-600/70 bg-ink-900 p-2 text-xs">
                <div className="flex flex-wrap items-center gap-2 text-fg-muted">Evidence snapshot {snap.assurance && <AssuranceBadge assurance={snap.assurance} />}<span className="mono">{snap.provider}/{snap.kind}</span><span className="text-fg-dim">captured as of {formatDate(snap.last_seen)}</span></div>
                {snap.summary && <div className="mt-1">{snap.summary}</div>}
              </div>
            )}
          </article>
        );
      })}
    </div>
  );
}

// ── notes ────────────────────────────────────────────────────────────────────

function NotesTab({ inv, onChange }: { inv: InvestigationDetail; onChange: () => void }) {
  const [body, setBody] = useState("");
  const add = useMutation({ mutationFn: () => api.addNote(inv.id, body.trim()), onSuccess: () => { setBody(""); onChange(); } });
  const del = useMutation({ mutationFn: (nid: number) => api.deleteNote(inv.id, nid), onSuccess: onChange });
  return (
    <div className="space-y-3">
      <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); if (body.trim()) add.mutate(); }}>
        <textarea className="input min-h-[5rem]" placeholder="Analyst note…" value={body} onChange={(e) => setBody(e.target.value)} aria-label="New note" />
        {add.isError && <ErrorBox error={add.error} />}
        <button className="btn btn-primary" disabled={!body.trim() || add.isPending}>Add note</button>
      </form>
      {inv.notes.length === 0 ? <div className="card"><Empty title="No notes yet" /></div> : inv.notes.map((n) => (
        <article key={n.id} className="card p-4">
          <div className="mb-1 flex items-center justify-between text-xs text-fg-muted"><span><strong className="text-fg">{n.author}</strong> · {formatDate(n.created_at)}</span><button className="btn btn-ghost px-1.5 py-1 text-fg-dim hover:text-danger" aria-label="Delete note" onClick={() => del.mutate(n.id)}><Trash2 size={13} /></button></div>
          <p className="whitespace-pre-wrap text-[13px]">{n.body}</p>
        </article>
      ))}
    </div>
  );
}

// ── graph & compare ──────────────────────────────────────────────────────────

function GraphTab({ id }: { id: number }) {
  const [depth, setDepth] = useState(1);
  const [inferred, setInferred] = useState(true);
  const g = useQuery({ queryKey: ["inv-graph", id, depth, inferred], queryFn: () => api.investigationGraph(id, depth, inferred) });
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-xs text-fg-muted">
        <label className="flex items-center gap-2">Expand<select className="input w-auto py-1 text-xs" value={depth} onChange={(e) => setDepth(Number(e.target.value))}>{[0, 1, 2, 3].map((d) => (<option key={d} value={d}>{d} hop{d === 1 ? "" : "s"}</option>))}</select></label>
        <label className="flex items-center gap-2"><input type="checkbox" className="accent-sky-400" checked={inferred} onChange={(e) => setInferred(e.target.checked)} /> show inferred links between indicators</label>
      </div>
      {g.isPending ? <Spinner /> : g.isError ? <ErrorBox error={g.error} /> : <GraphView graph={g.data} height={560} />}
    </div>
  );
}

function CompareTab({ inv }: { inv: InvestigationDetail }) {
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const cmp = useMutation({ mutationFn: () => api.compare([...picked]) });
  const toggle = (id: number) => { const n = new Set(picked); if (n.has(id)) n.delete(id); else n.add(id); setPicked(n); };
  return (
    <div className="space-y-4">
      <div className="card p-4">
        <p className="mb-3 text-xs text-fg-muted">Pick two or more indicators to see what infrastructure, tags and attributes they share.</p>
        <div className="flex flex-wrap gap-2">
          {inv.indicators.map((i) => (
            <label key={i.id} className={`flex cursor-pointer items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs ${picked.has(i.id) ? "border-accent bg-accent/10" : "border-ink-500"}`}>
              <input type="checkbox" className="accent-sky-400" checked={picked.has(i.id)} onChange={() => toggle(i.id)} />
              <span className="mono">{i.value.length > 38 ? i.value.slice(0, 36) + "…" : i.value}</span>
            </label>
          ))}
        </div>
        <button className="btn btn-primary mt-3" disabled={picked.size < 2 || picked.size > 10 || cmp.isPending} onClick={() => cmp.mutate()}><GitCompare size={13} /> Compare {picked.size || ""}</button>
        {cmp.isError && <ErrorBox error={cmp.error} />}
      </div>
      {cmp.data && <ComparisonResult c={cmp.data} />}
    </div>
  );
}

function ComparisonResult({ c }: { c: Comparison }) {
  const names = new Map(c.indicators.map((i) => [i.id, i.value]));
  const strengthStyle = { weak: "text-fg-muted border-ink-500", medium: "text-yellow-300 border-yellow-400/40", strong: "text-verified border-verified/40" } as const;
  return (
    <div className="space-y-4">
      <Notice>{c.note}</Notice>
      <section className="card overflow-x-auto">
        <div className="card-h"><h3 className="text-sm font-semibold">Shared between indicators</h3><AssuranceBadge assurance="inferred" /></div>
        {c.shared.length === 0 ? <Empty title="Nothing in common in the stored data" /> : (
          <table className="w-full text-xs"><thead><tr><th className="th">Shared</th><th className="th">Value</th><th className="th">Strength</th><th className="th">Between</th></tr></thead>
            <tbody className="divide-y divide-ink-600/40">{c.shared.map((s, i) => (
              <tr key={i}><td className="td text-fg-muted">{pretty(s.facet)}</td><td className="td mono break-all">{s.value}</td>
                <td className="td"><span className={`badge bg-transparent ${strengthStyle[s.strength]}`} title={s.caveat}>{s.strength}</span></td>
                <td className="td mono text-fg-muted">{s.indicator_ids.map((id) => names.get(id)?.slice(0, 28)).join(" · ")}</td></tr>))}</tbody></table>
        )}
      </section>
      <section className="card overflow-x-auto">
        <div className="card-h"><h3 className="text-sm font-semibold">Side by side</h3></div>
        <table className="w-full text-xs"><thead><tr><th className="th">Indicator</th><th className="th">Verdict</th><th className="th">Risk</th><th className="th">Attributes</th><th className="th">Tags</th></tr></thead>
          <tbody className="divide-y divide-ink-600/40">{c.indicators.map((i) => (
            <tr key={i.id}><td className="td"><div className="flex items-center gap-2"><TypeBadge type={i.type} /><Link className="mono break-all hover:text-accent" to={`/indicators/${i.id}`}>{i.value.slice(0, 48)}</Link></div></td>
              <td className="td"><VerdictBadge verdict={i.verdict} /></td><td className="td tabular-nums">{i.risk_score ?? "n/a"}</td>
              <td className="td text-fg-muted">{Object.entries(i.attributes).map(([k, v]) => (<div key={k}><span className="text-fg-dim">{pretty(k)}:</span> {/^\d{4}-\d{2}-\d{2}T/.test(String(v)) ? String(v).slice(0, 10) : String(v)}</div>))}</td>
              <td className="td"><div className="flex flex-wrap gap-1">{i.tags.slice(0, 8).map((t) => (<span key={t} className="badge border-ink-500 text-fg-muted">{t}</span>))}</div></td></tr>))}</tbody></table>
      </section>
    </div>
  );
}
