import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { IndicatorType } from "../api/types";
import { TypeBadge, VerdictBadge } from "../components/badges";
import { QueryPlan, defaultSelection } from "../components/QueryPlan";
import { ErrorBox, Notice, Spinner } from "../components/ui";

const TYPES: IndicatorType[] = ["domain", "ip", "url", "hash", "certificate", "asn", "email"];

/**
 * Step 1 of every investigation: parse locally (zero network), show the plan, and only
 * send the indicator to the providers the analyst ticks.
 */
export function LookupPage() {
  const [params, setParams] = useSearchParams();
  const value = params.get("value") ?? "";
  const forced = (params.get("type") as IndicatorType | null) ?? undefined;
  const navigate = useNavigate();
  const qc = useQueryClient();

  const classified = useQuery({
    queryKey: ["classify", value, forced],
    queryFn: () => api.classify(value, forced),
    enabled: value.length > 0,
    retry: false,
  });

  const plan = classified.data?.plan;
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [refresh, setRefresh] = useState(false);
  useEffect(() => {
    if (plan) setSelected(defaultSelection(plan));
  }, [plan]);

  const run = useMutation({
    mutationFn: (providers: string[]) => api.enrich(classified.data!.indicator.value, providers, classified.data!.indicator.type, refresh),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["stats"] });
      void qc.invalidateQueries({ queryKey: ["indicators"] });
      qc.setQueryData(["indicator", res.indicator.id], res.indicator);
      navigate(`/indicators/${res.indicator.id}`);
    },
  });

  const sharing = useMemo(() => plan?.filter((p) => selected.has(p.provider) && p.tier !== "local") ?? [], [plan, selected]);

  if (!value) return <div className="p-6 text-fg-muted">Enter an indicator in the search box.</div>;
  if (classified.isPending) return <Spinner label="Parsing locally" />;
  if (classified.isError) {
    return (
      <div className="mx-auto max-w-2xl space-y-3">
        <ErrorBox error={classified.error} />
        <div className="card p-4 text-xs text-fg-muted">
          Accepted: domains, IPv4/IPv6, URLs, MD5/SHA-1/SHA-256, <code>AS15169</code>, e-mail addresses, and certificates as{" "}
          <code>cert:&lt;sha256&gt;</code> or <code>crtsh:&lt;id&gt;</code>. Defanged input (<code>hxxps://evil[.]com</code>) is restored automatically.
        </div>
      </div>
    );
  }

  const { indicator: ind, known } = classified.data;
  const runnable = [...selected].filter((n) => plan?.some((p) => p.provider === n && p.state === "available"));

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <section className="card p-4">
        <div className="flex flex-wrap items-center gap-2">
          <TypeBadge type={ind.type} />
          {ind.subtype && <span className="badge border-ink-500 text-fg-muted">{ind.subtype}</span>}
          <span className="badge border-ink-500 text-fg-muted">scope: {ind.scope.replace("_", "-")}</span>
        </div>
        <div className="mono mt-2 break-all text-base">{ind.value}</div>
        {ind.value !== ind.raw && <div className="mt-1 text-xs text-fg-dim">entered as <span className="mono">{ind.raw}</span></div>}
        {ind.notes.length > 0 && (
          <ul className="mt-2 list-inside list-disc text-xs text-fg-muted">
            {ind.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-fg-muted">
          <span>Interpret as:</span>
          {TYPES.map((t) => (
            <button
              key={t}
              className={`rounded border px-2 py-0.5 ${ind.type === t ? "border-accent text-accent" : "border-ink-500 hover:border-accent/60"}`}
              onClick={() => setParams({ value, type: t })}
            >
              {t}
            </button>
          ))}
        </div>
        {known && (
          <div className="mt-3 flex items-center gap-2 rounded-md border border-ink-600/70 bg-ink-900 px-3 py-2 text-xs">
            Already in the store: <VerdictBadge verdict={known.verdict} />
            <Link to={`/indicators/${known.id}`} className="ml-auto text-accent hover:underline">
              open existing record
            </Link>
          </div>
        )}
      </section>

      {!ind.remote_lookup_allowed && (
        <Notice tone="warn">
          <strong>Remote lookups are disabled for this indicator.</strong> {ind.blocked_reason?.replace(/\.?$/, ".")} Only local analysis will run.
        </Notice>
      )}
      {ind.sensitive && (
        <Notice>E-mail addresses are never sent as-is: DNS lookups use only the domain part, and no third-party provider accepts e-mail.</Notice>
      )}

      <section className="card">
        <div className="card-h">
          <div>
            <h2 className="text-sm font-semibold">Query plan</h2>
            <p className="text-xs text-fg-muted">Nothing is sent anywhere until you run it. Tick only what you are comfortable sharing.</p>
          </div>
        </div>
        <div className="p-4">
          <QueryPlan plan={plan ?? []} selected={selected} onChange={setSelected} />
        </div>
        <div className="space-y-3 border-t border-ink-600/70 p-4">
          {sharing.length > 0 ? (
            <Notice tone="warn">
              <div className="mb-1 font-medium">You are about to send this indicator to:</div>
              <ul className="list-inside list-disc">
                {sharing.map((p) => (
                  <li key={p.provider}>
                    <strong>{p.display_name}</strong> — {p.data_shared}
                  </li>
                ))}
              </ul>
            </Notice>
          ) : (
            <Notice>
              <ShieldCheck size={13} className="mr-1 inline text-verified" aria-hidden />
              Only local analysis will run: no third party receives this indicator.
            </Notice>
          )}
          <div className="flex flex-wrap items-center gap-3">
            <button className="btn btn-primary" disabled={run.isPending} onClick={() => run.mutate(runnable)}>
              <Play size={13} /> {run.isPending ? "Running…" : `Run ${runnable.length} provider${runnable.length === 1 ? "" : "s"}`}
            </button>
            <button className="btn" disabled={run.isPending} onClick={() => run.mutate(["local"])}>
              Local analysis only
            </button>
            <label className="ml-auto flex items-center gap-2 text-xs text-fg-muted">
              <input type="checkbox" className="accent-sky-400" checked={refresh} onChange={(e) => setRefresh(e.target.checked)} /> bypass cache
            </label>
          </div>
          {run.isError && <ErrorBox error={run.error} />}
        </div>
      </section>
    </div>
  );
}
