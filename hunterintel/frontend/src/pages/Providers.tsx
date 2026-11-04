import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, ExternalLink, XCircle } from "lucide-react";
import { api } from "../api/client";
import { AssuranceBadge, TierBadge } from "../components/badges";
import { ErrorBox, Notice, Spinner } from "../components/ui";

export function ProvidersPage() {
  const providers = useQuery({ queryKey: ["providers"], queryFn: api.providers });
  if (providers.isPending) return <Spinner />;
  if (providers.isError) return <ErrorBox error={providers.error} />;

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Providers</h1>
        <p className="text-xs text-fg-muted">Intelligence sources, what each one receives, and whether it is ready. API keys are read from environment variables and are never shown here.</p>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <Notice>
          <div className="mb-1 flex items-center gap-2"><AssuranceBadge assurance="verified" /></div>
          Observed first-hand from the source of record (DNS answers, registry RDAP, a live probe) or computed locally.
        </Notice>
        <Notice>
          <div className="mb-1 flex items-center gap-2"><AssuranceBadge assurance="provider_claim" /></div>
          Asserted by a third party. Always attributed to its source and never presented as confirmed fact.
        </Notice>
        <Notice>
          <div className="mb-1 flex items-center gap-2"><AssuranceBadge assurance="inferred" /></div>
          Derived by HunterIntel (heuristics, shared infrastructure). A lead to verify, not proof.
        </Notice>
      </div>

      <div className="card overflow-x-auto">
        <table className="w-full text-left text-[13px]">
          <thead className="border-b border-ink-600/70">
            <tr>
              <th className="th">Provider</th>
              <th className="th">Receives</th>
              <th className="th">Handles</th>
              <th className="th">Status</th>
              <th className="th">Rate limit</th>
              <th className="th">Terms</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-600/40">
            {providers.data.map((p) => (
              <tr key={p.name} className={p.configured ? "" : "opacity-70"}>
                <td className="td">
                  <div className="font-medium">{p.display_name}</div>
                  <div className="mono text-[11px] text-fg-dim">{p.name}</div>
                  <div className="mt-1 max-w-xs text-xs text-fg-muted">{p.description}</div>
                </td>
                <td className="td"><TierBadge tier={p.tier} /></td>
                <td className="td">
                  <div className="flex max-w-[12rem] flex-wrap gap-1">
                    {p.supported_types.map((t) => (
                      <span key={t} className="badge border-ink-500 text-fg-muted">{t}</span>
                    ))}
                  </div>
                </td>
                <td className="td">
                  {p.configured ? (
                    <span className="inline-flex items-center gap-1.5 text-verified"><CheckCircle2 size={14} aria-hidden /> ready</span>
                  ) : (
                    <div>
                      <span className="inline-flex items-center gap-1.5 text-fg-muted"><XCircle size={14} aria-hidden /> not configured</span>
                      {p.key_env && <div className="mono mt-1 text-[11px] text-fg-dim">set {p.key_env}</div>}
                    </div>
                  )}
                </td>
                <td className="td text-xs text-fg-muted">
                  {p.rate_limit ? `${p.rate_limit.requests} / ${p.rate_limit.per_seconds >= 3600 ? `${p.rate_limit.per_seconds / 3600} h` : `${p.rate_limit.per_seconds} s`}` : "—"}
                </td>
                <td className="td">
                  {p.terms_url ? (
                    <a href={p.terms_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-accent hover:underline">
                      terms <ExternalLink size={11} />
                    </a>
                  ) : (
                    <span className="text-fg-dim">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
