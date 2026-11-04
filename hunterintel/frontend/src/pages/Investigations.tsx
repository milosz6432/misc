import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { TLP } from "../api/types";
import { TlpBadge } from "../components/badges";
import { Empty, ErrorBox, Spinner } from "../components/ui";
import { timeAgo } from "../lib/format";

export const TLP_OPTIONS: { id: TLP; hint: string }[] = [
  { id: "clear", hint: "No restriction on disclosure" },
  { id: "green", hint: "Community-wide" },
  { id: "amber", hint: "Limited to your organisation and clients" },
  { id: "amber_strict", hint: "Your organisation only — indicators become do-not-share" },
  { id: "red", hint: "Named recipients only — indicators become do-not-share" },
];

export function InvestigationsPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const list = useQuery({ queryKey: ["investigations"], queryFn: api.investigations });
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [tlp, setTlp] = useState<TLP>("amber");
  const create = useMutation({
    mutationFn: () => api.createInvestigation(title.trim(), description.trim(), tlp),
    onSuccess: (inv) => {
      void qc.invalidateQueries({ queryKey: ["investigations"] });
      void qc.invalidateQueries({ queryKey: ["stats"] });
      navigate(`/investigations/${inv.id}`);
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (title.trim()) create.mutate();
  };

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Investigations</h1>
        <p className="text-xs text-fg-muted">Workspaces that group indicators, findings and analyst notes, and export as a report.</p>
      </div>

      <form onSubmit={submit} className="card space-y-3 p-4">
        <div className="grid gap-3 md:grid-cols-[1fr_16rem]">
          <label className="text-xs text-fg-muted">Title
            <input className="input mt-1" value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Invoice-themed phishing wave" />
          </label>
          <label className="text-xs text-fg-muted">TLP
            <select className="input mt-1" value={tlp} onChange={(e) => setTlp(e.target.value as TLP)}>
              {TLP_OPTIONS.map((t) => (<option key={t.id} value={t.id}>TLP:{t.id.replace("_", "+").toUpperCase()} — {t.hint}</option>))}
            </select>
          </label>
        </div>
        <label className="block text-xs text-fg-muted">Description (optional)
          <textarea className="input mt-1 min-h-[3.5rem]" value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        {create.isError && <ErrorBox error={create.error} />}
        <button className="btn btn-primary" disabled={!title.trim() || create.isPending}><Plus size={13} /> Create investigation</button>
      </form>

      <div className="card">
        {list.isPending ? <Spinner /> : list.isError ? <ErrorBox error={list.error} /> : list.data.items.length === 0 ? (
          <Empty title="No investigations yet" />
        ) : (
          <ul className="divide-y divide-ink-600/40">
            {list.data.items.map((i) => (
              <li key={i.id}>
                <Link to={`/investigations/${i.id}`} className="flex items-center gap-3 px-4 py-3 hover:bg-ink-700/40">
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{i.title}</div>
                    {i.description && <div className="truncate text-xs text-fg-muted">{i.description}</div>}
                  </div>
                  <TlpBadge tlp={i.tlp} />
                  <span className={`badge ${i.status === "open" ? "border-verified/40 text-verified" : "border-ink-500 text-fg-muted"}`}>{i.status}</span>
                  <span className="w-24 text-right text-xs text-fg-muted">{i.indicator_count} IOCs · {i.finding_count} findings</span>
                  <span className="w-16 text-right text-xs text-fg-dim">{timeAgo(i.updated_at)}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
