import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api/client";
import { IndicatorTable } from "../components/IndicatorTable";
import { Empty, ErrorBox, Spinner } from "../components/ui";

const TYPES = ["", "domain", "ip", "url", "hash", "certificate", "asn", "email"];
const VERDICTS = ["", "malicious", "suspicious", "low_risk", "no_detections", "unknown"];
const PAGE = 25;

export function IndicatorsPage() {
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [verdict, setVerdict] = useState("");
  const [tag, setTag] = useState("");
  const [sort, setSort] = useState("last_seen");
  const [expired, setExpired] = useState(false);
  const [page, setPage] = useState(0);

  const params = { q, type, verdict, tag, sort, include_expired: expired, limit: PAGE, offset: page * PAGE };
  const list = useQuery({ queryKey: ["indicators", params], queryFn: () => api.listIndicators(params), placeholderData: keepPreviousData });
  const reset = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setPage(0);
  };

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Indicators</h1>
        <p className="text-xs text-fg-muted">
          The IOC store: everything you have searched or adopted. Indicators that were only <em>discovered</em> through relationships stay in the
          graph until you adopt them.
        </p>
      </div>
      <div className="card flex flex-wrap items-end gap-3 p-3">
        <label className="min-w-[14rem] flex-1 text-xs text-fg-muted">
          Contains
          <input className="input mt-1" value={q} onChange={(e) => reset(setQ)(e.target.value)} placeholder="filter by value" />
        </label>
        <label className="text-xs text-fg-muted">
          Type
          <select className="input mt-1" value={type} onChange={(e) => reset(setType)(e.target.value)}>
            {TYPES.map((t) => (
              <option key={t} value={t}>{t || "any"}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-fg-muted">
          Verdict
          <select className="input mt-1" value={verdict} onChange={(e) => reset(setVerdict)(e.target.value)}>
            {VERDICTS.map((t) => (
              <option key={t} value={t}>{t ? t.replace("_", " ") : "any"}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-fg-muted">
          Tag
          <input className="input mt-1 w-32" value={tag} onChange={(e) => reset(setTag)(e.target.value)} placeholder="exact tag" />
        </label>
        <label className="text-xs text-fg-muted">
          Sort
          <select className="input mt-1" value={sort} onChange={(e) => reset(setSort)(e.target.value)}>
            <option value="last_seen">last seen</option>
            <option value="risk">risk</option>
            <option value="confidence">confidence</option>
            <option value="first_seen">first seen</option>
            <option value="value">value</option>
          </select>
        </label>
        <label className="flex items-center gap-2 pb-2 text-xs text-fg-muted">
          <input type="checkbox" className="accent-sky-400" checked={expired} onChange={(e) => reset(setExpired)(e.target.checked)} /> include expired
        </label>
      </div>

      <div className="card">
        {list.isPending ? (
          <Spinner />
        ) : list.isError ? (
          <ErrorBox error={list.error} />
        ) : list.data.items.length === 0 ? (
          <Empty title="No indicators match">Search for something with the box above to add it.</Empty>
        ) : (
          <>
            <IndicatorTable items={list.data.items} />
            <div className="flex items-center justify-between border-t border-ink-600/70 px-4 py-2 text-xs text-fg-muted">
              <span>
                {list.data.offset + 1}–{list.data.offset + list.data.items.length} of {list.data.total}
              </span>
              <span className="flex gap-2">
                <button className="btn" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
                <button className="btn" disabled={(page + 1) * PAGE >= list.data.total} onClick={() => setPage(page + 1)}>Next</button>
              </span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
