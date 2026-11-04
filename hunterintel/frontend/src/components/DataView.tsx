import { useState } from "react";
import { pretty } from "../lib/format";

const MAX_DEPTH = 5;
const LINK_HOSTS = new Set([
  "www.virustotal.com",
  "www.abuseipdb.com",
  "otx.alienvault.com",
  "urlhaus.abuse.ch",
  "bazaar.abuse.ch",
]);

/** Only vendor pages we know about become links; every other URL stays inert text. */
function safeVendorLink(value: string): string | null {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && LINK_HOSTS.has(u.hostname) ? u.toString() : null;
  } catch {
    return null;
  }
}

function Scalar({ k, v }: { k: string; v: string | number | boolean }) {
  if (typeof v === "string" && /^(link|reference)$/.test(k)) {
    const href = safeVendorLink(v);
    if (href)
      return (
        <a href={href} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-2 hover:underline">
          {href}
        </a>
      );
  }
  if (typeof v === "boolean") return <span className={v ? "text-verified" : "text-fg-muted"}>{String(v)}</span>;
  if (typeof v === "number") return <span className="mono tabular-nums">{v}</span>;
  return <span className="mono break-all">{v === "" ? "—" : v}</span>;
}

function List({ items, depth }: { items: unknown[]; depth: number }) {
  const [all, setAll] = useState(false);
  const scalar = items.every((i) => i === null || typeof i !== "object");
  const limit = scalar ? 14 : 4;
  const shown = all ? items : items.slice(0, limit);
  return (
    <div>
      {scalar ? (
        <div className="flex flex-wrap gap-1">
          {shown.map((it, i) => (
            <span key={i} className="mono rounded border border-ink-500 bg-ink-900 px-1.5 py-0.5 text-xs break-all">
              {String(it)}
            </span>
          ))}
        </div>
      ) : (
        <div className="space-y-1.5">
          {shown.map((it, i) => (
            <div key={i} className="rounded border border-ink-600/70 bg-ink-900/60 p-2">
              <Node name="" value={it} depth={depth + 1} />
            </div>
          ))}
        </div>
      )}
      {items.length > limit && (
        <button className="mt-1 text-xs text-accent hover:underline" onClick={() => setAll(!all)}>
          {all ? "show fewer" : `show all ${items.length}`}
        </button>
      )}
    </div>
  );
}

function Node({ name, value, depth }: { name: string; value: unknown; depth: number }) {
  if (value === null || value === undefined) return <span className="text-fg-dim">—</span>;
  if (typeof value !== "object") return <Scalar k={name} v={value as string | number | boolean} />;
  if (depth >= MAX_DEPTH) return <span className="mono text-xs text-fg-dim">{JSON.stringify(value).slice(0, 200)}</span>;
  if (Array.isArray(value)) return value.length === 0 ? <span className="text-fg-dim">none</span> : <List items={value} depth={depth} />;
  const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined);
  if (entries.length === 0) return <span className="text-fg-dim">—</span>;
  return (
    <dl className="grid grid-cols-[minmax(7rem,max-content)_1fr] gap-x-4 gap-y-1.5">
      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="pt-0.5 text-xs text-fg-muted">{pretty(k)}</dt>
          <dd className="min-w-0 text-xs">
            <Node name={k} value={v} depth={depth + 1} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** Renders arbitrary provider data without ever interpreting it as HTML. */
export function DataView({ data }: { data: unknown }) {
  const [raw, setRaw] = useState(false);
  return (
    <div>
      <div className="mb-2 flex justify-end">
        <button className="text-[11px] text-fg-dim hover:text-fg" onClick={() => setRaw(!raw)}>
          {raw ? "structured view" : "raw JSON"}
        </button>
      </div>
      {raw ? (
        <pre className="max-h-96 overflow-auto rounded bg-ink-950 p-3 text-xs leading-relaxed">{JSON.stringify(data, null, 2)}</pre>
      ) : (
        <Node name="" value={data} depth={0} />
      )}
    </div>
  );
}
