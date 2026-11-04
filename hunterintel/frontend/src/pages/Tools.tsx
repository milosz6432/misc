import { useMutation } from "@tanstack/react-query";
import { FileUp, Search } from "lucide-react";
import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { CopyButton, ErrorBox, Notice } from "../components/ui";
import { bytes } from "../lib/format";

export function ToolsPage() {
  const input = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);
  const hash = useMutation({ mutationFn: (f: File) => api.fileHash(f) });
  const r = hash.data;

  const pick = (f: File | undefined) => f && hash.mutate(f);

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Local tools</h1>
        <p className="text-xs text-fg-muted">Everything on this page runs on your own server. Nothing is sent to a third party.</p>
      </div>

      <section className="card">
        <div className="card-h">
          <h2 className="text-sm font-semibold">Hash a file and identify its type</h2>
        </div>
        <div className="space-y-4 p-4">
          <Notice>
            The file is streamed to this server, hashed in memory and <strong>discarded</strong> — it is never stored and never uploaded to
            VirusTotal or any other service. You can then choose to look the <em>hash</em> up.
          </Notice>
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDrag(true);
            }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDrag(false);
              pick(e.dataTransfer.files[0]);
            }}
            className={`grid place-items-center rounded-lg border-2 border-dashed px-4 py-10 text-center ${drag ? "border-accent bg-accent/5" : "border-ink-500"}`}
          >
            <FileUp className="mb-2 text-fg-dim" aria-hidden />
            <button className="btn" onClick={() => input.current?.click()} disabled={hash.isPending}>
              {hash.isPending ? "Hashing…" : "Choose a file"}
            </button>
            <input ref={input} type="file" className="hidden" aria-label="File to hash" onChange={(e) => pick(e.target.files?.[0])} />
            <p className="mt-2 text-xs text-fg-dim">or drop it here</p>
          </div>
          {hash.isError && <ErrorBox error={hash.error} />}
          {r && (
            <div className="space-y-3 rounded-md border border-ink-600/70 bg-ink-900 p-4 text-xs">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <div className="mono text-sm">{r.filename ?? "(unnamed)"}</div>
                <div className="text-fg-muted">{bytes(r.size)}</div>
              </div>
              <dl className="grid grid-cols-[4rem_1fr_auto] items-center gap-x-3 gap-y-2">
                {(["md5", "sha1", "sha256"] as const).map((k) => (
                  <div key={k} className="contents">
                    <dt className="uppercase text-fg-muted">{k}</dt>
                    <dd className="mono break-all">{r[k]}</dd>
                    <dd><CopyButton text={r[k]} label={`Copy ${k}`} /></dd>
                  </div>
                ))}
              </dl>
              <div>
                <div className="h-label">Detected type</div>
                <div className="mt-0.5 text-sm">{r.file_type.type}</div>
                <div className="text-fg-dim">{r.file_type.mime} · by {r.file_type.basis}</div>
                <div className="mt-1 text-fg-muted">{r.file_type.note}</div>
              </div>
              <Link to={`/lookup?value=${r.sha256}`} className="btn btn-primary inline-flex">
                <Search size={13} /> Investigate this SHA-256…
              </Link>
              <p className="text-fg-dim">You will see which providers would receive the hash before anything is sent.</p>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
