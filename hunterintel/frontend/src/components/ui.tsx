import { AlertTriangle, Check, Copy, Loader2, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { ApiError } from "../api/client";
import { copyText } from "../lib/format";

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-6 text-fg-muted" role="status">
      <Loader2 className="animate-spin" size={16} aria-hidden /> {label}…
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error);
  return (
    <div className="m-4 flex items-start gap-2 rounded-md border border-danger/40 bg-danger/10 p-3 text-danger" role="alert">
      <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden />
      <span className="break-words">{message}</span>
    </div>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "warn" | "danger"; children: ReactNode }) {
  const style = {
    info: "border-accent/30 bg-accent/5 text-fg",
    warn: "border-orange-400/40 bg-orange-400/10 text-orange-200",
    danger: "border-danger/40 bg-danger/10 text-danger",
  }[tone];
  return <div className={`rounded-md border p-3 text-xs leading-relaxed ${style}`}>{children}</div>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="px-6 py-10 text-center">
      <div className="text-sm font-medium text-fg">{title}</div>
      {children && <div className="mt-1 text-xs text-fg-muted">{children}</div>}
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1500);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <button
      type="button"
      className="btn btn-ghost px-1.5 py-1"
      aria-label={label}
      title={label}
      onClick={async () => setDone(await copyText(text))}
    >
      {done ? <Check size={13} className="text-verified" /> : <Copy size={13} />}
    </button>
  );
}

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { id: T; label: string; count?: number }[];
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <div role="tablist" className="flex gap-1 border-b border-ink-600/70">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={`-mb-px border-b-2 px-3 py-2 text-xs font-medium transition-colors ${
            value === t.id ? "border-accent text-accent" : "border-transparent text-fg-muted hover:text-fg"
          }`}
        >
          {t.label}
          {t.count !== undefined && <span className="ml-1.5 rounded bg-ink-700 px-1.5 py-0.5 text-[10px] text-fg-muted">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-auto bg-black/60 p-4 pt-[10vh]" role="dialog" aria-modal="true" aria-label={title}>
      <div className="card w-full max-w-lg shadow-2xl">
        <div className="card-h">
          <h2 className="text-sm font-semibold">{title}</h2>
          <button className="btn btn-ghost px-1.5 py-1" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="card px-4 py-3">
      <div className="h-label">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-fg-dim">{hint}</div>}
    </div>
  );
}
