import { useQuery, useQueryClient } from "@tanstack/react-query";
import { BookOpenCheck, FileSearch, KeyRound, LayoutDashboard, Search, ShieldAlert, Wrench, Database } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { api, auth, onUnauthorized } from "../api/client";
import { BRAND } from "../brand";
import { Modal, Notice } from "./ui";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/indicators", label: "Indicators", icon: Database },
  { to: "/investigations", label: "Investigations", icon: BookOpenCheck },
  { to: "/providers", label: "Providers", icon: ShieldAlert },
  { to: "/tools", label: "Local tools", icon: Wrench },
];

function GlobalSearch() {
  const [value, setValue] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        input.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = value.trim();
    if (v) navigate(`/lookup?value=${encodeURIComponent(v)}`);
  };

  return (
    <form onSubmit={submit} role="search" className="relative w-full max-w-2xl">
      <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-fg-dim" aria-hidden />
      <input
        ref={input}
        className="input pl-9 pr-16"
        placeholder="Domain, IP, URL, hash, AS number, e-mail, cert:<sha256>…"
        aria-label="Search for an indicator"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        spellCheck={false}
        autoComplete="off"
      />
      <kbd className="absolute right-2 top-1/2 -translate-y-1/2 rounded border border-ink-500 px-1.5 py-0.5 text-[10px] text-fg-dim">Ctrl K</kbd>
    </form>
  );
}

function TokenGate() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState("");
  useEffect(() => onUnauthorized(() => setOpen(true)), []);
  if (!open) return null;
  return (
    <Modal title="API token required" onClose={() => setOpen(false)}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          auth.set(token.trim());
          setOpen(false);
          setToken("");
          void qc.invalidateQueries();
        }}
      >
        <Notice>
          This server requires a bearer token (<code>HUNTERINTEL_API_TOKEN</code>). It is kept in this tab's session storage only and
          sent as an <code>Authorization</code> header — never in a URL.
        </Notice>
        <input className="input mono" type="password" autoFocus placeholder="token" value={token} onChange={(e) => setToken(e.target.value)} aria-label="API token" />
        <button className="btn btn-primary" disabled={!token.trim()}>
          <KeyRound size={13} /> Save token
        </button>
      </form>
    </Modal>
  );
}

export function Layout() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 60_000 });
  return (
    <div className="flex h-full">
      <aside className="hidden w-52 shrink-0 flex-col border-r border-ink-600/70 bg-ink-850 md:flex">
        <div className="flex items-center gap-2 px-4 py-4">
          <FileSearch className="text-accent" size={20} aria-hidden />
          <span className="text-base font-semibold tracking-tight">{BRAND}</span>
        </div>
        <nav className="flex-1 space-y-0.5 px-2" aria-label="Main">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] ${isActive ? "bg-accent/10 text-accent" : "text-fg-muted hover:bg-ink-700 hover:text-fg"}`
              }
            >
              <Icon size={15} aria-hidden /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-1 border-t border-ink-600/70 p-3 text-[11px] text-fg-dim">
          {health.data ? (
            <>
              <div>v{health.data.version}</div>
              <div>{health.data.auth_required ? "token auth on" : "no auth (local use)"}</div>
              <div>default sharing: {health.data.default_sharing.replace("_", " ")}</div>
              <div>active probes: {health.data.active_probes_enabled ? "enabled" : "off"}</div>
            </>
          ) : health.isError ? (
            <div className="text-danger">API unreachable</div>
          ) : (
            <div>connecting…</div>
          )}
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-ink-600/70 bg-ink-850 px-4 py-2.5">
          <span className="font-semibold md:hidden">{BRAND}</span>
          <GlobalSearch />
        </header>
        <main className="min-h-0 flex-1 overflow-auto p-4 md:p-6">
          <Outlet />
        </main>
      </div>
      <TokenGate />
    </div>
  );
}
