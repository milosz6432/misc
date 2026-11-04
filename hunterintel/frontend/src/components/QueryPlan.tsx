import { Ban, KeyRound } from "lucide-react";
import type { PlanEntry, Tier } from "../api/types";
import { TierBadge } from "./badges";

const ORDER: Tier[] = ["local", "public", "third_party", "active"];
const HEADINGS: Record<Tier, string> = {
  local: "Stays on this host",
  public: "Public infrastructure (keyless)",
  third_party: "Third-party vendors (API key)",
  active: "Active — touches the target directly",
};

/**
 * The privacy contract made visible: every provider that would receive the indicator,
 * exactly what it receives, and why unavailable ones are unavailable. Nothing runs
 * unless it is ticked here.
 */
export function QueryPlan({
  plan,
  selected,
  onChange,
}: {
  plan: PlanEntry[];
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
}) {
  const toggle = (name: string) => {
    const next = new Set(selected);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    onChange(next);
  };

  return (
    <div className="space-y-4">
      {ORDER.map((tier) => {
        const entries = plan.filter((p) => p.tier === tier);
        if (entries.length === 0) return null;
        return (
          <section key={tier} aria-label={HEADINGS[tier]}>
            <div className="mb-1.5 flex items-center gap-2">
              <TierBadge tier={tier} />
              <h3 className="h-label">{HEADINGS[tier]}</h3>
            </div>
            <ul className="divide-y divide-ink-600/50 rounded-md border border-ink-600/70">
              {entries.map((p) => {
                const disabled = p.state !== "available";
                const forced = p.provider === "local";
                return (
                  <li key={p.provider} className={`flex gap-3 px-3 py-2.5 ${disabled ? "opacity-60" : ""}`}>
                    <input
                      id={`plan-${p.provider}`}
                      type="checkbox"
                      className="mt-1 h-4 w-4 accent-sky-400"
                      checked={forced || (!disabled && selected.has(p.provider))}
                      disabled={disabled || forced}
                      onChange={() => toggle(p.provider)}
                    />
                    <label htmlFor={`plan-${p.provider}`} className="min-w-0 flex-1 cursor-pointer">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium">{p.display_name}</span>
                        {p.state === "not_configured" && (
                          <span className="badge border-ink-500 text-fg-dim">
                            <KeyRound size={11} aria-hidden /> not configured
                          </span>
                        )}
                        {p.state === "blocked" && (
                          <span className="badge border-orange-400/50 text-orange-300">
                            <Ban size={11} aria-hidden /> blocked
                          </span>
                        )}
                      </div>
                      <p className="mt-0.5 text-xs text-fg-muted">{p.description}</p>
                      {disabled ? (
                        <p className="mt-1 text-xs text-orange-200/90">{p.reason}</p>
                      ) : (
                        <p className="mt-1 text-xs text-fg-dim">
                          <span className="text-fg-muted">Sends: </span>
                          {p.data_shared}
                        </p>
                      )}
                    </label>
                  </li>
                );
              })}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

export function defaultSelection(plan: PlanEntry[]): Set<string> {
  return new Set(plan.filter((p) => p.selected_by_default && p.state === "available").map((p) => p.provider));
}
