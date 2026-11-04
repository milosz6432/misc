import { Link } from "react-router-dom";
import type { IndicatorSummary } from "../api/types";
import { timeAgo } from "../lib/format";
import { ClassBadge, FreshnessBadge, LockBadge, TypeBadge, VerdictBadge } from "./badges";

export function IndicatorTable({ items, compact = false }: { items: IndicatorSummary[]; compact?: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[13px]">
        <thead className="border-b border-ink-600/70">
          <tr>
            <th className="th">Indicator</th>
            <th className="th">Verdict</th>
            {!compact && <th className="th text-right">Risk</th>}
            {!compact && <th className="th text-right">Conf.</th>}
            <th className="th">Freshness</th>
            {!compact && <th className="th">Tags</th>}
            <th className="th">Last seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-600/40">
          {items.map((i) => (
            <tr key={i.id} className="hover:bg-ink-700/40">
              <td className="td">
                <div className="flex flex-wrap items-center gap-2">
                  <TypeBadge type={i.type} />
                  <Link to={`/indicators/${i.id}`} className="mono break-all text-fg hover:text-accent">
                    {i.value.length > 70 ? i.value.slice(0, 66) + "…" : i.value}
                  </Link>
                  {i.do_not_share && <LockBadge />}
                  <ClassBadge value={i.classification} />
                </div>
              </td>
              <td className="td">
                <VerdictBadge verdict={i.verdict} />
              </td>
              {!compact && <td className="td text-right tabular-nums">{i.risk_score ?? <span className="text-fg-dim">n/a</span>}</td>}
              {!compact && <td className="td text-right tabular-nums">{i.confidence !== null ? `${i.confidence}%` : "—"}</td>}
              <td className="td">
                <FreshnessBadge freshness={i.freshness} />
              </td>
              {!compact && (
                <td className="td">
                  <div className="flex max-w-[16rem] flex-wrap gap-1">
                    {i.tags.slice(0, 4).map((t) => (
                      <span key={t} className="badge border-ink-500 text-fg-muted">
                        {t}
                      </span>
                    ))}
                    {i.tags.length > 4 && <span className="text-xs text-fg-dim">+{i.tags.length - 4}</span>}
                  </div>
                </td>
              )}
              <td className="td whitespace-nowrap text-fg-muted" title={i.last_seen}>
                {timeAgo(i.last_seen)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
