import type { Verdict } from "../api/types";

const COLOR: Record<Verdict, string> = {
  malicious: "#f87171",
  suspicious: "#fb923c",
  low_risk: "#facc15",
  no_detections: "#34d399",
  unknown: "#617086",
};

/** Semi-circular gauge. A null score is drawn empty and labelled n/a — never as zero risk. */
export function RiskMeter({ score, verdict, size = 120 }: { score: number | null; verdict: Verdict; size?: number }) {
  const r = 46;
  const c = Math.PI * r;
  const pct = score === null ? 0 : Math.min(Math.max(score, 0), 100) / 100;
  const color = COLOR[verdict];
  return (
    <svg
      width={size}
      height={size * 0.62}
      viewBox="0 0 120 74"
      role="img"
      aria-label={score === null ? "Risk score not available" : `Risk score ${score} out of 100`}
    >
      <path d="M 14 62 A 46 46 0 0 1 106 62" fill="none" stroke="#1a232f" strokeWidth="10" strokeLinecap="round" />
      <path
        d="M 14 62 A 46 46 0 0 1 106 62"
        fill="none"
        stroke={color}
        strokeWidth="10"
        strokeLinecap="round"
        strokeDasharray={`${c * pct} ${c}`}
      />
      <text x="60" y="56" textAnchor="middle" fontSize="24" fontWeight="600" fill="#d8e0ea" className="tabular-nums">
        {score === null ? "n/a" : score}
      </text>
      <text x="60" y="71" textAnchor="middle" fontSize="8" fill="#8e9bad" letterSpacing="1">
        RISK
      </text>
    </svg>
  );
}
