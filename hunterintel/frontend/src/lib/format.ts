import type { IndicatorType } from "../api/types";

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").slice(0, 16) + "Z";
}

export function timeAgo(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.round((now - t) / 1000);
  if (s < 0) return `in ${humanSeconds(-s)}`;
  if (s < 45) return "just now";
  return `${humanSeconds(s)} ago`;
}

function humanSeconds(s: number): string {
  if (s < 3600) return `${Math.max(Math.round(s / 60), 1)} min`;
  if (s < 86400) return `${Math.round(s / 3600)} h`;
  if (s < 86400 * 60) return `${Math.round(s / 86400)} d`;
  if (s < 86400 * 730) return `${Math.round(s / (86400 * 30))} mo`;
  return `${Math.round(s / (86400 * 365))} y`;
}

/** Defang an indicator for safe pasting into chat/tickets (hxxps://evil[.]example). */
export function defang(value: string, type: IndicatorType): string {
  if (type === "domain" || type === "ip" || type === "url" || type === "email") {
    return value.replace(/^http/i, "hxxp").replace(/@/g, "[@]").replace(/\./g, "[.]");
  }
  return value;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function pretty(label: string): string {
  return label.replace(/[_.]/g, " ").replace(/\s+/g, " ").trim();
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
