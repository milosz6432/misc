import type {
  Classified,
  Classification,
  Comparison,
  EnrichResult,
  FileHashResult,
  Finding,
  Graph,
  Health,
  IndicatorDetail,
  IndicatorSummary,
  IndicatorType,
  InvestigationDetail,
  InvestigationRow,
  Note,
  Observation,
  Paged,
  ProviderInfo,
  ProviderRun,
  Severity,
  Stats,
  TLP,
} from "./types";

const TOKEN_KEY = "hunterintel.token";
const BASE = "/api/v1";

/** The token lives in sessionStorage only (cleared when the tab closes); storage may be unavailable. */
export const auth = {
  get(): string | null {
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  set(token: string): void {
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
    } catch {
      /* private mode: the token simply will not persist */
    }
  },
  clear(): void {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      /* ignore */
    }
  },
};

type UnauthorizedListener = () => void;
const listeners = new Set<UnauthorizedListener>();
export const onUnauthorized = (fn: UnauthorizedListener): (() => void) => {
  listeners.add(fn);
  return () => listeners.delete(fn);
};

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

async function toError(res: Response): Promise<ApiError> {
  let code = "http_error";
  let message = `Request failed (HTTP ${res.status})`;
  try {
    const body = (await res.json()) as { detail?: unknown };
    const detail = body.detail;
    if (detail && typeof detail === "object" && "message" in detail) {
      const d = detail as { code?: string; message?: string };
      code = d.code ?? code;
      message = d.message ?? message;
    } else if (Array.isArray(detail)) {
      code = "validation_error";
      message = detail
        .map((e: { msg?: string; loc?: unknown[] }) => `${(e.loc ?? []).slice(1).join(".")}: ${e.msg ?? "invalid"}`)
        .join("; ");
    } else if (typeof detail === "string") {
      message = detail;
    }
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(res.status, code, message);
}

function headers(extra?: HeadersInit): Headers {
  const h = new Headers(extra);
  const token = auth.get();
  if (token) h.set("Authorization", `Bearer ${token}`);
  return h;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const h = headers(init.headers);
  if (init.body && typeof init.body === "string" && !h.has("Content-Type")) h.set("Content-Type", "application/json");
  const res = await fetch(BASE + path, { ...init, headers: h });
  if (res.status === 401) listeners.forEach((fn) => fn());
  if (!res.ok) throw await toError(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

const json = (body: unknown): RequestInit => ({ body: JSON.stringify(body) });
const qs = (params: Record<string, string | number | boolean | undefined | null>): string => {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") u.set(k, String(v));
  const s = u.toString();
  return s ? `?${s}` : "";
};

export interface ListParams {
  q?: string;
  type?: string;
  verdict?: string;
  classification?: string;
  tag?: string;
  include_expired?: boolean;
  sort?: string;
  desc?: boolean;
  limit?: number;
  offset?: number;
}

export const api = {
  health: () => request<Health>("/health"),
  providers: () => request<ProviderInfo[]>("/providers"),
  stats: () => request<Stats>("/stats"),

  classify: (value: string, type?: IndicatorType) =>
    request<Classified>("/indicators/classify", { method: "POST", ...json({ value, type }) }),
  enrich: (value: string, providers: string[] | undefined, type?: IndicatorType, refresh = false) =>
    request<EnrichResult>("/enrich", { method: "POST", ...json({ value, type, providers, refresh }) }),

  listIndicators: (p: ListParams) => request<Paged<IndicatorSummary>>(`/indicators${qs({ ...p })}`),
  indicator: (id: number) => request<IndicatorDetail>(`/indicators/${id}`),
  observations: (id: number) => request<{ items: Observation[] }>(`/indicators/${id}/observations?limit=500`),
  runs: (id: number) => request<{ items: ProviderRun[] }>(`/indicators/${id}/runs`),
  graph: (id: number, depth: number, inferred: boolean) =>
    request<Graph>(`/indicators/${id}/graph${qs({ depth, inferred })}`),
  patchIndicator: (
    id: number,
    body: { classification?: Classification; do_not_share?: boolean; add_tags?: string[]; remove_tags?: string[] },
  ) => request<IndicatorDetail>(`/indicators/${id}`, { method: "PATCH", ...json(body) }),
  deleteIndicator: (id: number) => request<void>(`/indicators/${id}`, { method: "DELETE" }),
  compare: (ids: number[]) => request<Comparison>("/compare", { method: "POST", ...json({ indicator_ids: ids }) }),

  investigations: () => request<{ total: number; items: InvestigationRow[] }>("/investigations"),
  createInvestigation: (title: string, description: string, tlp: TLP) =>
    request<InvestigationDetail>("/investigations", { method: "POST", ...json({ title, description, tlp }) }),
  investigation: (id: number) => request<InvestigationDetail>(`/investigations/${id}`),
  patchInvestigation: (id: number, body: Partial<{ title: string; description: string; status: "open" | "closed"; tlp: TLP }>) =>
    request<InvestigationDetail>(`/investigations/${id}`, { method: "PATCH", ...json(body) }),
  deleteInvestigation: (id: number) => request<void>(`/investigations/${id}`, { method: "DELETE" }),
  addMember: (id: number, body: { value?: string; indicator_id?: number }) =>
    request<InvestigationDetail>(`/investigations/${id}/indicators`, { method: "POST", ...json(body) }),
  removeMember: (id: number, indicatorId: number) =>
    request<void>(`/investigations/${id}/indicators/${indicatorId}`, { method: "DELETE" }),
  addNote: (id: number, body: string, indicator_id?: number) =>
    request<Note>(`/investigations/${id}/notes`, { method: "POST", ...json({ body, indicator_id }) }),
  deleteNote: (id: number, noteId: number) => request<void>(`/investigations/${id}/notes/${noteId}`, { method: "DELETE" }),
  addFinding: (
    id: number,
    body: { title: string; body: string; severity: Severity; indicator_id?: number; observation_id?: number },
  ) => request<Finding>(`/investigations/${id}/findings`, { method: "POST", ...json(body) }),
  deleteFinding: (id: number, findingId: number) =>
    request<void>(`/investigations/${id}/findings/${findingId}`, { method: "DELETE" }),
  investigationGraph: (id: number, depth: number, inferred: boolean) =>
    request<Graph>(`/investigations/${id}/graph${qs({ depth, inferred })}`),

  /** Streams the raw file as the body: the server hashes and discards it (nothing is stored). */
  fileHash: (file: File) =>
    request<FileHashResult>("/tools/file-hash", {
      method: "POST",
      body: file,
      headers: { "Content-Type": "application/octet-stream", "X-Filename": file.name.slice(0, 120) },
    }),

  async downloadReport(id: number, format: "md" | "json" | "html", defang: boolean): Promise<void> {
    const res = await fetch(`${BASE}/investigations/${id}/export${qs({ format, defang })}`, { headers: headers() });
    if (res.status === 401) listeners.forEach((fn) => fn());
    if (!res.ok) throw await toError(res);
    const blob = await res.blob();
    const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? `report.${format}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};
