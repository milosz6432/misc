import cytoscape, { type Core, type ElementDefinition, type LayoutOptions } from "cytoscape";
import { ExternalLink } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { Graph, GraphEdge, GraphNode } from "../api/types";
import { pretty } from "../lib/format";
import { ASSURANCE_COLOR, AssuranceBadge, TYPE_COLOR, VerdictBadge } from "./badges";
import { DataView } from "./DataView";

const VERDICT_BORDER: Record<string, string> = {
  malicious: "#f87171",
  suspicious: "#fb923c",
  low_risk: "#facc15",
  no_detections: "#34d399",
  unknown: "#33445a",
};
const SHAPE: Record<string, string> = {
  domain: "ellipse",
  ip: "round-rectangle",
  url: "tag",
  hash: "diamond",
  certificate: "hexagon",
  asn: "octagon",
  email: "round-tag",
};
const LAYOUTS = ["cose", "concentric", "breadthfirst", "circle"] as const;
type LayoutName = (typeof LAYOUTS)[number];

function layoutFor(name: LayoutName): LayoutOptions {
  const base = { name, animate: false, fit: true, padding: 30 };
  if (name === "cose")
    return {
      ...base,
      randomize: true,
      nodeDimensionsIncludeLabels: true,
      nodeRepulsion: () => 120000,
      nodeOverlap: 40,
      idealEdgeLength: () => 130,
      edgeElasticity: () => 80,
      gravity: 0.35,
      componentSpacing: 80,
      numIter: 2000,
    } as LayoutOptions;
  if (name === "concentric") return { ...base, concentric: (n: cytoscape.NodeSingular) => n.degree(false), levelWidth: () => 2 } as LayoutOptions;
  return base as LayoutOptions;
}

type Selection = { kind: "node"; node: GraphNode } | { kind: "edge"; edge: GraphEdge; from: GraphNode; to: GraphNode } | null;

export function GraphView({ graph, height = 520 }: { graph: Graph; height?: number }) {
  const host = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const [layout, setLayout] = useState<LayoutName>("cose");
  const [selection, setSelection] = useState<Selection>(null);

  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  const elements = useMemo<ElementDefinition[]>(() => {
    const nodes: ElementDefinition[] = graph.nodes.map((n) => ({
      data: { id: `n${n.id}`, label: n.label, type: n.type, verdict: n.verdict, root: n.is_root ? 1 : 0, tracked: n.tracked ? 1 : 0, size: 22 + Math.min(n.degree, 12) * 2.5 },
    }));
    const edges: ElementDefinition[] = graph.edges.map((e, i) => ({
      data: { id: `e${i}`, source: `n${e.source}`, target: `n${e.target}`, label: pretty(e.rel_type), assurance: e.assurance, idx: i },
    }));
    return [...nodes, ...edges];
  }, [graph]);

  useEffect(() => {
    if (!host.current) return;
    const instance = cytoscape({
      container: host.current,
      elements,
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.25,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "background-color": (n: cytoscape.NodeSingular) => TYPE_COLOR[n.data("type") as keyof typeof TYPE_COLOR] ?? "#94a3b8",
            "background-opacity": 0.9,
            shape: ((n: cytoscape.NodeSingular) => SHAPE[n.data("type") as string] ?? "ellipse") as unknown as "ellipse",
            width: "data(size)",
            height: "data(size)",
            "border-width": (n: cytoscape.NodeSingular) => (n.data("root") ? 4 : 2),
            "border-color": (n: cytoscape.NodeSingular) => VERDICT_BORDER[n.data("verdict") as string] ?? "#33445a",
            opacity: (n: cytoscape.NodeSingular) => (n.data("tracked") || n.data("root") ? 1 : 0.65),
            color: "#d8e0ea",
            "font-size": 9,
            "font-family": "JetBrains Mono, ui-monospace, monospace",
            "text-valign": "bottom",
            "text-margin-y": 4,
            "text-outline-color": "#0b0f14",
            "text-outline-width": 2,
            "min-zoomed-font-size": 7,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.8,
            "line-color": (e: cytoscape.EdgeSingular) => ASSURANCE_COLOR[e.data("assurance") as keyof typeof ASSURANCE_COLOR] ?? "#617086",
            "target-arrow-color": (e: cytoscape.EdgeSingular) => ASSURANCE_COLOR[e.data("assurance") as keyof typeof ASSURANCE_COLOR] ?? "#617086",
            "line-style": (e: cytoscape.EdgeSingular) => (e.data("assurance") === "verified" ? "solid" : e.data("assurance") === "provider_claim" ? "dashed" : "dotted"),
            opacity: 0.8,
            label: "data(label)",
            "font-size": 9,
            color: "#8e9bad",
            "text-rotation": "autorotate",
            "text-background-color": "#0b0f14",
            "text-background-opacity": 0.85,
            "text-background-padding": "2px",
            "min-zoomed-font-size": 13, // edge labels appear once you zoom in (or select the edge)
          },
        },
        { selector: "edge:selected", style: { label: "data(label)", "min-zoomed-font-size": 0, width: 2.5, opacity: 1 } },
        { selector: ":selected", style: { "overlay-color": "#38bdf8", "overlay-opacity": 0.25, "overlay-padding": 6 } },
      ],
    });
    cy.current = instance;
    instance.on("tap", "node", (evt) => {
      const id = Number(String(evt.target.id()).slice(1));
      const node = byId.get(id);
      if (node) setSelection({ kind: "node", node });
    });
    instance.on("tap", "edge", (evt) => {
      const edge = graph.edges[evt.target.data("idx") as number];
      const from = edge && byId.get(edge.source);
      const to = edge && byId.get(edge.target);
      if (edge && from && to) setSelection({ kind: "edge", edge, from, to });
    });
    instance.on("tap", (evt) => evt.target === instance && setSelection(null));
    return () => {
      instance.destroy();
      cy.current = null;
    };
  }, [elements, byId, graph.edges]);

  useEffect(() => {
    cy.current?.layout(layoutFor(layout)).run();
  }, [layout, elements]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 text-xs text-fg-muted">
          <span>
            {graph.stats.nodes} nodes · {graph.stats.edges} edges
            {graph.stats.inferred_edges > 0 && ` (${graph.stats.inferred_edges} inferred)`}
          </span>
          {graph.truncated && <span className="text-orange-300">truncated at {graph.stats.max_nodes} nodes</span>}
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-fg-muted" htmlFor="layout">
            Layout
          </label>
          <select id="layout" className="input w-auto py-1 text-xs" value={layout} onChange={(e) => setLayout(e.target.value as LayoutName)}>
            {LAYOUTS.map((l) => (
              <option key={l}>{l}</option>
            ))}
          </select>
          <button className="btn" onClick={() => cy.current?.fit(undefined, 30)}>
            Fit
          </button>
        </div>
      </div>

      <div className="relative overflow-hidden rounded-lg border border-ink-600/70 bg-ink-950" style={{ height }}>
        <div ref={host} className="absolute inset-0" aria-label="Relationship graph" />
        {graph.nodes.length === 0 && (
          <div className="absolute inset-0 grid place-items-center text-xs text-fg-dim">No relationships recorded yet. Enrich the indicator to discover some.</div>
        )}
      </div>
      <Legend />

      {selection && <Details selection={selection} />}
    </div>
  );
}

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-1 px-1 text-[11px] text-fg-muted" aria-label="Graph legend">
      <span className="flex items-center gap-2">
        <span className="inline-block w-6 border-t-2" style={{ borderColor: ASSURANCE_COLOR.verified }} /> verified
      </span>
      <span className="flex items-center gap-2">
        <span className="inline-block w-6 border-t-2 border-dashed" style={{ borderColor: ASSURANCE_COLOR.provider_claim }} /> provider claim
      </span>
      <span className="flex items-center gap-2">
        <span className="inline-block w-6 border-t-2 border-dotted" style={{ borderColor: ASSURANCE_COLOR.inferred }} /> inferred
      </span>
      <span>node border = verdict · faded node = discovered, not adopted · click a node or edge for details · zoom in for edge labels</span>
    </div>
  );
}

function NodeLine({ n }: { n: GraphNode }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className="mono break-all">{n.value}</span>
      <Link to={`/indicators/${n.id}`} className="text-accent hover:underline" aria-label={`Open ${n.value}`}>
        <ExternalLink size={12} />
      </Link>
    </span>
  );
}

function Details({ selection }: { selection: NonNullable<Selection> }) {
  if (selection.kind === "node") {
    const n = selection.node;
    return (
      <div className="card p-3 text-xs">
        <div className="mb-1 flex flex-wrap items-center gap-2">
          <span className="h-label">{n.type}</span>
          <VerdictBadge verdict={n.verdict} />
          {!n.tracked && <span className="badge border-ink-500 text-fg-dim">discovered, not adopted</span>}
        </div>
        <NodeLine n={n} />
      </div>
    );
  }
  const { edge, from, to } = selection;
  return (
    <div className="card space-y-2 p-3 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <NodeLine n={from} />
        <span className="text-fg-muted">— {pretty(edge.rel_type)} →</span>
        <NodeLine n={to} />
        <AssuranceBadge assurance={edge.assurance} />
      </div>
      <div>
        <div className="h-label mb-1">Evidence</div>
        <ul className="space-y-1">
          {edge.evidence.map((e, i) => (
            <li key={i} className="flex items-center gap-2">
              <AssuranceBadge assurance={e.assurance} />
              <span className="mono">{e.source}</span>
              {e.last_seen && <span className="text-fg-dim">last seen {e.last_seen.slice(0, 10)}</span>}
            </li>
          ))}
        </ul>
      </div>
      {Object.keys(edge.attrs).length > 0 && <DataView data={edge.attrs} />}
    </div>
  );
}
