// The single derived view of the topology, shared by the Cytoscape map and the
// accessible keyboard navigator (GraphNav) so the two can never disagree about
// what is shown. It applies the lens + timeline filter once, computes compound
// grouping and adjacency, and exposes a human/AT-readable description per node.

import { nodeKindLabel } from "@/domain/catalog";
import type { GraphEdge, GraphNode, CompromiseLevel } from "@/domain/types";
import { computeCompoundParents } from "@/graph/topology";
import { asOf } from "@/graph/timeline";
import { parseQuery } from "@/graph/query";
import type { Lens } from "@/state/store";

/** Whether a node passes the active lens. Centralized here so the map and the
 * navigator filter identically (no drift). */
export const isVisible = (n: GraphNode, lens: Lens): boolean => {
  switch (lens) {
    case "compromised":
      return n.compromise_level !== "unknown" && n.compromise_level !== "none";
    case "entry":
      return typeof n.fields["compromise_method"] === "string" && n.fields["compromise_method"] !== "";
    case "ad":
      return [
        "domain", "forest", "domain_controller", "organizational_unit", "gpo",
        "certificate_authority", "user_account", "group",
      ].includes(n.kind);
    case "unconfirmed":
      return n.provenance.confidence !== "confirmed";
    default:
      return true;
  }
};

export interface Adj {
  edge: GraphEdge;
  neighborId: string;
  dir: "out" | "in";
}

export interface GraphModel {
  visibleNodes: GraphNode[];
  visibleEdges: GraphEdge[];
  byId: Map<string, GraphNode>;
  /** child id -> compound parent id (Cytoscape `parent`). */
  parents: Record<string, string>;
  parentIds: Set<string>;
  /** parent id -> ordered child ids. */
  childrenOf: Map<string, string[]>;
  /** Top-level node ids (no compound parent), in display order. */
  roots: string[];
  /** node id -> its incident edges (both directions), for edge traversal. */
  adjacency: Map<string, Adj[]>;
}

const byLabel = (a: GraphNode, b: GraphNode): number =>
  (a.label || a.id).localeCompare(b.label || b.id);

/** Build the shared model from raw nodes/edges under the lens, the structured
 * filter query, and the timeline — applied identically for the map and the
 * navigator so they never disagree about what is shown. */
export function buildGraphModel(
  nodes: GraphNode[],
  edges: GraphEdge[],
  lens: Lens,
  viewAsOf: number | null,
  filterQuery = "",
  hiddenEdgeKinds?: ReadonlySet<string>,
  /** BloodHound-style explore: when set, ONLY these ids render. */
  scope?: { nodeIds: ReadonlySet<string>; edgeIds: ReadonlySet<string> },
): GraphModel {
  const pred = parseQuery(filterQuery);
  let visibleNodes = asOf(nodes.filter((n) => isVisible(n, lens) && pred(n)), viewAsOf);
  if (scope) visibleNodes = visibleNodes.filter((n) => scope.nodeIds.has(n.id));
  const ids = new Set(visibleNodes.map((n) => n.id));
  const visibleEdges = asOf(
    edges.filter(
      (e) =>
        ids.has(e.source) &&
        ids.has(e.target) &&
        !hiddenEdgeKinds?.has(e.kind) &&
        (!scope || scope.edgeIds.has(e.id)),
    ),
    viewAsOf,
  );
  const byId = new Map(visibleNodes.map((n) => [n.id, n] as const));

  const parents = computeCompoundParents(visibleNodes, visibleEdges);
  const parentIds = new Set(Object.values(parents));

  const childrenOf = new Map<string, string[]>();
  for (const n of [...visibleNodes].sort(byLabel)) {
    const p = parents[n.id];
    if (p) {
      const arr = childrenOf.get(p) ?? [];
      arr.push(n.id);
      childrenOf.set(p, arr);
    }
  }
  const roots = [...visibleNodes].sort(byLabel).filter((n) => !parents[n.id]).map((n) => n.id);

  const adjacency = new Map<string, Adj[]>();
  const push = (id: string, a: Adj) => {
    const arr = adjacency.get(id) ?? [];
    arr.push(a);
    adjacency.set(id, arr);
  };
  for (const e of visibleEdges) {
    push(e.source, { edge: e, neighborId: e.target, dir: "out" });
    push(e.target, { edge: e, neighborId: e.source, dir: "in" });
  }

  return { visibleNodes, visibleEdges, byId, parents, parentIds, childrenOf, roots, adjacency };
}

const COMPROMISE_PHRASE: Record<CompromiseLevel, string> = {
  unknown: "compromise unknown",
  none: "not compromised",
  user: "user-level compromise",
  admin: "admin-level compromise",
  system: "system-level compromise",
  domain_admin: "domain-admin compromise",
};

/** A screen-reader sentence describing a node and its relation count. */
export function describeNode(n: GraphNode, adjacency: Map<string, Adj[]>): string {
  const rel = adjacency.get(n.id)?.length ?? 0;
  return `${n.label || n.id}, ${nodeKindLabel(n.kind)}, ${COMPROMISE_PHRASE[n.compromise_level]}, ${rel} relation${rel === 1 ? "" : "s"}`;
}
