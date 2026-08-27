// Topology orchestration: turn the flat node/edge model into a *structured*
// graph the layout engine can render legibly. The key move is compound grouping
// — a VM is drawn inside its hypervisor, a container inside its host, and a
// domain's members inside the domain — so the picture mirrors real
// infrastructure containment instead of a hairball. The compound parents are
// derived purely from the graph's own edges, so this is testable in isolation
// from Cytoscape.

import type { GraphEdge, GraphNode } from "@/domain/types";

/**
 * Compute the compound parent of each node (Cytoscape `parent`), from
 * containment edges. Virtualization (a host *runs* the child) takes priority
 * over domain membership, and cycles are broken so the result is a forest.
 */
export function computeCompoundParents(nodes: GraphNode[], edges: GraphEdge[]): Record<string, string> {
  const ids = new Set(nodes.map((n) => n.id));
  const parent: Record<string, string> = {};
  const assign = (child: string, p: string): void => {
    if (child === p || !ids.has(child) || !ids.has(p)) return;
    if (!(child in parent)) parent[child] = p; // first (higher-priority) wins
  };

  // 1. Virtualization / hosting containment (highest priority).
  for (const e of edges) {
    if (e.kind === "hosts_vm" || e.kind === "runs_container") assign(e.target, e.source);
    else if (e.kind === "vm_hosted_on") assign(e.source, e.target);
  }
  // 2. Domain membership groups principals/hosts/groups under their domain.
  for (const e of edges) {
    if (e.kind === "member_of_domain") assign(e.source, e.target);
  }

  // 3. Break any cycle (Cytoscape compounds must form a forest): walk each
  //    parent chain; if it revisits a node, drop the originating link.
  for (const start of Object.keys(parent)) {
    const seen = new Set<string>();
    let cur: string | undefined = start;
    while (cur && parent[cur]) {
      if (seen.has(cur)) {
        delete parent[start];
        break;
      }
      seen.add(cur);
      cur = parent[cur];
    }
  }

  return parent;
}

/** The set of node ids that are compound parents (contain at least one child). */
export function compoundParentIds(parents: Record<string, string>): Set<string> {
  return new Set(Object.values(parents));
}
