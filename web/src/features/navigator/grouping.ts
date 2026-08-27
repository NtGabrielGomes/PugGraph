// Pure helpers that turn the flat list of visible nodes into the grouped,
// collapsible tree the navigator renders. No React and no store access — data
// in, rows out — so the component stays a thin view over this logic and the
// transformation is unit-testable on its own.

import { NODE_GROUPS } from "@/domain/catalog";
import type { CompromiseLevel, GraphNode, NodeKind } from "@/domain/types";

const FALLBACK_GROUP = "Other";

// The canonical group each node kind belongs to, and the order groups appear in,
// both derived once from the catalog.
const KIND_GROUP = new Map<NodeKind, string>();
const GROUP_ORDER: string[] = [];
for (const group of NODE_GROUPS) {
  GROUP_ORDER.push(group.group);
  for (const k of group.kinds) KIND_GROUP.set(k.kind as NodeKind, group.group);
}

export const groupOf = (kind: NodeKind): string => KIND_GROUP.get(kind) ?? FALLBACK_GROUP;

// Clicking a node's compromise dot cycles it through the meaningful access levels.
const CYCLE: CompromiseLevel[] = ["unknown", "user", "admin", "system", "domain_admin", "none"];
export const nextLevel = (level: CompromiseLevel): CompromiseLevel =>
  CYCLE[(CYCLE.indexOf(level) + 1) % CYCLE.length]!;

export interface NodeGroup {
  group: string;
  items: GraphNode[];
}

export type Row =
  | { type: "group"; key: string; group: string; count: number; expanded: boolean }
  | { type: "node"; key: string; node: GraphNode; group: string };

/** Filter nodes by a free-text query, then bucket them into catalog-ordered groups. */
export function groupNodes(nodes: GraphNode[], filter: string): NodeGroup[] {
  const f = filter.trim().toLowerCase();
  const buckets = new Map<string, GraphNode[]>();

  for (const n of nodes) {
    if (f && !`${n.label} ${n.kind} ${n.tags.join(" ")}`.toLowerCase().includes(f)) continue;
    const group = groupOf(n.kind);
    const arr = buckets.get(group) ?? buckets.set(group, []).get(group)!;
    arr.push(n);
  }

  for (const arr of buckets.values()) {
    arr.sort((a, b) => (a.label || a.id).localeCompare(b.label || b.id));
  }

  const ordered = GROUP_ORDER.filter((g) => buckets.has(g));
  const extra = [...buckets.keys()].filter((g) => !GROUP_ORDER.includes(g));
  return [...ordered, ...extra].map((group) => ({ group, items: buckets.get(group)! }));
}

/** Flatten groups into renderable rows, hiding the children of collapsed groups. */
export function buildRows(groups: NodeGroup[], collapsed: Set<string>): Row[] {
  const rows: Row[] = [];
  for (const { group, items } of groups) {
    const expanded = !collapsed.has(group);
    rows.push({ type: "group", key: `grp:${group}`, group, count: items.length, expanded });
    if (expanded) {
      for (const n of items) rows.push({ type: "node", key: `node:${n.id}`, node: n, group });
    }
  }
  return rows;
}
