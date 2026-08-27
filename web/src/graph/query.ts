// A small structured query language for filtering the topology. A query is a
// space-separated list of terms, ANDed together:
//   kind:domain_controller        node kind is one of (comma list)
//   compromise:>=admin            compromise level compared by severity rank
//   tag:crown-jewel               has any of the listed tags
//   confidence:suspected          provenance confidence is one of
//   has:finding | has:spn         field present/non-empty (finding == has findings)
//   <bare word>                   substring of label, a string field, or a tag
// It powers the map filter and the saved "filters" (which subsume the old lenses).

import type { GraphNode } from "@/domain/types";
import { COMPROMISE_RANK } from "@/viz/viz";

type Pred = (n: GraphNode) => boolean;

const compromiseCmp = (op: string, level: string): Pred => {
  const target = COMPROMISE_RANK[level as keyof typeof COMPROMISE_RANK];
  if (target === undefined) return () => true;
  return (n) => {
    const r = COMPROMISE_RANK[n.compromise_level];
    switch (op) {
      case ">=": return r >= target;
      case ">": return r > target;
      case "<=": return r <= target;
      case "<": return r < target;
      default: return r === target;
    }
  };
};

const textMatch = (word: string): Pred => {
  const w = word.toLowerCase();
  return (n) => {
    if ((n.label || "").toLowerCase().includes(w)) return true;
    for (const v of Object.values(n.fields)) if (typeof v === "string" && v.toLowerCase().includes(w)) return true;
    return n.tags.some((t) => t.toLowerCase().includes(w));
  };
};

/** Compile a query string into a predicate (parsed once, applied per node). */
export function parseQuery(query: string): Pred {
  const tokens = query.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return () => true;
  const preds: Pred[] = [];
  for (const tok of tokens) {
    const m = tok.match(/^(\w+):(.+)$/);
    if (!m) {
      preds.push(textMatch(tok));
      continue;
    }
    const field = m[1]!;
    const raw = m[2]!;
    const values = raw.split(",").map((s) => s.toLowerCase());
    switch (field) {
      case "kind":
        preds.push((n) => values.includes(n.kind));
        break;
      case "tag":
        preds.push((n) => n.tags.some((t) => values.includes(t.toLowerCase())));
        break;
      case "confidence":
        preds.push((n) => values.includes(n.provenance.confidence));
        break;
      case "compromise": {
        const cm = raw.match(/^(>=|<=|>|<)?(\w+)$/);
        if (cm) preds.push(compromiseCmp(cm[1] ?? "=", cm[2]!));
        break;
      }
      case "has":
        preds.push((n) =>
          values.some((k) => {
            if (k === "finding" || k === "findings") {
              return Array.isArray(n.fields["findings"]) && (n.fields["findings"] as unknown[]).length > 0;
            }
            const v = n.fields[k];
            return v !== undefined && v !== "" && v !== false;
          }),
        );
        break;
      default:
        preds.push(textMatch(tok));
        break;
    }
  }
  return (n) => preds.every((p) => p(n));
}

export const matchesQuery = (n: GraphNode, query: string): boolean => parseQuery(query)(n);
