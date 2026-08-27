// Derived state: memoized, read-only projections of the campaign, computed off
// the edit hot path. Components subscribe to these rather than recomputing graph
// algorithms inline. See web/ARCHITECTURE.md.

export { useGraphModel } from "@/data/derived/useGraphModel";
export { useAttackPaths } from "@/data/derived/useAttackPaths";
