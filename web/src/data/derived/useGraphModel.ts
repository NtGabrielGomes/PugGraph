// The shared derived graph view as a hook. Both the map and the navigator render
// the SAME topology under the active lens / filter / timeline, so they must agree
// on what is visible — this hook is the one place that derives it, memoized on its
// inputs, so render-time consumers never recompute it by hand or drift apart.

import { useMemo } from "react";
import { useStore } from "@/state/store";
import { buildGraphModel, type GraphModel } from "@/graph/model";

export function useGraphModel(): GraphModel {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const lens = useStore((s) => s.lens);
  const viewAsOf = useStore((s) => s.viewAsOf);
  const filterQuery = useStore((s) => s.filterQuery);
  return useMemo(
    () => buildGraphModel(nodes, edges, lens, viewAsOf, filterQuery),
    [nodes, edges, lens, viewAsOf, filterQuery],
  );
}
