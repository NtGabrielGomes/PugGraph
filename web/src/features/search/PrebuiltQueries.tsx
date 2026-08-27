// Pre-built queries panel (BloodHound/Pughound-style): a collapsible catalog of
// offensive queries with live counts. Selecting one scopes the map — everything
// outside the query dims — and opens the abuse card in the inspector's "abuse"
// tab on the right.

import { useMemo, useState } from "react";
import { PREBUILT_QUERIES, type PrebuiltQuery } from "@/graph/prebuiltQueries";
import { useStore } from "@/state/store";
import { Icon } from "@/ui";

export function PrebuiltQueries() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const queryScope = useStore((s) => s.queryScope);
  const setQueryScope = useStore((s) => s.setQueryScope);
  const setInspectorTab = useStore((s) => s.setInspectorTab);

  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  // Live counts, recomputed with the graph.
  const counts = useMemo(() => {
    const m = new Map<PrebuiltQuery, { nodes: number; edges: number }>();
    for (const g of PREBUILT_QUERIES)
      for (const q of g.items) {
        const s = q.match(nodes, edges);
        m.set(q, { nodes: s.nodeIds.length, edges: s.edgeIds.length });
      }
    return m;
  }, [nodes, edges]);

  const toggle = (q: PrebuiltQuery) => {
    if (queryScope?.label === q.name) {
      setQueryScope(null);
      return;
    }
    const s = q.match(nodes, edges);
    setQueryScope({ label: q.name, nodeIds: s.nodeIds, edgeIds: s.edgeIds });
    setInspectorTab("abuse"); // the reading material lives in the inspector
  };

  const toggleGroup = (g: string) =>
    setCollapsed((c) => {
      const n = new Set(c);
      if (n.has(g)) n.delete(g);
      else n.add(g);
      return n;
    });

  return (
    <div className="pbq">
      <div className="pbqhead">
        <span className="pbqtitle">Queries</span>
        {queryScope && (
          <button className="linklike small" onClick={() => setQueryScope(null)}>
            clear
          </button>
        )}
      </div>
      <button
        className={"pbqbtn" + (queryScope === null ? " active" : "")}
        onClick={() => setQueryScope(null)}
      >
        All
      </button>
      {PREBUILT_QUERIES.map((g) => (
        <div key={g.group} className="pbqgroup">
          <button className="pbqgrouphead" onClick={() => toggleGroup(g.group)} aria-expanded={!collapsed.has(g.group)}>
            <Icon name="chevron-down" size={11} className={collapsed.has(g.group) ? "flip-left" : ""} /> {g.group}
          </button>
          {!collapsed.has(g.group) &&
            g.items.map((q) => {
              const c = counts.get(q)!;
              const total = c.nodes + c.edges;
              const isActive = queryScope?.label === q.name;
              return (
                <button
                  key={q.name}
                  className={"pbqbtn" + (isActive ? " active" : "")}
                  disabled={total === 0 && !isActive}
                  title={q.description}
                  onClick={() => toggle(q)}
                >
                  <span className="pbqname">{q.name}</span>
                  <span className="pbqcount">{total}</span>
                </button>
              );
            })}
        </div>
      ))}
    </div>
  );
}
