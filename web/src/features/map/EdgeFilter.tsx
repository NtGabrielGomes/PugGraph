// Edge-kind filter (BloodHound CE-style): every relationship type present in
// the campaign, with a live count and a checkbox; unchecked kinds disappear
// from the map. This is the main decluttering control after a big AD import —
// membership/container noise hides without deleting any data.

import { useMemo, useState } from "react";
import { useStore } from "@/state/store";
import { Icon, Popover } from "@/ui";
import { edgeGroup, EDGE_GROUP_STYLE } from "@/viz/viz";
import type { EdgeKind } from "@/domain/types";

export function EdgeFilterButton() {
  const edges = useStore((s) => s.edges);
  const hidden = useStore((s) => s.hiddenEdgeKinds);
  const toggleEdgeKind = useStore((s) => s.toggleEdgeKind);
  const showAllEdgeKinds = useStore((s) => s.showAllEdgeKinds);

  const [at, setAt] = useState<{ x: number; y: number } | null>(null);

  const present = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of edges) counts.set(e.kind, (counts.get(e.kind) ?? 0) + 1);
    // Grouped like the visual legend, kinds sorted by count inside each group.
    const byGroup = new Map<string, [string, number][]>();
    for (const [kind, count] of counts) {
      const g = edgeGroup(kind as EdgeKind);
      const arr = byGroup.get(g) ?? [];
      arr.push([kind, count]);
      byGroup.set(g, arr);
    }
    for (const arr of byGroup.values()) arr.sort((a, b) => b[1] - a[1]);
    return [...byGroup.entries()];
  }, [edges]);

  const open = (e: React.MouseEvent) => {
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    setAt({ x: r.right - 300, y: r.bottom + 6 });
  };

  return (
    <>
      <button
        className={"icon" + (hidden.length ? " armed" : "")}
        title={`Edge filter — ${hidden.length} kind(s) hidden (BloodHound-style declutter)`}
        aria-label="Edge filter"
        aria-pressed={hidden.length > 0}
        onClick={open}
      ><Icon name="filter" size={16} /></button>
      {at && (
        <Popover x={at.x} y={at.y} onClose={() => setAt(null)} label="Edge filter" className="filterpop">
          <div className="edgefilter">
            <div className="edgefilter-head">
              <span className="muted small">{hidden.length ? `${hidden.length} hidden` : "all visible"}</span>
              {hidden.length > 0 && (
                <button className="linklike small" onClick={showAllEdgeKinds}>show all</button>
              )}
            </div>
            {present.map(([group, kinds]) => (
              <div key={group} className="edgefilter-group">
                <div className="edgefilter-gname" style={{ color: EDGE_GROUP_STYLE[group as keyof typeof EDGE_GROUP_STYLE]?.color }}>
                  {group.replace(/_/g, " ")}
                </div>
                {kinds.map(([kind, count]) => (
                  <label key={kind} className="edgefilter-row">
                    <input
                      type="checkbox"
                      checked={!hidden.includes(kind)}
                      onChange={() => toggleEdgeKind(kind)}
                    />
                    <span className="edgefilter-kind">{kind}</span>
                    <span className="edgefilter-count">{count}</span>
                  </label>
                ))}
              </div>
            ))}
          </div>
        </Popover>
      )}
    </>
  );
}
