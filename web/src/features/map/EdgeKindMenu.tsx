// The relation picker shown when connecting two nodes. It offers ONLY the edge
// kinds that make sense for the ordered (source kind → target kind) pair —
// `edgeKindsFor` — instead of all 34, so the operator can't draw a nonsensical
// relation by accident. `custom` is always present as the escape hatch.

import { edgeKindLabel, edgeKindsFor } from "@/domain/catalog";
import { nodeKindLabel } from "@/domain/catalog";
import { edgeGroup, EDGE_GROUP_STYLE } from "@/viz/viz";
import type { EdgeKind, NodeKind } from "@/domain/types";
import { Popover, menuArrowKeys } from "@/ui";

export interface EdgeMenuTarget {
  sourceId: string;
  targetId: string;
  sourceKind: NodeKind;
  targetKind: NodeKind;
  x: number;
  y: number;
}

export function EdgeKindMenu({
  target,
  onPick,
  onClose,
}: {
  target: EdgeMenuTarget;
  onPick: (kind: EdgeKind) => void;
  onClose: () => void;
}) {
  const kinds = edgeKindsFor(target.sourceKind, target.targetKind);
  // `custom` is always last in declaration order; keep canonical kinds first.
  const canonical = kinds.filter((k) => k !== "custom");
  const heading = `${nodeKindLabel(target.sourceKind)} → ${nodeKindLabel(target.targetKind)}`;

  return (
    <Popover x={target.x} y={target.y} onClose={onClose} label={`Relation from ${heading}`}>
      <div className="mhead">{heading}</div>
      {canonical.length === 0 && <div className="edgemenu-empty">No canonical relation. Use Custom.</div>}
      <ul className="menu" onKeyDown={menuArrowKeys}>
        {canonical.map((k) => (
          <li key={k}>
            <button type="button" role="menuitem" className="mitem" onClick={() => onPick(k)}>
              <span className="dot" style={{ background: EDGE_GROUP_STYLE[edgeGroup(k)].color }} />
              {edgeKindLabel(k)}
            </button>
          </li>
        ))}
        <li>
          <button type="button" role="menuitem" className="mitem custom" onClick={() => onPick("custom")}>
            <span className="dot" style={{ background: EDGE_GROUP_STYLE.custom.color }} />
            custom...
          </button>
        </li>
      </ul>
    </Popover>
  );
}
