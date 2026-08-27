// One node row in the navigator tree: a color glyph, the label, a strip of
// status badges (on an attack path / has findings / has credentials) and the
// click-to-cycle compromise dot. Presentational only — all behavior arrives
// through callbacks so the row holds no state of its own.

import { nodeKindLabel } from "@/domain/catalog";
import { compromiseColor } from "@/viz/viz";
import { Icon } from "@/ui";
import type { Row } from "@/features/navigator/grouping";

export interface NodeRowProps {
  row: Extract<Row, { type: "node" }>;
  selected: boolean;
  active: boolean;
  glyphColor: string;
  hasFindings: boolean;
  hasCreds: boolean;
  onPath: boolean;
  /** This row's focus scope is the one dimming the map. */
  focused: boolean;
  onChoose: () => void;
  onContext: (e: React.MouseEvent) => void;
  onCycle: () => void;
  onFocus: () => void;
}

export function NodeRow({
  row,
  selected,
  active,
  glyphColor,
  hasFindings,
  hasCreds,
  onPath,
  focused,
  onChoose,
  onContext,
  onCycle,
  onFocus,
}: NodeRowProps) {
  const n = row.node;
  const compromised = n.compromise_level !== "unknown" && n.compromise_level !== "none";

  return (
    <div
      id={`gnav-${row.key}`}
      data-key={row.key}
      role="treeitem"
      aria-level={2}
      aria-selected={selected}
      className={"ovitem trow" + (selected ? " active" : "") + (active ? " kbd" : "")}
      onClick={onChoose}
      onContextMenu={onContext}
    >
      <span className="ovdot" style={{ background: glyphColor }} />
      <span className="ovlabel">{n.label || n.id}</span>
      <span className="visually-hidden">
        {nodeKindLabel(n.kind)}
        {onPath ? ", on an attack path" : ""}
      </span>
      <span className="ovbadges">
        {onPath && <Icon name="path" size={11} className="ovb-path" title="On an attack path" />}
        {hasFindings && <Icon name="alert" size={11} className="ovb-find" title="Has findings" />}
        {hasCreds && <Icon name="key" size={11} className="ovb-cred" title="Has credentials" />}
        <button
          type="button"
          className={"ovfocus" + (focused ? " on" : "")}
          title={focused ? "Clear focus (show everything)" : "Focus: dim everything except this node and its neighborhood"}
          aria-label={focused ? "Clear focus" : `Focus ${n.label || n.id} and its neighborhood`}
          aria-pressed={focused}
          onClick={(e) => {
            e.stopPropagation();
            onFocus();
          }}
        ><Icon name="focus" size={11} /></button>
        <button
          type="button"
          className="ovcmp-btn"
          title={`Access: ${n.compromise_level}. Click to change`}
          aria-label={`Access level ${n.compromise_level}, click to cycle`}
          onClick={(e) => {
            e.stopPropagation();
            onCycle();
          }}
          style={{
            background: compromised ? compromiseColor(n.compromise_level) : "transparent",
            borderColor: compromiseColor(n.compromise_level),
          }}
        />
      </span>
    </div>
  );
}
