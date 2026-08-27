// The network navigator: a filterable, keyboard-navigable tree of every visible
// node, grouped by kind. It is the accessible, no-canvas counterpart to the map
// — selecting a row selects the node and centers the map on it. The heavy lifting
// lives in focused modules: `grouping` (data → rows), `useTreeKeyboard` (the ARIA
// tree interaction), `NodeRow` (the row view) and the shared node `Menu`.

import { useEffect, useMemo, useState } from "react";
import { useStore } from "@/state/store";
import { useGraphModel } from "@/data/derived";
import { incidentScope } from "@/graph/prebuiltQueries";
import { kindColor } from "@/viz/viz";
import { describeNode } from "@/graph/model";
import { readFindings } from "@/domain/fieldSchema";
import { mapApi } from "@/features/map/mapApi";
import { buildNodeActions } from "@/features/map/nodeActions";
import { announce, Icon, Menu } from "@/ui";
import { buildRows, groupNodes, groupOf, nextLevel, type Row } from "@/features/navigator/grouping";
import { NodeRow } from "@/features/navigator/NodeRow";
import { useTreeKeyboard } from "@/features/navigator/useTreeKeyboard";

interface ContextMenuState {
  id: string;
  x: number;
  y: number;
}

export function GraphNav() {
  const credentials = useStore((s) => s.credentials);
  const attackPaths = useStore((s) => s.attackPaths);
  const theme = useStore((s) => s.theme);
  const selectedId = useStore((s) => s.selectedId);
  const select = useStore((s) => s.select);
  const setCompromise = useStore((s) => s.setCompromise);
  const queryScope = useStore((s) => s.queryScope);
  const setQueryScope = useStore((s) => s.setQueryScope);
  const edges = useStore((s) => s.edges);

  const model = useGraphModel();

  // Node-id sets used to badge rows.
  const credNodes = useMemo(() => {
    const ids = new Set<string>();
    for (const c of credentials) {
      if (c.belongs_to) ids.add(c.belongs_to);
      if (c.obtained_from) ids.add(c.obtained_from);
    }
    return ids;
  }, [credentials]);
  const pathNodes = useMemo(() => {
    const ids = new Set<string>();
    for (const p of attackPaths) for (const hop of p.hops) ids.add(hop);
    return ids;
  }, [attackPaths]);

  const [filter, setFilter] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [menu, setMenu] = useState<ContextMenuState | null>(null);

  const groups = useMemo(() => groupNodes(model.visibleNodes, filter), [model, filter]);
  const rows = useMemo(() => buildRows(groups, collapsed), [groups, collapsed]);

  const toggleGroup = (group: string) =>
    setCollapsed((c) => {
      const next = new Set(c);
      if (next.has(group)) next.delete(group);
      else next.add(group);
      return next;
    });

  const onActivate = (row: Row) => {
    if (row.type === "group") {
      toggleGroup(row.group);
    } else {
      select(row.node.id);
      mapApi.centerOn?.(row.node.id);
    }
  };

  const { activeKey, setActiveKey, treeRef, onKeyDown, activate } = useTreeKeyboard(rows, onActivate);

  // Focus scopes: a key identifies the focused row so toggling it again clears
  // the dimming. Nodes focus their 1-hop neighborhood; groups the category.
  const focusKey = queryScope?.label ?? null;
  const toggleFocus = (key: string, ids: string[]): void => {
    if (focusKey === key) {
      setQueryScope(null);
      return;
    }
    const s = incidentScope(ids, edges);
    setQueryScope({ label: key, nodeIds: s.nodeIds, edgeIds: s.edgeIds });
  };

  // Reveal and focus the selected node whenever the selection changes elsewhere.
  useEffect(() => {
    if (!selectedId) return;
    const n = model.byId.get(selectedId);
    if (!n) return;
    const group = groupOf(n.kind);
    setCollapsed((c) => (c.has(group) ? new Set([...c].filter((g) => g !== group)) : c));
    setActiveKey(`node:${selectedId}`);
  }, [selectedId, model, setActiveKey]);

  // Announce selection changes for screen readers.
  useEffect(() => {
    if (!selectedId) return;
    const n = model.byId.get(selectedId);
    if (n) announce(`Selected ${describeNode(n, model.adjacency)}`);
  }, [selectedId, model]);

  const openMenu = (e: React.MouseEvent, id: string) => {
    e.preventDefault();
    select(id);
    setMenu({ id, x: e.clientX, y: e.clientY });
  };

  return (
    <div className="overview">
      <div className="ovhead">
        <h2 id="gnav-label">Network</h2>
        <span className="ovcount">{model.visibleNodes.length}</span>
      </div>

      <div className="ovfilter">
        <Icon className="searchicon" name="search" size={13} />
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter the network..."
          aria-label="Filter the network list"
          spellCheck={false}
        />
        {filter && (
          <button className="x" onClick={() => setFilter("")} aria-label="Clear filter">
            x
          </button>
        )}
      </div>

      {model.visibleNodes.length === 0 ? (
        <p className="muted ovempty">
          No assets yet. Add a node, import a scan, or chat <code>/node ...</code> below.
        </p>
      ) : rows.length === 0 ? (
        <p className="muted ovempty">No asset matches “{filter}”.</p>
      ) : (
        <div
          className="ovlist"
          role="tree"
          aria-labelledby="gnav-label"
          tabIndex={0}
          aria-activedescendant={activeKey ? `gnav-${activeKey}` : undefined}
          ref={treeRef}
          onKeyDown={onKeyDown}
        >
          {rows.map((row) =>
            row.type === "group" ? (
              <div
                key={row.key}
                id={`gnav-${row.key}`}
                data-key={row.key}
                role="treeitem"
                aria-level={1}
                aria-expanded={row.expanded}
                className={"ovgrouphead trow" + (row.key === activeKey ? " kbd" : "")}
                onClick={() => activate(row)}
              >
                <span className="gtwist" aria-hidden>
                  {row.expanded ? "▾" : "▸"}
                </span>
                <span>{row.group}</span>
                <span className="n">{row.count}</span>
                <button
                  type="button"
                  className={"ovfocus" + (focusKey === `group:${row.group}` ? " on" : "")}
                  title={focusKey === `group:${row.group}` ? "Clear focus (show everything)" : `Focus: dim everything except ${row.group}`}
                  aria-label={focusKey === `group:${row.group}` ? "Clear focus" : `Focus the ${row.group} group`}
                  aria-pressed={focusKey === `group:${row.group}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleFocus(`group:${row.group}`, (groups.find((g) => g.group === row.group)?.items ?? []).map((n) => n.id));
                  }}
                ><Icon name="focus" size={11} /></button>
              </div>
            ) : (
              <NodeRow
                key={row.key}
                row={row}
                selected={row.node.id === selectedId}
                active={row.key === activeKey}
                glyphColor={kindColor(row.node.kind, theme.colors[row.node.kind])}
                hasFindings={readFindings(row.node.fields).length > 0}
                hasCreds={credNodes.has(row.node.id)}
                onPath={pathNodes.has(row.node.id)}
                focused={focusKey === `node:${row.node.id}`}
                onChoose={() => activate(row)}
                onContext={(e) => openMenu(e, row.node.id)}
                onCycle={() => setCompromise(row.node.id, nextLevel(row.node.compromise_level))}
                onFocus={() => toggleFocus(`node:${row.node.id}`, [row.node.id])}
              />
            ),
          )}
        </div>
      )}

      {menu && (
        <Menu
          x={menu.x}
          y={menu.y}
          label="Node actions"
          actions={buildNodeActions(menu.id)}
          onClose={() => setMenu(null)}
        />
      )}
    </div>
  );
}
