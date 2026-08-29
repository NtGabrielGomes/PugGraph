import { useEffect, useRef, useState } from "react";
import cytoscape, { type Core, type ElementDefinition, type StylesheetStyle } from "cytoscape";
import fcose from "cytoscape-fcose";
import { useStore } from "@/state/store";
import type { EdgeKind, GraphNode } from "@/domain/types";
import { edgePermits } from "@/domain/catalog";
import { buildGraphModel, type GraphModel } from "@/graph/model";
import { mapApi } from "@/features/map/mapApi";
import { platform } from "@/io/platform";

cytoscape.use(fcose as cytoscape.Ext);
import {
  EDGE_GROUP_STYLE,
  compromiseBorder,
  compromiseColor,
  compromiseFill,
  edgeGroup,
} from "@/viz/viz";
import { iconDataUri } from "@/viz/icons";
import { buildNodeActions } from "@/features/map/nodeActions";
import { Icon, Menu } from "@/ui";

const reducedMotion = (): boolean =>
  typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

const PERF_THRESHOLD = 800;

const EDGE_GROUP_SELECTORS: StylesheetStyle[] = Object.entries(EDGE_GROUP_STYLE).map(([g, s]) => ({
  selector: `edge.eg-${g}`,
  style: {
    "line-color": s.color,
    "target-arrow-color": s.color,
    "line-style": s.line,
    "target-arrow-shape": s.arrow ? "triangle" : "none",
    width: s.width,
  },
}));

const SEL = "#ececec";
const STYLE: StylesheetStyle[] = [
  {
    selector: "node",
    style: {
      width: 56,
      height: 56,
      shape: "ellipse",
      label: "data(label)",
      color: "#ededed",
      "font-size": 11,
      "font-weight": 600,
      "text-valign": "bottom",
      "text-margin-y": 7,
      "text-wrap": "wrap",
      "text-max-width": "140px",
      "text-background-color": "#070707",
      "text-background-opacity": 0.85,
      "text-background-padding": "3px",
      "text-background-shape": "roundrectangle",
      "min-zoomed-font-size": 7,
      "border-width": 2.5,
      "border-color": "#3a3a3a",
      "background-color": "#070707",
      "background-fit": "contain",
      "background-clip": "node",
      "background-opacity": 1,
      "overlay-shape": "ellipse",
    },
  },

  {
    selector: ":parent",
    style: {
      "background-color": "#0d0d0d",
      "background-opacity": 0.5,
      "border-color": "#2c2c2c",
      "border-opacity": 1,
      "border-width": 1.5,
      shape: "round-rectangle",
      "text-valign": "top",
      "text-halign": "center",
      "text-margin-y": -8,
      padding: "26px",
      "font-size": 12,
      "font-weight": 700,
      color: "#cfcfcf",
      "min-zoomed-font-size": 5,
    },
  },

  { selector: "node.onpath", style: { "overlay-color": "#db8038", "overlay-opacity": 0.22, "overlay-padding": 8, "min-zoomed-font-size": 0, "z-index": 50 } },
  { selector: "node.selected", style: { "overlay-color": SEL, "overlay-opacity": 0.16, "overlay-padding": 7, "border-color": SEL, "border-width": 2.5, "min-zoomed-font-size": 0, "z-index": 99 } },
  { selector: "node:selected", style: { "overlay-color": SEL, "overlay-opacity": 0.14, "overlay-padding": 6 } },

  {
    selector: "edge",
    style: {
      width: 2.5,
      "line-color": "#8a8a8a",
      "target-arrow-color": "#8a8a8a",
      "target-arrow-shape": "triangle",
      "arrow-scale": 1.2,
      "curve-style": "bezier",
      label: "data(elabel)",
      "font-size": 10,
      color: "#b3b3b3",
      "text-background-color": "#070707",
      "text-background-opacity": 0.85,
      "text-background-padding": "3px",
      "text-background-shape": "roundrectangle",
      "min-zoomed-font-size": 9,
      "text-rotation": "none",
    },
  },
  ...EDGE_GROUP_SELECTORS,
  { selector: "edge.noncanonical", style: { "line-color": "#d4b257", "target-arrow-color": "#d4b257", "line-style": "dashed", color: "#d4b257" } },
  { selector: "edge.suspected", style: { "line-style": "dashed", opacity: 0.85 } },
  { selector: "edge.onpath", style: { "line-color": "#db8038", "target-arrow-color": "#db8038", width: 3, "min-zoomed-font-size": 0, "z-index": 50 } },
  { selector: "edge.selected", style: { "line-color": SEL, "target-arrow-color": SEL, width: 3, "min-zoomed-font-size": 0, "z-index": 60 } },
  { selector: "node.hipath", style: { "overlay-color": "#ffffff", "overlay-opacity": 0.26, "overlay-padding": 11, "min-zoomed-font-size": 0, "z-index": 80 } },
  { selector: "edge.hipath", style: { "line-color": "#ffffff", "target-arrow-color": "#ffffff", width: 4, "min-zoomed-font-size": 0, "z-index": 80 } },
];

interface Emphasis {
  selectedId: string | null;
  pathNodes: Set<string>;
  pathEdges: Set<string>;
  hiNodes: Set<string>;
  hiEdges: Set<string>;
}

function computeEmphasis(): Emphasis {
  const s = useStore.getState();
  
  const pathNodes = new Set<string>();
  const pathEdges = new Set<string>();
  for (const p of s.attackPaths) {
    p.hops.forEach((h) => pathNodes.add(h));
    for (let i = 0; i + 1 < p.hops.length; i++)
      pathEdges.add(`${p.hops[i]}->${p.hops[i + 1]}`);
  }
  
  const hiNodes = new Set<string>();
  const hiEdges = new Set<string>();
  if (s.highlightPath) {
    s.highlightPath.forEach((h) => hiNodes.add(h));
    for (let i = 0; i + 1 < s.highlightPath.length; i++)
        hiEdges.add(`${s.highlightPath[i]}->${s.highlightPath[i + 1]}`);
  }
  
  return { selectedId: s.selectedId, pathNodes, pathEdges, hiNodes, hiEdges };
}

export function NetworkMap() {
  const ref = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const structRef = useRef<string>("");
  const prevNodeIdsRef = useRef<Set<string>>(new Set());
  const prevParentsRef = useRef<Record<string, string>>({});
  const firstRef = useRef<boolean>(true);
  const layoutTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [ctx, setCtx] = useState<{ id: string; x: number; y: number } | null>(null);

  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const attackPaths = useStore((s) => s.attackPaths);
  const lens = useStore((s) => s.lens);
  const selectedId = useStore((s) => s.selectedId);
  const theme = useStore((s) => s.theme);
  const viewAsOf = useStore((s) => s.viewAsOf);
  const filterQuery = useStore((s) => s.filterQuery);
  const highlightPath = useStore((s) => s.highlightPath);
  const queryScope = useStore((s) => s.queryScope);
  const hideAll = useStore((s) => s.hideAll);
  const hiddenEdgeKinds = useStore((s) => s.hiddenEdgeKinds);

  useEffect(() => {
    if (!ref.current) return;
    const container = ref.current;
    const cy = cytoscape({
      container,
      style: STYLE,
      wheelSensitivity: 1,
      minZoom: 0.04,
      maxZoom: 4,
      pixelRatio: 1,
    });
    cyRef.current = cy;

    firstRef.current = true;
    structRef.current = "";
    prevNodeIdsRef.current = new Set();
    prevParentsRef.current = {};

    const ro = new ResizeObserver(() => cy.resize());
    ro.observe(container);
    requestAnimationFrame(() => cy.resize());

    cy.on("tap", "node", (e) => {
      useStore.getState().select(e.target.id());
    });

    cy.on("tap", "edge", (e) => {
      useStore.getState().select(e.target.id());
    });

    cy.on("cxttap", "node", (e) => {
      e.originalEvent?.preventDefault?.();
      const oe = e.originalEvent as MouseEvent | undefined;
      setCtx({ id: e.target.id(), x: oe?.clientX ?? 0, y: oe?.clientY ?? 0 });
    });

    cy.on("tap", (e) => {
      if (e.target !== cy)
          return;
      useStore.getState().select(null);
    });

    cy.on("select unselect", "node", () => {
      const ids: string[] = [];
      cy.nodes(":selected").forEach((n) => { ids.push(n.id()); });
      useStore.getState().setBulkIds(ids);
    });

    cy.on("dragfree", "node", (e) => {
      const moved = new Set<string>();
      moved.add(e.target.id());
      cy.nodes(":selected").forEach((n) => { moved.add(n.id()); });
      const entries = [...moved]
        .map((id) => cy.getElementById(id))
        .filter((el) => el.nonempty() && !el.isParent())
        .map((el) => ({ id: el.id(), x: el.position().x, y: el.position().y }));
      if (entries.length)
          useStore.getState().saveNodePositions(entries);
    });

    mapApi.clearSelection = () => { cy.elements().unselect(); useStore.getState().setBulkIds([]); };

    return () => {
      ro.disconnect();
      if (layoutTimerRef.current)
          clearTimeout(layoutTimerRef.current);
      cy.destroy();
    };
  }, []);

  const nodeStyle = (n: GraphNode, model: GraphModel) => {
    const compromised = n.compromise_level !== "unknown" && n.compromise_level !== "none";
    if (model.parentIds.has(n.id)) {
      return {
        "background-color": "#0d0d0d",
        "background-opacity": 0.5,
        "background-image": "none",
        "border-color": compromised ? compromiseColor(n.compromise_level) : "#2c2c2c",
        "border-width": compromised ? 2 : 1.5,
      };
    }

    return {
      "background-color": compromiseFill(n.compromise_level),
      "background-image": iconDataUri(n.kind, theme.glyphs[n.kind], theme.variants[n.kind], n.compromise_level),
      "border-color": compromiseColor(n.compromise_level),
      "border-width": compromiseBorder(n.compromise_level),
    };
  };

  const canonicalOf = (model: GraphModel, e: { kind: EdgeKind; source: string; target: string }): boolean => {
    const sk = model.byId.get(e.source)?.kind;
    const tk = model.byId.get(e.target)?.kind;
    return sk && tk ? edgePermits(e.kind, sk, tk) : true;
  };
  const edgeLabel = (model: GraphModel, e: { kind: EdgeKind; source: string; target: string }): string =>
    (canonicalOf(model, e) ? "" : "⚠ ") + e.kind;

  const nodeClasses = (n: GraphNode, em: Emphasis): string =>
    [
      em.pathNodes.has(n.id) ? "onpath" : "",
      em.hiNodes.has(n.id) ? "hipath" : "",
      n.id === em.selectedId ? "selected" : "",
    ].filter(Boolean).join(" ").trim();

  const edgeClasses = (model: GraphModel, e: GraphModel["visibleEdges"][number], em: Emphasis): string =>
    [
      `eg-${edgeGroup(e.kind)}`,
      canonicalOf(model, e) ? "" : "noncanonical",
      e.confidence === "confirmed" ? "confirmed" : "suspected",
      em.pathEdges.has(`${e.source}->${e.target}`) ? "onpath" : "",
      em.hiEdges.has(`${e.source}->${e.target}`) ? "hipath" : "",
      e.id === em.selectedId ? "selected" : "",
    ].filter(Boolean).join(" ").trim();

  // The map label adds a ☠ marker to owned nodes; parents (group boxes) keep
  // their uppercase group name unmarked.
  const nodeLabel = (n: GraphNode, model: GraphModel): string => {
    if (model.parentIds.has(n.id)) return (n.label || n.id).toUpperCase();
    const owned = n.compromise_level !== "unknown" && n.compromise_level !== "none";
    return owned ? `\u2620 ${n.label}` : n.label;
  };

  const elementsFor = (model: GraphModel, em: Emphasis): ElementDefinition[] => {
    const els: ElementDefinition[] = [];
    for (const n of model.visibleNodes) {
      els.push({ data: { id: n.id, label: nodeLabel(n, model), kind: n.kind, parent: model.parents[n.id] }, classes: nodeClasses(n, em), style: nodeStyle(n, model) });
    }
    for (const e of model.visibleEdges) {
      els.push({ data: { id: e.id, source: e.source, target: e.target, kind: e.kind, elabel: edgeLabel(model, e) }, classes: edgeClasses(model, e, em) });
    }
    return els;
  };

  const applyInPlace = (cy: Core, model: GraphModel, em: Emphasis) => {
    cy.batch(() => {
      for (const n of model.visibleNodes) {
        const el = cy.getElementById(n.id);
        if (el.nonempty()) {
          el.classes(nodeClasses(n, em));
          el.style(nodeStyle(n, model));
          el.data("label", nodeLabel(n, model));
        }
      }
      for (const e of model.visibleEdges) {
        const el = cy.getElementById(e.id);
        if (el.nonempty()) {
          el.classes(edgeClasses(model, e, em));
          el.data("elabel", edgeLabel(model, e));
        }
      }
    });
  };

  const runLayout = (
    cy: Core,
    opts: { fit: boolean; randomize?: boolean; fixed?: { nodeId: string; position: { x: number; y: number } }[] },
  ): cytoscape.Layouts => {
    const count = cy.nodes().length;
    const perf = count > PERF_THRESHOLD;
    return cy
      .layout({
        name: "fcose",
        // Dense AD graphs (every user × every privileged group) need strong
        // repulsion or fcose collapses into a hairball; labels count toward
        // node bounds so text stops overlapping nodes. Small graphs can afford
        // fcose's "proof" quality pass.
        quality: perf ? "draft" : count < 120 ? ("proof" as const) : "default",
        animate: false,
        randomize: opts.randomize ?? firstRef.current,
        fit: opts.fit,
        padding: 48,
        nodeSeparation: 160,
        idealEdgeLength: 150,
        nodeRepulsion: 40000,
        nodeDimensionsIncludeLabels: true,
        packComponents: true,
        fixedNodeConstraint: opts.fixed && opts.fixed.length ? opts.fixed : undefined,
      } as cytoscape.LayoutOptions);
  };

  // Restore every saved (team-shared) position; return the visible non-parent
  // nodes that have NO saved position and therefore still need auto-placement.
  const restorePositions = (cy: Core, m: GraphModel, saved: Record<string, { x: number; y: number }>): string[] => {
    const unplaced: string[] = [];
    for (const n of m.visibleNodes) {
      if (m.parentIds.has(n.id)) continue;
      const el = cy.getElementById(n.id);
      if (el.empty()) continue;
      const p = saved[n.id];
      if (p) el.position({ x: p.x, y: p.y });
      else unplaced.push(n.id);
    }
    return unplaced;
  };

  const persistPositions = (cy: Core, ids: string[]) => {
    const entries = ids
      .map((id) => cy.getElementById(id))
      .filter((el) => el.nonempty() && !el.isParent())
      .map((el) => ({ id: el.id(), x: el.position().x, y: el.position().y }));
    if (entries.length) useStore.getState().saveNodePositions(entries);
  };

  const fitAll = (cy: Core) => cy.fit(cy.elements(), 40);

  // BloodHound-style explore: an explicit scope (search hit, navigator focus,
  // pre-built query) IS the visible set; with "hide all" and no scope the map
  // stays empty until one is chosen.
  const activeScope = queryScope
    ? { nodeIds: new Set(queryScope.nodeIds), edgeIds: new Set(queryScope.edgeIds) }
    : hideAll
      ? { nodeIds: new Set<string>(), edgeIds: new Set<string>() }
      : undefined;

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy)
        return;
    const model = buildGraphModel(nodes, edges, lens, viewAsOf, filterQuery, new Set(hiddenEdgeKinds), activeScope);
    const em = computeEmphasis();

    const struct = JSON.stringify([
      lens,
      model.visibleNodes.map((n) => n.id),
      model.visibleEdges.map((e) => e.id),
      Object.entries(model.parents),
    ]);

    if (struct === structRef.current && !firstRef.current) {
      applyInPlace(cy, model, em);
      return;
    }

    if (layoutTimerRef.current) clearTimeout(layoutTimerRef.current);
    const apply = () => {
      const cur = cyRef.current;
      if (!cur)
          return;
      const st = useStore.getState();
      const m = buildGraphModel(st.nodes, st.edges, st.lens, st.viewAsOf, st.filterQuery, new Set(st.hiddenEdgeKinds), activeScope);
      const e2 = computeEmphasis();
      const saved = st.positions;
      const curIds = new Set(m.visibleNodes.map((n) => n.id));
      const prevIds = prevNodeIdsRef.current;
      const prevParents = prevParentsRef.current;

      let removedOrReparented = false;
      for (const id of prevIds) if (!curIds.has(id)) { removedOrReparented = true; break; }
      if (!removedOrReparented) {
        for (const id of curIds) {
          if (prevIds.has(id) && prevParents[id] !== m.parents[id]) { removedOrReparented = true; break; }
        }
      }
      const addedNodes = [...curIds].filter((id) => !prevIds.has(id));

      const wasEmpty = cur.elements().empty();
      const hasContent = m.visibleNodes.length > 0;
      if (firstRef.current || removedOrReparented || wasEmpty) {
        cur.elements().remove();
        cur.add(elementsFor(m, e2));
        const unplaced = restorePositions(cur, m, saved);
        const fixed = m.visibleNodes
          .filter((n) => !m.parentIds.has(n.id) && saved[n.id])
          .map((n) => ({ nodeId: n.id, position: { x: saved[n.id]!.x, y: saved[n.id]!.y } }));
        if (unplaced.length) {
          runLayout(cur, { fit: false, randomize: fixed.length === 0 && firstRef.current, fixed }).run();
          persistPositions(cur, unplaced);
        }
        if ((firstRef.current || wasEmpty) && hasContent) fitAll(cur);
        if (hasContent) firstRef.current = false;
      } else {
        const present = new Set<string>();
        cur.elements().forEach((el) => { present.add(el.id()); });
        const newEls = elementsFor(m, e2).filter((el) => !present.has(el.data.id as string));
        if (newEls.length)
            cur.add(newEls);
        const unplaced = restorePositions(cur, m, saved);
        const newUnplaced = unplaced.filter((id) => addedNodes.includes(id));
        if (newUnplaced.length) {
          const fixed: { nodeId: string; position: { x: number; y: number } }[] = [];
          cur.nodes().forEach((el) => {
            if (!el.isParent() && !newUnplaced.includes(el.id()))
                fixed.push({ nodeId: el.id(), position: { ...el.position() } });
          });
          runLayout(cur, { fit: false, randomize: false, fixed }).run();
          persistPositions(cur, newUnplaced);
        }
        applyInPlace(cur, m, e2);
      }

      structRef.current = JSON.stringify([
        useStore.getState().lens,
        m.visibleNodes.map((n) => n.id),
        m.visibleEdges.map((e) => e.id),
        Object.entries(m.parents),
      ]);
      prevNodeIdsRef.current = curIds;
      prevParentsRef.current = m.parents;
    };

    if (firstRef.current)
        apply();
    else
        layoutTimerRef.current = setTimeout(apply, 90);
  }, [nodes, edges, attackPaths, lens, filterQuery, selectedId, theme, viewAsOf, highlightPath, queryScope, hideAll, hiddenEdgeKinds]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !highlightPath || highlightPath.length === 0) return;
    let eles = cy.collection();
    for (const id of highlightPath) eles = eles.union(cy.getElementById(id));
    for (let i = 0; i + 1 < highlightPath.length; i++) {
      eles = eles.union(cy.edges(`[source = "${highlightPath[i]}"][target = "${highlightPath[i + 1]}"]`));
    }
    if (eles.nonempty()) cy.animate({ fit: { eles, padding: 90 } }, { duration: reducedMotion() ? 0 : 280 });
  }, [highlightPath]);

  const fit = () => {
    const cy = cyRef.current;
    if (cy)
        cy.animate({ fit: { eles: cy.elements(), padding: 30 } }, { duration: reducedMotion() ? 0 : 250 });
  };
  const focus = () => {
    const cy = cyRef.current;
    if (!cy || !selectedId)
        return;
    const el = cy.getElementById(selectedId);
    if (el.nonempty())
        cy.animate({ center: { eles: el }, zoom: 1.6 }, { duration: reducedMotion() ? 0 : 250 });
  };
  mapApi.fit = fit;
  mapApi.focus = focus;
  mapApi.centerOn = (id: string) => {
    const cy = cyRef.current;
    if (!cy)
        return;
    const el = cy.getElementById(id);
    if (el.nonempty())
        cy.animate({ center: { eles: el }, zoom: Math.max(cy.zoom(), 1.3) }, { duration: reducedMotion() ? 0 : 220 });
  };
  mapApi.exportImage = () => {
    const cy = cyRef.current;
    if (!cy)
        return;
    const uri = cy.png({ full: true, scale: 2, bg: getComputedStyle(document.documentElement).getPropertyValue("--bg-0").trim() || "#070707" });
    void platform.saveDataUri("topology.png", uri);
  };
  mapApi.autoArrange = () => {
    const cy = cyRef.current;
    if (!cy)
        return;
    // fcose is async even without animation — persist only when it STOPS, or
    // we'd save the pre-layout positions and the arrangement would be lost.
    const layout = runLayout(cy, { fit: true, randomize: true });
    void layout.promiseOn("layoutstop").then(() => {
      const ids: string[] = [];
      cy.nodes().forEach((n) => { if (!n.isParent()) ids.push(n.id()); });
      persistPositions(cy, ids);
    });
    layout.run();
  };

  return (
    <div className="mapwrap">
      <div
        id="topology-map"
        className="map"
        ref={ref}
        tabIndex={0}
        role="application"
        aria-label="Network topology map. Use the network navigator in the left panel to explore by keyboard."
      />
      {hideAll && !queryScope && (
        <div className="maphidden">
          <Icon name="eye-off" size={22} />
          <p>Map hidden.</p>
          <p className="muted">
            Search a node above, or use the focus button on an item in the Network panel, or run a pre-built query
            — only that scope renders.
          </p>
        </div>
      )}
      {ctx && (
        <Menu
          x={ctx.x}
          y={ctx.y}
          label="Node actions"
          actions={buildNodeActions(ctx.id)}
          onClose={() => setCtx(null)}
        />
      )}
    </div>
  );
}
