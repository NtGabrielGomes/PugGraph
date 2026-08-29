import { useEffect, useState } from "react";
import { ALL_EDGE_KINDS, IDENTITY_KINDS, NODE_GROUPS, edgeKindDesc, edgeKindLabel, edgeKindsFor, nodeKindDesc } from "@/domain/catalog";
import { isHostKind, schemaFor, schemaForEdge, type FieldDef } from "@/domain/fieldSchema";
import { useStore } from "@/state/store";
import type { CompromiseLevel, Confidence, EdgeKind, NodeKind } from "@/domain/types";
import { COMPROMISE_LEVELS, EDGE_GROUP_STYLE, compromiseColor, edgeGroup, kindColor } from "@/viz/viz";
import { mapApi } from "@/features/map/mapApi";
import { VizSettings } from "@/features/appearance/VizSettings";
import { EdgeFilterButton } from "@/features/map/EdgeFilter";

/** BloodHound-style explore toggle: hide the whole map until a search hit,
 * navigator focus, or pre-built query reveals a scope. */
function HideAllButton() {
  const hideAll = useStore((s) => s.hideAll);
  const toggleHideAll = useStore((s) => s.toggleHideAll);
  return (
    <button
      className={"icon" + (hideAll ? " armed" : "")}
      onClick={toggleHideAll}
      aria-pressed={hideAll}
      title={hideAll ? "Show the whole map again" : "Hide everything — search or focus to reveal (BloodHound-style)"}
    ><Icon name={hideAll ? "eye" : "eye-off"} size={16} /></button>
  );
}

/** Hard reset: wipe every node, edge and saved position. Two-step confirm so a
 * stray click can't nuke the graph. */
function CleanGraphButton() {
  const clearGraph = useStore((s) => s.clearGraph);
  const nodeCount = useStore((s) => s.nodes.length);
  const [confirming, setConfirming] = useState(false);
  useEffect(() => {
    if (!confirming) return;
    const t = setTimeout(() => setConfirming(false), 3000);
    return () => clearTimeout(t);
  }, [confirming]);
  return (
    <button
      className={"icon" + (confirming ? " armed" : "")}
      disabled={nodeCount === 0}
      onClick={() => {
        if (confirming) {
          clearGraph();
          setConfirming(false);
        } else {
          setConfirming(true);
        }
      }}
      title={confirming ? "Click again to CONFIRM wiping the whole graph" : "Clean: wipe all nodes and edges"}
    ><Icon name="trash" size={16} />{confirming && <span className="cleantext">sure?</span>}</button>
  );
}
import { Dialog as UiDialog, Icon, Select } from "@/ui";
import { ProgressiveFields } from "@/features/inspector/TypedFields";

const CONFIDENCES: Confidence[] = ["confirmed", "suspected", "possible"];

const leadingSchema = (schema: FieldDef[]): FieldDef[] =>
  schema.filter((f) => f.group !== "Notes" && f.group !== "Evidence" && f.group !== "Tradecraft");

export function Toolbar() {
  const setMode = useStore((s) => s.setCreator);
  const mode = useStore((s) => s.creator);
  const settings = useStore((s) => s.appearanceOpen);
  const setSettings = useStore((s) => s.setAppearanceOpen);
  const selectedId = useStore((s) => s.selectedId);
  return (
    <>
      <div className="maptools" role="toolbar" aria-label="Map creation and view controls">
        <div className="tgroup">
          <span className="tglabel">Create</span>
          <button onClick={() => setMode("node")} title="Add an asset / node (n)"><Icon name="node" size={14} /> Node</button>
          <button onClick={() => setMode("edge")} title="Add a relation / edge between two nodes (e)"><Icon name="edge" size={14} /> Edge</button>
        </div>
        <div className="tgroup">
          <span className="tglabel">View</span>
          <button className="icon" onClick={() => mapApi.autoArrange?.()} title="Auto-arrange the layout (shared with the team)"><Icon name="arrange" size={16} /></button>
          <button className="icon" onClick={() => mapApi.fit?.()} title="Fit graph to view (f)"><Icon name="fit" size={16} /></button>
          <button className="icon" onClick={() => mapApi.focus?.()} disabled={!selectedId} title="Focus the selected node"><Icon name="focus" size={16} /></button>
          <HideAllButton />
          <EdgeFilterButton />
          <CleanGraphButton />
        </div>
        <div className="tgroup">
          <button className="icon" onClick={() => setSettings(true)} title="Appearance / theme (shared across operators)"><Icon name="theme" size={16} /></button>
        </div>
      </div>
      {mode === "node" && <AddNodeDialog onClose={() => setMode(null)} />}
      {mode === "edge" && <AddEdgeDialog onClose={() => setMode(null)} />}
      {settings && <VizSettings onClose={() => setSettings(false)} />}
    </>
  );
}

function Dialog({ title, subtitle, onClose, children, canSubmit, onSubmit }: {
  title: string;
  subtitle: string;
  onClose: () => void;
  children: React.ReactNode;
  canSubmit: boolean;
  onSubmit: (e: React.SubmitEvent<HTMLFormElement>) => void;
}) {
  return (
    <UiDialog title={title} subtitle={subtitle} onClose={onClose}>
      <form className="modalform" onSubmit={onSubmit}>
        <div className="modalbody">{children}</div>
        <div className="modalactions">
          <button type="submit" disabled={!canSubmit}>Add</button>
          <button type="button" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </UiDialog>
  );
}

function AddNodeDialog({ onClose }: { onClose: () => void }) {
  const createNode = useStore((s) => s.createNode);
  const templates = useStore((s) => s.nodeTemplates);
  const createFromTemplate = useStore((s) => s.createFromTemplate);
  const [nkind, setNkind] = useState<NodeKind>("host_windows");
  const [label, setLabel] = useState("");
  const [compromise, setCompromise] = useState<CompromiseLevel>("unknown");
  const [idKind, setIdKind] = useState("ip_address");
  const [idVal, setIdVal] = useState("");
  const [draft, setDraft] = useState<Record<string, unknown>>({});

  useEffect(() => setDraft({}), [nkind]);
  const typed = leadingSchema(schemaFor(nkind));

  const submit = (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!label.trim()) return;
    createNode(nkind, label, isHostKind(nkind) ? compromise : "unknown", idVal.trim() ? { kind: idKind, value: idVal } : undefined, draft);
    onClose();
  };

  return (
    <Dialog title="Add node" subtitle="A host, account, or other asset on the map." onClose={onClose} canSubmit={!!label.trim()} onSubmit={submit}>
      {templates.length > 0 && (
        <label className="field">
          <span>Start from template</span>
          <Select
            value=""
            placeholder="- blank -"
            ariaLabel="Start from a saved template"
            options={templates.map((t) => ({ value: t.id, label: `${t.name} * ${t.kind}` }))}
            onChange={(v) => { if (v) { createFromTemplate(v, label.trim()); onClose(); } }}
          />
        </label>
      )}
      { }
      <label className="field">
        <span>Kind</span>
        <Select
          value={nkind}
          ariaLabel="Kind"
          triggerSwatch={kindColor(nkind)}
          onChange={(v) => setNkind(v as NodeKind)}
          options={NODE_GROUPS.map((g) => ({
            label: g.group,
            options: g.kinds.map((k) => ({ value: k.kind, label: k.label, swatch: kindColor(k.kind) })),
          }))}
        />
        <p className="kinddesc">{nodeKindDesc(nkind)}</p>
      </label>
      <label className="field">
        <span>Label</span>
        <input autoFocus value={label} onChange={(e) => setLabel(e.target.value)} placeholder="DC01.corp.local" required />
      </label>
      <div className="modalrow">
        { }
        {isHostKind(nkind) && (
          <label className="field">
            <span>Compromise</span>
            <Select
              value={compromise}
              ariaLabel="Compromise"
              triggerColor={compromiseColor(compromise)}
              onChange={(v) => setCompromise(v as CompromiseLevel)}
              options={COMPROMISE_LEVELS.map((l) => ({ value: l, label: l, color: compromiseColor(l) }))}
            />
          </label>
        )}
        <label className="field">
          <span>Identity key (optional)</span>
          <div className="addrow">
            <Select
              size="sm"
              value={idKind}
              ariaLabel="Identity key kind"
              onChange={setIdKind}
              options={IDENTITY_KINDS.map((k) => ({ value: k.kind, label: k.label }))}
            />
            <input value={idVal} onChange={(e) => setIdVal(e.target.value)} placeholder="e.g. 10.0.0.1" />
          </div>
        </label>
      </div>
      { }
      {typed.length > 0 && (
        <div className="createfields">
          <ProgressiveFields draftKey={`node:${nkind}`} schema={typed} values={draft} onChange={(k, v) => setDraft((d) => ({ ...d, [k]: v }))} />
        </div>
      )}
    </Dialog>
  );
}

function AddEdgeDialog({ onClose }: { onClose: () => void }) {
  const nodes = useStore((s) => s.nodes);
  const createEdge = useStore((s) => s.createEdge);

  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [ekind, setEkind] = useState<EdgeKind>("admin_to");
  const [conf, setConf] = useState<Confidence>("confirmed");
  const [draft, setDraft] = useState<Record<string, unknown>>({});

  const sorted = [...nodes].sort((a, b) => (a.label || a.id).localeCompare(b.label || b.id));
  const labelOf = (id: string) => nodes.find((n) => n.id === id)?.label ?? id;

  const srcKind = nodes.find((n) => n.id === source)?.kind;
  const tgtKind = nodes.find((n) => n.id === target)?.kind;
  const allowed = srcKind && tgtKind ? edgeKindsFor(srcKind, tgtKind) : ALL_EDGE_KINDS;
  useEffect(() => {
    if (!allowed.includes(ekind))
        setEkind(allowed[0] ?? "custom");
  }, [source, target]);
  useEffect(() => setDraft({}), [ekind]);
  const typed = leadingSchema(schemaForEdge(ekind));

  const valid = !!source && !!target && source !== target;
  const submit = (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!valid) return;
    createEdge(source, target, ekind, conf, draft);
    onClose();
  };

  return (
    <Dialog title="Add edge" subtitle="A directed relation from one node to another." onClose={onClose} canSubmit={valid} onSubmit={submit}>
      {sorted.length < 2 && <p className="muted">Add at least two nodes first.</p>}
      { }
      <label className="field">
        <span>Source</span>
        <Select
          value={source}
          placeholder="- pick a node -"
          ariaLabel="Source node"
          onChange={setSource}
          options={sorted.map((n) => ({ value: n.id, label: n.label || n.id, hint: n.kind }))}
        />
      </label>
      <label className="field">
        <span>Relation{srcKind && tgtKind ? ` * ${srcKind} → ${tgtKind}` : ""}</span>
        <Select
          value={ekind}
          ariaLabel="Relation"
          disabled={!valid}
          onChange={(v) => setEkind(v as EdgeKind)}
          options={allowed.map((k) => ({ value: k, label: edgeKindLabel(k) }))}
        />
      <p className="kinddesc">
        {edgeKindDesc(ekind)}
        {srcKind && tgtKind ? ` * ${allowed.length - 1} valid relation${allowed.length - 1 === 1 ? "" : "s"} for these kinds` : ""}
      </p>
      </label>
      <label className="field">
        <span>Target</span>
        <Select
          value={target}
          placeholder="- pick a node -"
          ariaLabel="Target node"
          onChange={setTarget}
          options={sorted.map((n) => ({ value: n.id, label: n.label || n.id, hint: n.kind }))}
        />
      </label>
      {source && target && source === target && <p className="kinddesc warn">Source and target must be different nodes.</p>}
      {valid && (
        <div className="edgepreview">
          {labelOf(source)}{" "}
          <span className="rel" style={{ color: EDGE_GROUP_STYLE[edgeGroup(ekind)].color }}>—{ekind}→</span>{" "}
          {labelOf(target)}
        </div>
      )}
      <label className="field">
        <span>Confidence</span>
        <Select
          value={conf}
          ariaLabel="Confidence"
          onChange={(v) => setConf(v as Confidence)}
          options={CONFIDENCES.map((c) => ({ value: c, label: c }))}
        />
      </label>
      { }
      {valid && typed.length > 0 && (
        <div className="createfields">
          <ProgressiveFields draftKey={`edge:${ekind}`} schema={typed} values={draft} onChange={(k, v) => setDraft((d) => ({ ...d, [k]: v }))} />
        </div>
      )}
    </Dialog>
  );
}
