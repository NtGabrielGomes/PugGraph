// The selection dossier — the "Inspect" tab of the right inspector. Driven by
// the per-kind/per-edge field schema (`fieldSchema.ts`) through the SHARED
// `TypedFields` renderer, so creation and editing never diverge. A node reads as
// a deep, grouped dossier (compromise/access vector first, then typed details,
// findings, services, relations, identity, tags, credentials, provenance), never
// an empty form; an edge records *why* and *how* (typed relation fields).

import { useCallback, useState } from "react";
import { COMMON_TAGS, IDENTITY_KINDS, edgeKindDesc, fieldSuggestions, nodeKindLabel } from "@/domain/catalog";
import {
  FINDING_STATUSES,
  SEVERITIES,
  SEVERITY_COLOR,
  edgeSchemaKeys,
  readFindings,
  schemaFor,
  schemaForEdge,
  schemaKeys,
  type Finding,
  type FindingStatus,
  type Severity,
} from "@/domain/fieldSchema";
import { credsForNode, useStore } from "@/state/store";
import type { Confidence, CompromiseLevel } from "@/domain/types";
import { COMPROMISE_LEVELS, EDGE_GROUP_STYLE, compromiseColor, edgeGroup, kindColor } from "@/viz/viz";
import { TypedFields } from "@/features/inspector/TypedFields";
import { Icon, Select } from "@/ui";

const CONFIDENCES: Confidence[] = ["confirmed", "suspected", "possible"];

function FindingsEditor({ id, fields }: { id: string; fields: Record<string, unknown> }) {
  const setField = useStore((s) => s.setField);
  const removeField = useStore((s) => s.removeField);
  const findings = readFindings(fields);
  const [title, setTitle] = useState("");
  const [sev, setSev] = useState<Severity>("medium");

  const write = (arr: Finding[]) => (arr.length ? setField(id, "findings", arr) : removeField(id, "findings"));
  const add = () => {
    if (!title.trim()) return;
    write([...findings, { title: title.trim(), severity: sev, status: "open" }]);
    setTitle("");
  };
  const update = (i: number, patch: Partial<Finding>) => write(findings.map((f, j) => (j === i ? { ...f, ...patch } : f)));
  const remove = (i: number) => write(findings.filter((_, j) => j !== i));

  return (
    <div className="field">
      <span>Findings</span>
      {findings.map((f, i) => (
        <div key={i} className="finding">
          <span className="sevdot" style={{ background: SEVERITY_COLOR[f.severity] }} />
          <span className="ftitle" title={f.note}>{f.title}</span>
          <Select
            size="sm"
            ariaLabel="Severity"
            value={f.severity}
            triggerColor={SEVERITY_COLOR[f.severity]}
            onChange={(v) => update(i, { severity: v as Severity })}
            options={SEVERITIES.map((s) => ({ value: s, label: s, color: SEVERITY_COLOR[s] }))}
          />
          <Select
            size="sm"
            ariaLabel="Status"
            value={f.status}
            onChange={(v) => update(i, { status: v as FindingStatus })}
            options={FINDING_STATUSES.map((s) => ({ value: s, label: s }))}
          />
          <button type="button" className="x" onClick={() => remove(i)} aria-label="Remove finding">×</button>
        </div>
      ))}
      <div className="addrow">
        <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="add finding" onKeyDown={(e) => e.key === "Enter" && add()} />
        <Select
          size="sm"
          ariaLabel="Severity"
          value={sev}
          triggerColor={SEVERITY_COLOR[sev]}
          onChange={(v) => setSev(v as Severity)}
          options={SEVERITIES.map((s) => ({ value: s, label: s, color: SEVERITY_COLOR[s] }))}
        />
        <button type="button" onClick={add} aria-label="Add finding"><Icon name="plus" size={14} /></button>
      </div>
    </div>
  );
}

function NodeEditor({ id }: { id: string }) {
  const node = useStore((s) => s.nodes.find((n) => n.id === id))!;
  const allNodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const credentials = useStore((s) => s.credentials);
  const setCompromise = useStore((s) => s.setCompromise);
  const setLabel = useStore((s) => s.setLabel);
  const setNodeConfidence = useStore((s) => s.setNodeConfidence);
  const addTag = useStore((s) => s.addTag);
  const removeTag = useStore((s) => s.removeTag);
  const addIdentity = useStore((s) => s.addIdentity);
  const setField = useStore((s) => s.setField);
  const removeField = useStore((s) => s.removeField);
  const removeNode = useStore((s) => s.removeNode);
  const cloneNode = useStore((s) => s.cloneNode);
  const saveNodeTemplate = useStore((s) => s.saveNodeTemplate);
  const select = useStore((s) => s.select);
  const theme = useStore((s) => s.theme);

  const [tag, setTag] = useState("");
  const [idKind, setIdKind] = useState("ip_address");
  const [idVal, setIdVal] = useState("");
  const [fk, setFk] = useState("");
  const [fv, setFv] = useState("");

  const owned = schemaKeys(node.kind);
  const schema = schemaFor(node.kind);
  const extras = Object.entries(node.fields).filter(([k]) => !owned.has(k));

  // Derived inline views.
  const services = edges
    .filter((e) => e.kind === "listens_on" && e.target === id)
    .map((e) => allNodes.find((n) => n.id === e.source))
    .filter((n): n is NonNullable<typeof n> => !!n);
  const incident = edges.filter((e) => e.source === id || e.target === id);
  const nc = credsForNode(credentials, id);

  const commitTag = () => { if (tag.trim()) addTag(id, tag.trim()); setTag(""); };
  const commitIdentity = () => { if (idVal.trim()) addIdentity(id, idKind, idVal.trim()); setIdVal(""); };
  const commitField = () => {
    if (!fk.trim()) return;
    let value: unknown = fv;
    try { value = JSON.parse(fv); } catch { /* keep string */ }
    setField(id, fk.trim(), value);
    setFk(""); setFv("");
  };

  return (
    <div className="detail">
      <div className="row">
        <span className="swatch" style={{ background: kindColor(node.kind, theme.colors[node.kind]) }} />
        <input
          key={id}
          className="labeledit"
          defaultValue={node.label}
          onBlur={(e) => e.target.value.trim() && e.target.value !== node.label && setLabel(id, e.target.value.trim())}
        />
        <span className="kind" title={node.kind}>{nodeKindLabel(node.kind)}</span>
      </div>

      <label className="field">
        <span>Access level (compromise)</span>
        <Select
          ariaLabel="Access level (compromise)"
          value={node.compromise_level}
          triggerColor={compromiseColor(node.compromise_level)}
          onChange={(v) => setCompromise(id, v as CompromiseLevel)}
          options={COMPROMISE_LEVELS.map((l) => ({ value: l, label: l, color: compromiseColor(l) }))}
        />
      </label>

      <label className="field">
        <span>Confidence</span>
        <Select
          ariaLabel="Confidence"
          value={node.provenance.confidence}
          onChange={(v) => setNodeConfidence(id, v as Confidence)}
          options={CONFIDENCES.map((c) => ({ value: c, label: c }))}
        />
      </label>

      {/* Typed details, grouped, driven by the per-kind schema. The compromise/
          access dossier leads; a single-field group named like its only field
          (e.g. Notes) drops the redundant header (handled inside TypedFields). */}
      <TypedFields
        ownerId={id}
        fields={node.fields}
        schema={schema}
        onSet={(k, v) => setField(id, k, v)}
        onRemove={(k) => removeField(id, k)}
      />

      <FindingsEditor id={id} fields={node.fields} />

      {services.length > 0 && (
        <div className="field">
          <span>Services ({services.length})</span>
          <div className="svclist">
            {services.map((s) => (
              <div key={s.id} className="svc" onClick={() => select(s.id)}>
                <code>{(s.fields["port"] as string) ?? "?"}</code>
                <span>{s.label}</span>
                <small className="muted">{[s.fields["product"], s.fields["version"]].filter(Boolean).join(" ")}</small>
              </div>
            ))}
          </div>
        </div>
      )}

      {incident.length > 0 && (
        <div className="field">
          <span>Relations ({incident.length})</span>
          <div className="rels">
            {incident.map((e) => {
              const out = e.source === id;
              const other = out ? e.target : e.source;
              const otherLabel = allNodes.find((n) => n.id === other)?.label ?? other;
              return (
                <div key={e.id} className="relrow">
                  <button type="button" className="reledit" onClick={() => select(e.id)} title="Edit this relation">
                    <span className="reldir">{out ? "→" : "←"}</span>
                    <span className="relkind" style={{ color: EDGE_GROUP_STYLE[edgeGroup(e.kind)].color }}>{e.kind}</span>
                  </button>
                  <button type="button" className="relother" onClick={() => select(other)} title="Go to this node">{otherLabel}</button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="field">
        <span>Identity</span>
        <div className="chips">
          {node.identity_keys.map((k, i) => <code key={i} className="chip">{k.kind}:{k.value}</code>)}
        </div>
        <div className="addrow">
          <Select
            size="sm"
            ariaLabel="Identity key kind"
            value={idKind}
            onChange={setIdKind}
            options={IDENTITY_KINDS.map((k) => ({ value: k.kind, label: k.label }))}
          />
          <input value={idVal} onChange={(e) => setIdVal(e.target.value)} placeholder="value" onKeyDown={(e) => e.key === "Enter" && commitIdentity()} />
          <button type="button" onClick={commitIdentity} aria-label="Add identity key"><Icon name="plus" size={14} /></button>
        </div>
      </div>

      <div className="field">
        <span>Tags</span>
        <div className="chips">
          {node.tags.map((t) => (
            <span key={t} className="chip tag">
              #{t}
              <button type="button" className="x" onClick={() => removeTag(id, t)} aria-label={`Remove tag ${t}`}>×</button>
            </span>
          ))}
        </div>
        <div className="addrow">
          <input list="tagsugg" value={tag} onChange={(e) => setTag(e.target.value)} placeholder="add tag" onKeyDown={(e) => e.key === "Enter" && commitTag()} />
          <datalist id="tagsugg">{COMMON_TAGS.map((t) => <option key={t} value={t} />)}</datalist>
          <button type="button" onClick={commitTag} aria-label="Add tag"><Icon name="plus" size={14} /></button>
        </div>
      </div>

      {(nc.authenticatesAs.length > 0 || nc.obtainedHere.length > 0 || nc.testedHere.length > 0) && (
        <div className="field">
          <span>Credentials</span>
          {nc.authenticatesAs.map((c) => <CredRef key={"a" + c.id} c={c} rel="authenticates as" />)}
          {nc.obtainedHere.map((c) => <CredRef key={"o" + c.id} c={c} rel="captured here" />)}
          {nc.testedHere.map((c) => {
            const t = c.tested_against.find((x) => x.host === id);
            return <CredRef key={"t" + c.id} c={c} rel={t?.succeeded ? "valid here" : "tested here"} />;
          })}
        </div>
      )}

      {extras.length > 0 && (
        <div className="field">
          <span>Other fields</span>
          {extras.map(([k, v]) => (
            <div key={k} className="kvrow">
              <code>{k}</code>
              <span className="val">{typeof v === "string" ? v : JSON.stringify(v)}</span>
              <button type="button" className="x" onClick={() => removeField(id, k)} aria-label={`Remove ${k}`}>×</button>
            </div>
          ))}
        </div>
      )}
      <div className="field">
        <span>Add field</span>
        <div className="addrow">
          <input className="small" list="fieldsugg" value={fk} onChange={(e) => setFk(e.target.value)} placeholder="key" />
          <datalist id="fieldsugg">{fieldSuggestions(node.kind).map((k) => <option key={k} value={k} />)}</datalist>
          <input value={fv} onChange={(e) => setFv(e.target.value)} placeholder="value" onKeyDown={(e) => e.key === "Enter" && commitField()} />
          <button type="button" onClick={commitField} aria-label="Add field"><Icon name="plus" size={14} /></button>
        </div>
      </div>

      <div className="field">
        <span>Provenance</span>
        <small className="muted">
          {node.provenance.author} * {node.provenance.source.kind}
          {node.provenance.source.tool ? `:${node.provenance.source.tool}` : ""}
        </small>
      </div>

      <div className="detailactions">
        <button type="button" className="ghost" onClick={() => cloneNode(id)} title="Duplicate this node's modelling (no identity keys)">
          <Icon name="clone" size={14} /> Clone
        </button>
        <button
          type="button"
          className="ghost"
          title="Save this node's kind + fields + tags as a reusable team template"
          onClick={() => { const name = window.prompt("Template name", node.label || node.kind); if (name?.trim()) saveNodeTemplate(id, name.trim()); }}
        ><Icon name="star" size={14} /> Template</button>
        <button type="button" className="danger" onClick={() => removeNode(id)} title="Delete this node"><Icon name="trash" size={14} /></button>
      </div>
    </div>
  );
}

function CredRef({ c, rel }: { c: { username: string; domain?: string; validity: string }; rel: string }) {
  return (
    <div className="credref">
      <strong>{c.username}{c.domain ? "@" + c.domain : ""}</strong>
      <span className="rel">{rel}</span>
      <span className="muted">{c.validity}</span>
    </div>
  );
}

function EdgeEditor({ id }: { id: string }) {
  const edge = useStore((s) => s.edges.find((e) => e.id === id));
  const nodes = useStore((s) => s.nodes);
  const labelOf = useCallback(
    (nid: string) => nodes.find((n) => n.id === nid)?.label ?? nid,
    [nodes],
  );
  const setEdgeConfidence = useStore((s) => s.setEdgeConfidence);
  const setEdgeField = useStore((s) => s.setEdgeField);
  const removeEdgeField = useStore((s) => s.removeEdgeField);
  const removeEdge = useStore((s) => s.removeEdge);
  const select = useStore((s) => s.select);

  if (!edge) return null;

  const fields = edge.fields ?? {};
  const schema = schemaForEdge(edge.kind);
  const owned = edgeSchemaKeys(edge.kind);
  const extras = Object.entries(fields).filter(([k]) => !owned.has(k));
  const color = EDGE_GROUP_STYLE[edgeGroup(edge.kind)].color;

  return (
    <div className="detail">
      <div className="row">
        <button type="button" className="relother" onClick={() => select(edge.source)}>{labelOf(edge.source)}</button>
        <span className="kind" style={{ color }}>—{edge.kind}→</span>
        <button type="button" className="relother" onClick={() => select(edge.target)}>{labelOf(edge.target)}</button>
      </div>
      <p className="kinddesc">{edgeKindDesc(edge.kind)}</p>
      <label className="field">
        <span>Confidence</span>
        <Select
          ariaLabel="Confidence"
          value={edge.confidence}
          onChange={(v) => setEdgeConfidence(id, v as Confidence)}
          options={CONFIDENCES.map((c) => ({ value: c, label: c }))}
        />
      </label>

      { }
      <TypedFields
        ownerId={id}
        fields={fields}
        schema={schema}
        onSet={(k, v) => setEdgeField(id, k, v)}
        onRemove={(k) => removeEdgeField(id, k)}
      />

      {extras.length > 0 && (
        <div className="field">
          <span>Other fields</span>
          {extras.map(([k, v]) => (
            <div key={k} className="kvrow">
              <code>{k}</code>
              <span className="val">{typeof v === "string" ? v : JSON.stringify(v)}</span>
              <button type="button" className="x" onClick={() => removeEdgeField(id, k)} aria-label={`Remove ${k}`}>×</button>
            </div>
          ))}
        </div>
      )}

      <button type="button" className="danger" onClick={() => removeEdge(id)}><Icon name="trash" size={14} /> Delete edge</button>
    </div>
  );
}

export function SidePanel() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const selectedId = useStore((s) => s.selectedId);

  const selectedNode = selectedId ? nodes.find((n) => n.id === selectedId) : undefined;
  const selectedEdge = selectedId && !selectedNode ? edges.find((e) => e.id === selectedId) : undefined;

  if (!selectedNode && !selectedEdge) {
    return (
      <div className="inspect-empty">
        <Icon name="focus" size={22} />
        <p className="muted">Select a node or edge to inspect and edit it.</p>
        <p className="muted small">Click on the map or the network list to select and inspect nodes and edges.</p>
      </div>
    );
  }
  return (
    <div className="inspect">
      {selectedNode && <NodeEditor id={selectedNode.id} />}
      {selectedEdge && <EdgeEditor id={selectedEdge.id} />}
    </div>
  );
}
