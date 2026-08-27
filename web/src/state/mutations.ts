// Command layer (Command pattern): the SOLE place graph/credential/collaboration
// mutations + their activity-log entries are expressed, as pure functions over
// (campaign, session, …args). The store's actions become thin delegators that wrap
// these with flush/refresh/select, so the "what happens and what gets logged"
// business rules live here — testable without spinning up the whole store.

import type { Campaign } from "@/campaign/document";
import type { Session } from "@/campaign/session";
import type {
  ClaimIntent,
  CompromiseLevel,
  Confidence,
  CredentialSource,
  CredentialType,
  Detection,
  EdgeKind,
  GraphNode,
  NodeKind,
  Objective,
  Task,
} from "@/domain/types";

const now = (): number => Date.now();
const uuid = (prefix: string): string => `${prefix}_${crypto.randomUUID()}`;

const log = (c: Campaign, s: Session, action: string, summary: string): void =>
  c.appendEvent({ author: s.operatorId, at: now(), action, summary });

const hostnameKey = (label: string): GraphNode["identity_keys"][number] => ({
  kind: "hostname",
  value: label.toLowerCase(),
  is_primary: true,
});

// ---- node / edge --------------------------------------------------------------

export const setCompromise = (c: Campaign, s: Session, id: string, level: CompromiseLevel): void => {
  c.setCompromise(id, level);
  log(c, s, "node.compromise", `set ${id} → ${level}`);
};

export const removeNode = (c: Campaign, s: Session, id: string): void => {
  c.removeNode(id);
  log(c, s, "node.remove", `removed ${id}`);
};

/** Create a node and return its id (the store handles flush/refresh/select). */
export const createNode = (
  c: Campaign,
  s: Session,
  kind: NodeKind,
  label: string,
  compromise: CompromiseLevel,
  identity?: { kind: string; value: string },
  fields?: Record<string, unknown>,
): string => {
  const id = uuid("node");
  const lbl = label.trim();
  const keys: GraphNode["identity_keys"] = [];
  if (lbl) keys.push(hostnameKey(lbl));
  if (identity && identity.value.trim()) {
    keys.push({ kind: identity.kind, value: identity.value.trim(), is_primary: keys.length === 0 });
  }
  c.upsertNode({
    id,
    kind,
    label: lbl,
    identity_keys: keys,
    compromise_level: compromise,
    fields: fields ?? {},
    tags: [],
    provenance: s.provenance(),
  });
  log(c, s, "node.upsert", `added ${lbl || id} (${kind})`);
  return id;
};

export const createEdge = (
  c: Campaign,
  s: Session,
  source: string,
  target: string,
  kind: EdgeKind,
  confidence: Confidence,
  labelOf: (id: string) => string,
  fields?: Record<string, unknown>,
): string => {
  const id = `${source}|${kind}|${target}`;
  c.addEdge({ id, kind, source, target, confidence, fields, provenance: s.provenance() });
  log(c, s, "edge.add", `${labelOf(source)} -[${kind}]-> ${labelOf(target)}`);
  return id;
};

export const cloneNode = (c: Campaign, s: Session, src: GraphNode): string => {
  const id = uuid("node");
  const label = `${src.label || src.kind} copy`;
  c.upsertNode({
    id,
    kind: src.kind,
    label,
    identity_keys: [hostnameKey(label)],
    compromise_level: src.compromise_level,
    fields: { ...src.fields },
    tags: [...src.tags],
    provenance: s.provenance(),
  });
  log(c, s, "node.upsert", `cloned ${src.label || src.id} → ${label}`);
  return id;
};

// ---- bulk ---------------------------------------------------------------------

export const bulkSetCompromise = (c: Campaign, s: Session, ids: string[], level: CompromiseLevel): void => {
  for (const id of ids) c.setCompromise(id, level);
  log(c, s, "node.compromise", `set ${ids.length} node(s) → ${level}`);
};

export const bulkAddTag = (c: Campaign, s: Session, ids: string[], tag: string): void => {
  for (const id of ids) c.addTag(id, tag);
  log(c, s, "node.tag", `tagged ${ids.length} node(s) #${tag}`);
};

export const bulkSetField = (c: Campaign, s: Session, ids: string[], key: string, value: unknown): void => {
  for (const id of ids) c.setField(id, key, value);
  log(c, s, "node.field", `set ${key} on ${ids.length} node(s)`);
};

export const bulkRemove = (c: Campaign, s: Session, ids: string[]): void => {
  for (const id of ids) c.removeNode(id);
  log(c, s, "node.remove", `removed ${ids.length} node(s)`);
};

export const clearGraph = (c: Campaign, s: Session): void => {
  const count = c.nodes().length;
  c.clearGraph();
  log(c, s, "graph.clear", `cleared the graph (${count} node(s))`);
};

// ---- saved views / templates / paths ------------------------------------------

export const saveFilter = (c: Campaign, s: Session, name: string, query: string): void => {
  c.addFilter({ id: uuid("filter"), name, query, created_by: s.operatorId });
  log(c, s, "filter.save", `saved filter "${name}"`);
};

export const saveNodeTemplate = (c: Campaign, s: Session, node: GraphNode, name: string): void => {
  const fields = { ...node.fields };
  delete fields["findings"];
  c.addTemplate({ id: uuid("tpl"), name, kind: node.kind, fields, tags: [...node.tags], created_by: s.operatorId });
  log(c, s, "template.save", `saved template "${name}" (${node.kind})`);
};

export const createFromTemplate = (
  c: Campaign,
  s: Session,
  tpl: { kind: NodeKind; name: string; fields: Record<string, unknown>; tags: string[] },
  label: string,
): string => {
  const id = uuid("node");
  const lbl = label.trim() || tpl.name;
  c.upsertNode({
    id,
    kind: tpl.kind,
    label: lbl,
    identity_keys: [hostnameKey(lbl)],
    compromise_level: "unknown",
    fields: { ...tpl.fields },
    tags: [...tpl.tags],
    provenance: s.provenance(),
  });
  log(c, s, "node.upsert", `added ${lbl} from template ${tpl.name}`);
  return id;
};

export const savePath = (c: Campaign, s: Session, name: string, hops: string[]): void => {
  c.addPathMark({ id: uuid("path"), name, hops, created_by: s.operatorId, created_at: now() });
  log(c, s, "path.save", `saved path "${name}" (${hops.length - 1} hops)`);
};

// ---- credentials --------------------------------------------------------------

export interface NewCredentialInput {
  username: string;
  domain: string;
  credential_type: CredentialType;
  source: CredentialSource;
  secret: string;
  belongs_to?: string;
  obtained_from?: string;
}

export const addCredential = (c: Campaign, s: Session, input: NewCredentialInput): void => {
  const t = now();
  const secret_sealed = input.secret && s.hasVault() ? s.sealCredentialSecret(input.secret) : undefined;
  c.addCredential({
    id: uuid("cred"),
    username: input.username,
    domain: input.domain || undefined,
    credential_type: input.credential_type,
    secret_sealed,
    belongs_to: input.belongs_to || undefined,
    obtained_from: input.obtained_from || undefined,
    validity: "unknown",
    validity_as_of: t,
    source: input.source,
    tested_against: [],
    provenance: s.provenance(),
  });
  log(c, s, "credential.add", `${input.username}${input.domain ? "@" + input.domain : ""} (${input.credential_type})`);
};

export const addCredentialTest = (
  c: Campaign,
  s: Session,
  id: string,
  host: string,
  succeeded: boolean,
  note?: string,
): void => {
  c.addCredentialTest(id, { host, succeeded, at: now(), note: note || undefined });
  log(c, s, "credential.test", `tested ${id} on ${host}: ${succeeded ? "valid" : "failed"}`);
};

// ---- collaboration ------------------------------------------------------------

export const claimNode = (c: Campaign, s: Session, id: string, intent: ClaimIntent, note?: string): void => {
  const t = now();
  c.setClaim({ node_id: id, operator_id: s.operatorId, intent, note, claimed_at: t, expires_at: t + 30 * 60_000 });
  log(c, s, "node.claim", `claimed ${id} (${intent})`);
};

export const logDetection = (c: Campaign, s: Session, d: Omit<Detection, "id" | "operator">): void => {
  c.addDetection({ ...d, id: uuid("det"), operator: s.operatorId });
  log(c, s, "detection.log", `${d.vector} → ${d.outcome}${d.control ? ` (${d.control})` : ""}`);
};

export const createTask = (
  c: Campaign,
  s: Session,
  title: string,
  opts?: Partial<Pick<Task, "description" | "assignee" | "priority" | "node_ref" | "phase">>,
): void => {
  const t = now();
  c.addTask({
    id: uuid("task"),
    title,
    created_by: s.operatorId,
    status: "todo",
    priority: opts?.priority ?? "med",
    description: opts?.description,
    assignee: opts?.assignee,
    node_ref: opts?.node_ref,
    phase: opts?.phase,
    created_at: t,
    updated_at: t,
  });
};

export const createObjective = (
  c: Campaign,
  s: Session,
  title: string,
  opts?: Partial<Pick<Objective, "description" | "owner" | "target_node" | "priority">>,
): void => {
  c.addObjective({
    id: uuid("obj"),
    title,
    status: "not_started",
    priority: opts?.priority ?? "med",
    created_by: s.operatorId,
    created_at: now(),
    description: opts?.description,
    owner: opts?.owner,
    target_node: opts?.target_node,
  });
};

export const sendMessage = (c: Campaign, s: Session, body: string, ref?: string): void => {
  const text = body.trim();
  if (!text) return;
  c.addMessage({ id: uuid("msg"), author: s.operatorId, at: now(), body: text, ref });
};
