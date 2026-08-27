// Codecs: the read/write rules for each domain entity, factored out of the
// Campaign document so the storage shape lives in one place per type. Each codec
// is a faithful transcription of the original hand‑written upsert/parse pair —
// same keys, same JSON encoding, same tolerant defaults — so the CRDT bytes are
// byte‑for‑byte identical and existing snapshots round‑trip unchanged.

import type { LoroMap } from "loro-crdt";
import { childMap, childList, type Codec, type JsonObj } from "@/campaign/crdt/Container";
import type {
  ChatMessage,
  Claim,
  ClaimIntent,
  Confidence,
  Credential,
  CredentialSource,
  CredentialTestResult,
  CredentialType,
  Detection,
  DetectionOutcome,
  GraphEdge,
  GraphNode,
  IdentityKey,
  NodeKind,
  NodeTemplate,
  NoiseLevel,
  Objective,
  ObjectiveStatus,
  OperatorRole,
  PathMark,
  Priority,
  Provenance,
  RosterEntry,
  RosterStatus,
  SavedFilter,
  Task,
  TaskStatus,
  ValidityState,
  CompromiseLevel,
} from "@/domain/types";

/** The stable index token for an identity key (`kind:value`). Shared by the
 * identity submap, the reconciliation index, and the fold index. */
export const identityToken = (k: IdentityKey): string => `${k.kind}:${k.value}`;

// ---- provenance (the shared `_`-prefixed fields on every entity) -------------

export function writeProvenance(m: LoroMap, p: Provenance): void {
  m.set("_author", p.author);
  m.set("_confidence", p.confidence);
  m.set("_source", JSON.stringify(p.source));
  m.set("_first_seen", p.first_seen);
  m.set("_last_verified", p.last_verified);
}

export function parseProvenance(o: JsonObj): Provenance {
  let source: Provenance["source"] = { kind: "manual" };
  try {
    source = JSON.parse(String(o["_source"] ?? '{"kind":"manual"}'));
  } catch {
    /* keep default */
  }
  return {
    author: String(o["_author"] ?? ""),
    source,
    confidence: (o["_confidence"] as Confidence) ?? "suspected",
    first_seen: Number(o["_first_seen"] ?? 0),
    last_verified: Number(o["_last_verified"] ?? 0),
  };
}

// ---- node --------------------------------------------------------------------
// NB: the reconciliation `idindex` is maintained by the Campaign (it spans
// containers), so the node codec only writes the node's own `identity` submap.

export const nodeCodec: Codec<GraphNode> = {
  id: (n) => n.id,
  write(entry, node) {
    entry.set("kind", node.kind);
    entry.set("label", node.label);
    entry.set("compromise", node.compromise_level);
    writeProvenance(entry, node.provenance);

    const idmap = childMap(entry, "identity");
    for (const k of node.identity_keys) idmap.set(identityToken(k), JSON.stringify(k));
    const fields = childMap(entry, "fields");
    for (const [key, val] of Object.entries(node.fields)) fields.set(key, JSON.stringify(val));
    const tags = childMap(entry, "tags");
    for (const t of node.tags) tags.set(t, true);
  },
  read(id, o) {
    if (typeof o["kind"] !== "string") return null;
    const identity_keys: IdentityKey[] = [];
    const idm = o["identity"];
    if (idm && typeof idm === "object") {
      for (const v of Object.values(idm as JsonObj)) {
        try {
          identity_keys.push(JSON.parse(String(v)) as IdentityKey);
        } catch {
          /* skip malformed */
        }
      }
    }
    const fields: Record<string, unknown> = {};
    const fm = o["fields"];
    if (fm && typeof fm === "object") {
      for (const [k, v] of Object.entries(fm as JsonObj)) {
        try {
          fields[k] = JSON.parse(String(v));
        } catch {
          fields[k] = v;
        }
      }
    }
    const tags: string[] = [];
    const tm = o["tags"];
    if (tm && typeof tm === "object") {
      for (const [k, v] of Object.entries(tm as JsonObj)) if (v === true) tags.push(k);
    }
    return {
      id,
      kind: o["kind"] as NodeKind,
      label: String(o["label"] ?? ""),
      identity_keys,
      compromise_level: (o["compromise"] as CompromiseLevel) ?? "unknown",
      fields,
      tags,
      provenance: parseProvenance(o),
    };
  },
};

// ---- edge --------------------------------------------------------------------

export const edgeCodec: Codec<GraphEdge> = {
  id: (e) => e.id,
  write(entry, edge) {
    entry.set("kind", edge.kind);
    entry.set("source", edge.source);
    entry.set("target", edge.target);
    entry.set("confidence", edge.confidence);
    writeProvenance(entry, edge.provenance);
    if (edge.fields) {
      const fields = childMap(entry, "fields");
      for (const [key, val] of Object.entries(edge.fields)) fields.set(key, JSON.stringify(val));
    }
  },
  read(id, o) {
    if (typeof o["kind"] !== "string" || typeof o["source"] !== "string" || typeof o["target"] !== "string") {
      return null;
    }
    const fields: Record<string, unknown> = {};
    const fm = o["fields"];
    if (fm && typeof fm === "object") {
      for (const [k, v] of Object.entries(fm as JsonObj)) {
        try {
          fields[k] = JSON.parse(String(v));
        } catch {
          fields[k] = v;
        }
      }
    }
    return {
      id,
      kind: o["kind"] as GraphEdge["kind"],
      source: String(o["source"]),
      target: String(o["target"]),
      confidence: (o["confidence"] as Confidence) ?? "suspected",
      fields,
      provenance: parseProvenance(o),
    };
  },
};

// ---- credential --------------------------------------------------------------

export const credentialCodec: Codec<Credential> = {
  id: (c) => c.id,
  write(entry, c) {
    entry.set("username", c.username);
    if (c.domain !== undefined) entry.set("domain", c.domain);
    entry.set("credential_type", c.credential_type);
    if (c.secret_sealed !== undefined) entry.set("secret_sealed", c.secret_sealed);
    if (c.belongs_to !== undefined) entry.set("belongs_to", c.belongs_to);
    if (c.obtained_from !== undefined) entry.set("obtained_from", c.obtained_from);
    entry.set("validity", c.validity);
    entry.set("validity_as_of", c.validity_as_of);
    entry.set("source", c.source);
    writeProvenance(entry, c.provenance);
    childList(entry, "tested_against"); // ensure the container exists
    for (const r of c.tested_against) childList(entry, "tested_against").push(JSON.stringify(r));
  },
  read(id, o) {
    if (typeof o["username"] !== "string" || typeof o["credential_type"] !== "string") return null;
    const tested: CredentialTestResult[] = [];
    const tm = o["tested_against"];
    if (Array.isArray(tm)) {
      for (const v of tm) {
        try {
          tested.push(JSON.parse(String(v)) as CredentialTestResult);
        } catch {
          /* skip malformed */
        }
      }
    }
    return {
      id,
      username: String(o["username"]),
      domain: o["domain"] !== undefined ? String(o["domain"]) : undefined,
      credential_type: o["credential_type"] as CredentialType,
      secret_sealed: o["secret_sealed"] !== undefined ? String(o["secret_sealed"]) : undefined,
      belongs_to: o["belongs_to"] !== undefined ? String(o["belongs_to"]) : undefined,
      obtained_from: o["obtained_from"] !== undefined ? String(o["obtained_from"]) : undefined,
      validity: (o["validity"] as ValidityState) ?? "unknown",
      validity_as_of: Number(o["validity_as_of"] ?? 0),
      source: (o["source"] as CredentialSource) ?? "manual",
      tested_against: tested,
      provenance: parseProvenance(o),
    };
  },
};

// ---- web‑managed containers (presentation/team state; Rust core ignores them) -

export const rosterCodec: Codec<RosterEntry> = {
  id: (e) => e.operator_id,
  write(entry, e) {
    entry.set("display_name", e.display_name);
    entry.set("signing_pubkey", e.signing_pubkey);
    entry.set("wrapping_pubkey", e.wrapping_pubkey);
    entry.set("role", e.role);
    entry.set("status", e.status);
    entry.set("added_by", e.added_by);
    entry.set("added_at", e.added_at);
  },
  read(id, o) {
    if (typeof o["signing_pubkey"] !== "string") return null;
    return {
      operator_id: id,
      display_name: String(o["display_name"] ?? id),
      signing_pubkey: String(o["signing_pubkey"]),
      wrapping_pubkey: String(o["wrapping_pubkey"] ?? ""),
      role: (o["role"] as OperatorRole) ?? "operator",
      status: (o["status"] as RosterStatus) ?? "active",
      added_by: String(o["added_by"] ?? ""),
      added_at: Number(o["added_at"] ?? 0),
    };
  },
};

export const filterCodec: Codec<SavedFilter> = {
  id: (f) => f.id,
  write(entry, f) {
    entry.set("name", f.name);
    entry.set("query", f.query);
    entry.set("created_by", f.created_by);
  },
  read(id, o) {
    return { id, name: String(o["name"] ?? id), query: String(o["query"] ?? ""), created_by: String(o["created_by"] ?? "") };
  },
};

export const templateCodec: Codec<NodeTemplate> = {
  id: (t) => t.id,
  write(entry, t) {
    entry.set("name", t.name);
    entry.set("kind", t.kind);
    entry.set("fields", JSON.stringify(t.fields));
    entry.set("tags", JSON.stringify(t.tags));
    entry.set("created_by", t.created_by);
  },
  read(id, o) {
    if (typeof o["kind"] !== "string") return null;
    let fields: Record<string, unknown> = {};
    let tags: string[] = [];
    try {
      fields = JSON.parse(String(o["fields"] ?? "{}"));
    } catch {
      /* skip */
    }
    try {
      const t = JSON.parse(String(o["tags"] ?? "[]"));
      if (Array.isArray(t)) tags = t.map(String);
    } catch {
      /* skip */
    }
    return { id, name: String(o["name"] ?? id), kind: o["kind"] as NodeKind, fields, tags, created_by: String(o["created_by"] ?? "") };
  },
};

export const pathmarkCodec: Codec<PathMark> = {
  id: (p) => p.id,
  write(entry, p) {
    entry.set("name", p.name);
    entry.set("hops", JSON.stringify(p.hops));
    entry.set("created_by", p.created_by);
    entry.set("created_at", p.created_at);
  },
  read(id, o) {
    let hops: string[] = [];
    try {
      const parsed = JSON.parse(String(o["hops"]));
      if (Array.isArray(parsed)) hops = parsed.map(String);
    } catch {
      /* skip malformed */
    }
    return {
      id,
      name: String(o["name"] ?? id),
      hops,
      created_by: String(o["created_by"] ?? ""),
      created_at: Number(o["created_at"] ?? 0),
    };
  },
};

export const claimCodec: Codec<Claim> = {
  id: (c) => c.node_id,
  write(entry, c) {
    entry.set("operator_id", c.operator_id);
    entry.set("intent", c.intent);
    if (c.note !== undefined) entry.set("note", c.note);
    entry.set("claimed_at", c.claimed_at);
    entry.set("expires_at", c.expires_at);
  },
  read(id, o) {
    if (typeof o["operator_id"] !== "string") return null;
    return {
      node_id: id,
      operator_id: String(o["operator_id"]),
      intent: (o["intent"] as ClaimIntent) ?? "recon",
      note: o["note"] !== undefined ? String(o["note"]) : undefined,
      claimed_at: Number(o["claimed_at"] ?? 0),
      expires_at: Number(o["expires_at"] ?? 0),
    };
  },
};

export const detectionCodec: Codec<Detection> = {
  id: (d) => d.id,
  write(entry, d) {
    entry.set("at", d.at);
    entry.set("operator", d.operator);
    if (d.node_ref !== undefined) entry.set("node_ref", d.node_ref);
    entry.set("vector", d.vector);
    if (d.tooling !== undefined) entry.set("tooling", d.tooling);
    entry.set("noise_level", d.noise_level);
    entry.set("outcome", d.outcome);
    if (d.control !== undefined) entry.set("control", d.control);
    if (d.note !== undefined) entry.set("note", d.note);
  },
  read(id, o) {
    if (typeof o["vector"] !== "string") return null;
    return {
      id,
      at: Number(o["at"] ?? 0),
      operator: String(o["operator"] ?? ""),
      node_ref: o["node_ref"] !== undefined ? String(o["node_ref"]) : undefined,
      vector: String(o["vector"]),
      tooling: o["tooling"] !== undefined ? String(o["tooling"]) : undefined,
      noise_level: (o["noise_level"] as NoiseLevel) ?? "moderate",
      outcome: (o["outcome"] as DetectionOutcome) ?? "undetected",
      control: o["control"] !== undefined ? String(o["control"]) : undefined,
      note: o["note"] !== undefined ? String(o["note"]) : undefined,
    };
  },
};

export const taskCodec: Codec<Task> = {
  id: (t) => t.id,
  write(entry, t) {
    entry.set("title", t.title);
    if (t.description !== undefined) entry.set("description", t.description);
    if (t.assignee !== undefined) entry.set("assignee", t.assignee);
    entry.set("created_by", t.created_by);
    entry.set("status", t.status);
    entry.set("priority", t.priority);
    if (t.node_ref !== undefined) entry.set("node_ref", t.node_ref);
    if (t.phase !== undefined) entry.set("phase", t.phase);
    entry.set("created_at", t.created_at);
    entry.set("updated_at", t.updated_at);
  },
  read(id, o) {
    if (typeof o["title"] !== "string") return null;
    return {
      id,
      title: String(o["title"]),
      description: o["description"] !== undefined ? String(o["description"]) : undefined,
      assignee: o["assignee"] !== undefined ? String(o["assignee"]) : undefined,
      created_by: String(o["created_by"] ?? ""),
      status: (o["status"] as TaskStatus) ?? "todo",
      priority: (o["priority"] as Priority) ?? "med",
      node_ref: o["node_ref"] !== undefined ? String(o["node_ref"]) : undefined,
      phase: o["phase"] !== undefined ? String(o["phase"]) : undefined,
      created_at: Number(o["created_at"] ?? 0),
      updated_at: Number(o["updated_at"] ?? 0),
    };
  },
};

export const objectiveCodec: Codec<Objective> = {
  id: (o) => o.id,
  write(entry, ob) {
    entry.set("title", ob.title);
    if (ob.description !== undefined) entry.set("description", ob.description);
    entry.set("status", ob.status);
    if (ob.owner !== undefined) entry.set("owner", ob.owner);
    if (ob.target_node !== undefined) entry.set("target_node", ob.target_node);
    entry.set("priority", ob.priority);
    entry.set("created_by", ob.created_by);
    entry.set("created_at", ob.created_at);
    if (ob.achieved_at !== undefined) entry.set("achieved_at", ob.achieved_at);
  },
  read(id, o) {
    if (typeof o["title"] !== "string") return null;
    return {
      id,
      title: String(o["title"]),
      description: o["description"] !== undefined ? String(o["description"]) : undefined,
      status: (o["status"] as ObjectiveStatus) ?? "not_started",
      owner: o["owner"] !== undefined ? String(o["owner"]) : undefined,
      target_node: o["target_node"] !== undefined ? String(o["target_node"]) : undefined,
      priority: (o["priority"] as Priority) ?? "med",
      created_by: String(o["created_by"] ?? ""),
      created_at: Number(o["created_at"] ?? 0),
      achieved_at: o["achieved_at"] !== undefined ? Number(o["achieved_at"]) : undefined,
    };
  },
};

export const messageCodec: Codec<ChatMessage> = {
  id: (m) => m.id,
  write(entry, m) {
    entry.set("author", m.author);
    entry.set("at", m.at);
    entry.set("body", m.body);
    if (m.ref !== undefined) entry.set("ref", m.ref);
  },
  read(id, o) {
    if (typeof o["body"] !== "string") return null;
    return {
      id,
      author: String(o["author"] ?? ""),
      at: Number(o["at"] ?? 0),
      body: String(o["body"]),
      ref: o["ref"] !== undefined ? String(o["ref"]) : undefined,
    };
  },
};
