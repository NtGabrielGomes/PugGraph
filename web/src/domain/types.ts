// Mirror of the `domain` model (string-union enums match the Rust
// snake_case serde representation, so JSON crosses the boundary unchanged).

export type NodeKind =
  | "host_windows" | "host_linux" | "host_macos" | "network_device"
  | "hypervisor" | "virtual_machine" | "container" | "container_host"
  | "domain" | "forest" | "organizational_unit" | "gpo" | "domain_controller"
  | "certificate_authority" | "cert_template"
  | "network_segment" | "subnet" | "vlan"
  | "service" | "share" | "web_application"
  | "user_account" | "computer_account" | "service_account" | "group"
  | "cloud_resource" | "cloud_identity"
  | "finding" | "loot" | "custom";

export type EdgeKind =
  | "member_of" | "admin_to" | "has_local_admin" | "owns" | "write_dacl"
  | "generic_all" | "force_change_password" | "add_member" | "priv_esc"
  | "shadow_credentials" | "write_spn" | "allowed_to_act" | "allowed_to_delegate"
  | "read_gmsa_password" | "read_laps_password"
  | "member_of_domain" | "contains_ou" | "linked_gpo" | "dc_for" | "trusts"
  | "dc_sync" | "manage_ca"
  | "has_session" | "credential_valid_for" | "dumped_from"
  | "can_rdp" | "can_ps_remote" | "execute_dcom" | "can_ssh" | "sql_admin" | "coerce"
  | "hosts_vm" | "vm_hosted_on" | "runs_container" | "listens_on"
  | "connects_to" | "routes_through" | "same_segment" | "parent_segment"
  | "reachable_from" | "pivot_established" | "lateral_movement" | "exploitable_via"
  | "generic_write" | "write_owner" | "all_extended_rights" | "write_gp_link" | "add_self"
  | "unconstrained_delegation" | "can_kerberoast" | "can_asrep_roast"
  | "enroll" | "enroll_on_behalf_of" | "published_to" | "authenticates_as"
  | "gpo_applies_to" | "sql_link" | "relay_to" | "hosted_on"
  | "affects" | "looted_from" | "yields_credential" | "evidence_for"
  | "custom";

export type CompromiseLevel =
  | "unknown" | "none" | "user" | "admin" | "system" | "domain_admin";

export type Confidence = "confirmed" | "suspected" | "possible";

export type CredentialType =
  | "password_plaintext" | "password_ntlm" | "password_net_ntlmv2"
  | "kerberos_ticket" | "kerberos_key" | "ssh_key" | "api_key"
  | "token" | "cookie" | "certificate";

export type ValidityState = "unknown" | "valid" | "invalid" | "expired" | "rotated";

export type CredentialSource =
  | "dump" | "spray" | "phishing" | "mitm" | "service_exploit"
  | "config_file" | "memory_dump" | "manual";

export interface CredentialTestResult {
  host: string;
  succeeded: boolean;
  at: number;
  note?: string;
}

export interface Credential {
  id: string;
  username: string;
  domain?: string;
  credential_type: CredentialType;
  /** JSON of a SealedBlob, sealed under the campaign vault key. Absent when only
   * the *existence* of a credential is recorded (no secret captured yet). */
  secret_sealed?: string;
  /** Node id of the principal/account this credential authenticates *as* — the
   * entity it belongs to. Ties the vault to the graph. */
  belongs_to?: string;
  /** Node id of the host this credential was captured/dumped from. */
  obtained_from?: string;
  validity: ValidityState;
  validity_as_of: number;
  source: CredentialSource;
  tested_against: CredentialTestResult[];
  provenance: Provenance;
}

/** Mirrors domain OperatorRole. Lead/operator hold the credential vault. */
export type OperatorRole = "lead" | "operator" | "observer" | "auditor";

export type RosterStatus = "active" | "revoked";

/** A team member, managed in the campaign doc's `roster` container — the single
 * source of truth the UI uses to enroll co-operators, re-wrap the campaign key on
 * rotation, and pick recovery trustees, so pubkeys are never re-pasted. It holds
 * PUBLIC material only (safe inside the E2E-encrypted doc). It is NEVER trusted
 * for op-signature verification: the file-header recipients are the cryptographic
 * source of truth, since the roster is writable by any member. */
export interface RosterEntry {
  operator_id: string;
  display_name: string;
  /** Base64 Ed25519 verifying key. */
  signing_pubkey: string;
  /** Base64 X25519 public key (the campaign-key envelope recipient). */
  wrapping_pubkey: string;
  role: OperatorRole;
  status: RosterStatus;
  /** Operator id that added this entry. */
  added_by: string;
  added_at: number;
}

export interface IdentityKey {
  kind: string;
  value: string;
  is_primary: boolean;
}

/** A team-shared, named attack path bookmarked from the live graph. Stored in
 * the campaign doc's web-managed `pathmarks` container (like `theme`/`roster`),
 * so everyone sees the routes the team cares about. */
export interface PathMark {
  id: string;
  name: string;
  /** Ordered node ids from foothold to goal. */
  hops: string[];
  created_by: string;
  created_at: number;
}

/** An operator chat message, team-shared in the campaign doc's web-managed
 * `messages` container (like `pathmarks`). It lives inside the sealed campaign
 * file exactly like every other entry, so chat is E2E-encrypted and convergent
 * for free. `ref` optionally pins the message to a node/edge it discusses (a
 * clickable context chip). */
export interface ChatMessage {
  id: string;
  author: string;
  at: number;
  body: string;
  ref?: string;
}

/** A team-shared, named structured filter query (subsumes the old lenses).
 * Web-managed `filters` container. */
export interface SavedFilter {
  id: string;
  name: string;
  query: string;
  created_by: string;
}

/** A team-shared node template — a reusable kind + field defaults + tags to
 * stamp out similar assets. Web-managed `templates` container. */
export interface NodeTemplate {
  id: string;
  name: string;
  kind: NodeKind;
  fields: Record<string, unknown>;
  tags: string[];
  created_by: string;
}

export interface Provenance {
  author: string;
  source: { kind: "manual" | "import" | "inference"; tool?: string };
  confidence: Confidence;
  first_seen: number;
  last_verified: number;
}

// ---- collaboration & engagement lifecycle (team-shared, web-managed) --------

/** A lease-based "I am operating on this host" claim, for live deconfliction —
 * so two operators don't kerberoast the same DC into lockout or double-beacon a
 * box. One per node; renewed on heartbeat, auto-expires. */
export type ClaimIntent = "recon" | "exploiting" | "priv_esc" | "beaconing" | "looting" | "cleanup";
export interface Claim {
  node_id: string;
  operator_id: string;
  intent: ClaimIntent;
  note?: string;
  claimed_at: number;
  expires_at: number;
}

/** A detection/OPSEC event — what was loud and what the defenders caught. Drives
 * the purple-team readout (technique × control × outcome) and per-node OPSEC status. */
export type NoiseLevel = "silent" | "low" | "moderate" | "loud";
export type DetectionOutcome =
  | "undetected" | "logged" | "alerted" | "blocked" | "quarantined" | "investigated" | "burned";
export interface Detection {
  id: string;
  at: number;
  operator: string;
  node_ref?: string;
  /** ATT&CK technique id / name of what was attempted. */
  vector: string;
  tooling?: string;
  noise_level: NoiseLevel;
  outcome: DetectionOutcome;
  /** The security control involved (e.g. MDE, CrowdStrike, Splunk). */
  control?: string;
  note?: string;
}

/** A work item on the tasking board, assignable to an operator. */
export type TaskStatus = "todo" | "in_progress" | "blocked" | "done" | "wont_do";
export type Priority = "low" | "med" | "high";
export interface Task {
  id: string;
  title: string;
  description?: string;
  assignee?: string;
  created_by: string;
  status: TaskStatus;
  priority: Priority;
  node_ref?: string;
  phase?: string;
  created_at: number;
  updated_at: number;
}

/** A SOW objective / flag, with the asset it targets and whether it's been met. */
export type ObjectiveStatus = "not_started" | "in_progress" | "achieved" | "failed" | "partial";
export interface Objective {
  id: string;
  title: string;
  description?: string;
  status: ObjectiveStatus;
  owner?: string;
  target_node?: string;
  priority: Priority;
  created_by: string;
  created_at: number;
  achieved_at?: number;
}

/** Engagement scope / rules of engagement — the guardrails. A single record. */
export interface Scope {
  in_scope_cidrs: string[];
  out_of_scope_cidrs: string[];
  forbidden_node_ids: string[];
  time_windows: { start: string; end: string; tz?: string; label?: string }[];
  notes?: string;
}

/** Team-shared visual overrides, persisted in the campaign doc's `theme`
 * container. Empty by default — the baked-in per-kind defaults are correct
 * without any tuning; these only carry deliberate operator customizations. */
export interface ThemeOverrides {
  colors: Partial<Record<NodeKind, string>>;
  glyphs: Partial<Record<NodeKind, NodeKind>>;
  /** Per-kind icon form-factor (e.g. "laptop", "router"); empty = recommended default. */
  variants: Partial<Record<NodeKind, string>>;
}

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  identity_keys: IdentityKey[];
  compromise_level: CompromiseLevel;
  fields: Record<string, unknown>;
  tags: string[];
  provenance: Provenance;
}

/** A member of a folded collection — a parsed object kept OFF the canvas (never a
 * graph node) until something references it or the operator promotes it. Keyed by
 * a stable dedup key (SID / `domain\sam` / UPN). Sealed secrets (e.g. NTDS hashes)
 * ride along to be lifted into the vault on promotion. */
export interface CollectionMember {
  key: string;
  kind: NodeKind;
  label: string;
  identity_keys: IdentityKey[];
  fields: Record<string, unknown>;
  tags: string[];
  sealed_secrets?: { type: CredentialType; username: string; domain?: string; sealed?: string }[];
}

/** A folded import collection: a SharpHound/secretsdump dump's thousands of objects
 * stored as ONE off-canvas node, so a 5k-seat domain doesn't bury the map. Members
 * are promoted to real graph nodes lazily (on edge reference, finding, or operator
 * pick). Web-managed (the Rust core ignores it; it round-trips in the snapshot). */
export interface Collection {
  id: string;
  tool: string;
  object_type: string;
  domain?: string;
  label: string;
  created_by: string;
  created_at: number;
  last_collected_at: number;
  /** Aggregate counts for the folded-node dashboard (e.g. {kerberoastable: 12}). */
  stats: Record<string, number>;
  /** Live folded-member count (not yet promoted). */
  count: number;
}

export interface GraphEdge {
  id: string;
  kind: EdgeKind;
  source: string;
  target: string;
  confidence: Confidence;
  /** Role-specific attributes of the relation (trust direction, port, technique
   * id, evidence...), in the open `fields` bag mirroring a node's `fields`. Always
   * populated by the campaign reader; optional on construction. */
  fields?: Record<string, unknown>;
  provenance: Provenance;
}

/** Edge kinds an attacker can actually traverse (mirrors EdgeKind::is_traversable). */
const NON_TRAVERSABLE: ReadonlySet<EdgeKind> = new Set([
  "same_segment", "parent_segment", "contains_ou", "member_of_domain",
  "published_to", "affects", "looted_from", "yields_credential", "evidence_for",
]);
export const isTraversable = (k: EdgeKind): boolean => !NON_TRAVERSABLE.has(k);

/** High-value targets pathfinding treats as goals (mirrors NodeKind::is_high_value). */
const HIGH_VALUE: ReadonlySet<NodeKind> = new Set([
  "domain_controller", "certificate_authority", "domain", "forest",
]);
export const isHighValue = (k: NodeKind): boolean => HIGH_VALUE.has(k);
