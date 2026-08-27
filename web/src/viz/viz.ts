// Visual encoding shared by the map and the side panel. The chrome is neutral
// grey; COLOR is meaning. A node reads as a matte icon inside a ring: the icon is
// tinted by its node GROUP (a sober per-category hue), and the ring COLOR encodes
// compromise (grey clean → green safe → yellow/orange/red owned → magenta apex).
// Edges read by the abuse/structure family they encode.

import type { CompromiseLevel, EdgeKind, NodeKind } from "@/domain/types";

// ---- Per-group node colors (sober, no blue) — drive the icon tint + nav dot. ----
const G_HOST = "#b8bcc0";
const G_NET = "#8b9196";
const G_VIRT = "#6fae9c";
const G_AD = "#c0925a";
const G_CA = "#d4af37";
const G_SVC = "#9ca35f";
const G_ID = "#cbb187";
const G_CLOUD = "#a085c8";
const G_FIND = "#b5685f";
const G_LOOT = "#c79a3e";
const G_OTHER = "#9a9a9a";

export const KIND_COLOR: Record<NodeKind, string> = {
  host_windows: G_HOST,
  host_linux: G_HOST,
  host_macos: G_HOST,
  network_device: G_NET,
  hypervisor: G_VIRT,
  virtual_machine: G_VIRT,
  container: G_VIRT,
  container_host: G_VIRT,
  domain: G_AD,
  forest: G_AD,
  organizational_unit: G_AD,
  gpo: G_AD,
  domain_controller: G_AD,
  certificate_authority: G_CA,
  cert_template: G_CA,
  network_segment: G_NET,
  subnet: G_NET,
  vlan: G_NET,
  service: G_SVC,
  share: G_SVC,
  web_application: G_SVC,
  user_account: G_ID,
  computer_account: G_AD,
  service_account: G_ID,
  group: G_AD,
  cloud_resource: G_CLOUD,
  cloud_identity: G_CLOUD,
  finding: G_FIND,
  loot: G_LOOT,
  custom: G_OTHER,
};

export const kindColor = (k: NodeKind, override?: string): string =>
  override || KIND_COLOR[k] || G_OTHER;

/** A stable hue per operator id — colors authorship tags in the activity log. */
export function operatorHue(id: string): number {
  let h = 0;
  for (const c of id)
    h = (h * 31 + c.charCodeAt(0)) % 360;

  return h;
}

// Ring color by compromise — the loud chromatic ramp (no blue).
export const COMPROMISE_COLOR: Record<CompromiseLevel, string> = {
  unknown: "#5a5a5a",
  none: "#5aa170",
  user: "#d4b257",
  admin: "#db8038",
  system: "#d9554e",
  domain_admin: "#d65a8c",
};

// Node FILL is the canvas color, so even if a renderer paints the square bounding
// box it stays invisible; the icon bakes its own circular face disc, and the ring
// (border) carries compromise. No more square halo behind the node.
const NODE_FACE = "#070707";
export const COMPROMISE_FILL: Record<CompromiseLevel, string> = {
  unknown: NODE_FACE,
  none: NODE_FACE,
  user: NODE_FACE,
  admin: NODE_FACE,
  system: NODE_FACE,
  domain_admin: NODE_FACE,
};

export const compromiseFill = (l: CompromiseLevel): string => COMPROMISE_FILL[l];

export const COMPROMISE_RANK: Record<CompromiseLevel, number> = {
  unknown: 0,
  none: 0,
  user: 1,
  admin: 2,
  system: 3,
  domain_admin: 4,
};

export const compromiseColor = (l: CompromiseLevel): string => COMPROMISE_COLOR[l];

/** Ring thickness grows with compromise severity, so an owned node reads as a
 * heavy ring even at the map node size; apex (domain_admin) is the loudest. */
export const compromiseBorder = (l: CompromiseLevel): number => 2 + COMPROMISE_RANK[l] * 0.85;

// ---- Edge semantic styling -------------------------------------------------
export type EdgeGroup =
  | "identity_priv" | "ad_trust" | "session_cred" | "remote_exec"
  | "hosting" | "network" | "structural" | "operator" | "custom";

export const EDGE_STYLE_GROUP: Record<EdgeKind, EdgeGroup> = {
  member_of: "identity_priv", admin_to: "identity_priv", has_local_admin: "identity_priv",
  owns: "identity_priv", write_dacl: "identity_priv", generic_all: "identity_priv",
  force_change_password: "identity_priv", add_member: "identity_priv", priv_esc: "identity_priv",
  shadow_credentials: "identity_priv", write_spn: "identity_priv", allowed_to_act: "identity_priv",
  allowed_to_delegate: "identity_priv", read_gmsa_password: "identity_priv",
  read_laps_password: "identity_priv", dc_sync: "identity_priv", manage_ca: "identity_priv",
  member_of_domain: "ad_trust", linked_gpo: "ad_trust", dc_for: "ad_trust", trusts: "ad_trust",
  contains_ou: "structural", same_segment: "structural", parent_segment: "structural",
  has_session: "session_cred", credential_valid_for: "session_cred", dumped_from: "session_cred",
  can_rdp: "remote_exec", can_ps_remote: "remote_exec", execute_dcom: "remote_exec", can_ssh: "remote_exec",
  sql_admin: "remote_exec", coerce: "remote_exec",
  hosts_vm: "hosting", vm_hosted_on: "hosting", runs_container: "hosting", listens_on: "hosting",
  connects_to: "network", routes_through: "network", reachable_from: "network",
  pivot_established: "operator", lateral_movement: "operator", exploitable_via: "operator",
  generic_write: "identity_priv", write_owner: "identity_priv", all_extended_rights: "identity_priv",
  write_gp_link: "identity_priv", add_self: "identity_priv",
  unconstrained_delegation: "identity_priv", can_kerberoast: "identity_priv", can_asrep_roast: "identity_priv",
  enroll: "identity_priv", enroll_on_behalf_of: "identity_priv", authenticates_as: "identity_priv",
  published_to: "structural", gpo_applies_to: "identity_priv",
  sql_link: "remote_exec", relay_to: "remote_exec", hosted_on: "hosting",
  affects: "structural", looted_from: "structural", yields_credential: "structural", evidence_for: "structural",
  custom: "custom",
};

export interface EdgeGroupStyle {
  color: string;
  line: "solid" | "dashed" | "dotted";
  arrow: boolean;
  width: number;
}

// Semantic edge palette (mirror the `--edge-*` tokens). Orange = the attack/
// privilege family; green = creds/sessions; bronze = AD trust; yellow = remote
// exec; teal = operator tradecraft; greys = ambient hosting / structure.
const C_PRIV = "#db8038";
const C_CRED = "#5aa170";
const C_TRUST = "#c0925a";
const C_EXEC = "#d4b257";
const C_OP = "#6fae9c";
const C_FG = "#8a8a8a";
const C_DIM = "#46464a";
export const EDGE_GROUP_STYLE: Record<EdgeGroup, EdgeGroupStyle> = {
  identity_priv: { color: C_PRIV, line: "solid", arrow: true, width: 3 },
  ad_trust: { color: C_TRUST, line: "solid", arrow: true, width: 2.5 },
  session_cred: { color: C_CRED, line: "dashed", arrow: true, width: 2.5 },
  remote_exec: { color: C_EXEC, line: "solid", arrow: true, width: 2.5 },
  hosting: { color: C_FG, line: "solid", arrow: true, width: 2 },
  network: { color: C_DIM, line: "dotted", arrow: true, width: 2 },
  structural: { color: C_DIM, line: "dotted", arrow: false, width: 2 },
  operator: { color: C_OP, line: "dashed", arrow: true, width: 2.5 },
  custom: { color: C_FG, line: "dashed", arrow: true, width: 2 },
};

export const edgeGroup = (k: EdgeKind): EdgeGroup => EDGE_STYLE_GROUP[k] ?? "custom";

export const COMPROMISE_LEVELS: CompromiseLevel[] = [
  "unknown", "none", "user", "admin", "system", "domain_admin",
];
