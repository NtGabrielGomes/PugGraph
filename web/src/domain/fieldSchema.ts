// A declarative, per-node-kind field schema that drives a typed editor in the
// side panel — so capturing a host's OS, role, services and findings is
// structured where structure helps, instead of raw key/value JSON. Values still
// live in the open `fields` bag (no Rust/CRDT migration; importers stay free to
// stash anything), and arbitrary extra keys remain addable. `notes` is appended
// to every kind; `findings` is a structured list handled by the panel directly.

import type { EdgeKind, NodeKind } from "@/domain/types";

export type FieldType = "text" | "number" | "bool" | "enum" | "tags" | "multiline";

export interface FieldDef {
  key: string;
  label: string;
  type: FieldType;
  group: string;
  enumValues?: string[];
  placeholder?: string;
}

const ROLE = ["workstation", "server", "domain_controller", "file_server", "web_server", "database", "jump_host", "hypervisor", "other"];
const DELEGATION = ["none", "unconstrained", "constrained", "rbcd"];

// Per-kind schemas (without the shared `notes`, which `schemaFor` appends). The
// fields are the ones an operator actually records and abuses — not an exhaustive
// directory dump. Values live in the open `fields` bag (no Rust/CRDT migration).
const SCHEMA: Partial<Record<NodeKind, FieldDef[]>> = {
  host_windows: [
    { key: "os", label: "OS", type: "text", group: "System", placeholder: "Windows Server 2019" },
    { key: "os_version", label: "OS version / build", type: "text", group: "System" },
    { key: "network_role", label: "Role", type: "enum", group: "System", enumValues: ROLE },
    { key: "ip_addresses", label: "IP addresses", type: "tags", group: "Network" },
    { key: "mac", label: "MAC", type: "text", group: "Network" },
    { key: "domain", label: "Domain", type: "text", group: "Identity" },
    { key: "smb_signing", label: "SMB signing", type: "enum", group: "Identity", enumValues: ["required", "enabled", "disabled"] },
    { key: "av_edr", label: "AV / EDR", type: "text", group: "Access" },
    { key: "delegation", label: "Delegation", type: "enum", group: "Access", enumValues: DELEGATION },
    { key: "unconstrained_delegation", label: "Unconstrained delegation", type: "bool", group: "Access" },
    { key: "ms17_010", label: "MS17-010 candidate", type: "bool", group: "Access" },
    { key: "pre2k", label: "Pre-Windows 2000 compatible", type: "bool", group: "Access" },
    { key: "local_admin_obtained", label: "Local admin obtained", type: "bool", group: "Access" },
    { key: "patch_level", label: "Patch level", type: "text", group: "Access" },
  ],
  host_linux: [
    { key: "os", label: "OS / distro", type: "text", group: "System", placeholder: "Ubuntu 22.04" },
    { key: "os_version", label: "Version", type: "text", group: "System" },
    { key: "network_role", label: "Role", type: "enum", group: "System", enumValues: ROLE },
    { key: "kernel", label: "Kernel", type: "text", group: "System" },
    { key: "ip_addresses", label: "IP addresses", type: "tags", group: "Network" },
    { key: "ssh_version", label: "SSH version", type: "text", group: "Network" },
    { key: "sudo_rights", label: "Sudo rights", type: "text", group: "Access" },
    { key: "root_obtained", label: "Root obtained", type: "bool", group: "Access" },
  ],
  host_macos: [
    { key: "os_version", label: "macOS version", type: "text", group: "System" },
    { key: "ip_addresses", label: "IP addresses", type: "tags", group: "Network" },
    { key: "mac", label: "MAC", type: "text", group: "Network" },
    { key: "filevault", label: "FileVault", type: "bool", group: "Access" },
    { key: "sip", label: "SIP enabled", type: "bool", group: "Access" },
    { key: "gatekeeper", label: "Gatekeeper", type: "bool", group: "Access" },
    { key: "tcc_bypass", label: "TCC bypass", type: "text", group: "Access" },
  ],
  network_device: [
    { key: "vendor", label: "Vendor", type: "text", group: "System" },
    { key: "model", label: "Model", type: "text", group: "System" },
    { key: "os_version", label: "Firmware / OS", type: "text", group: "System" },
    { key: "mgmt_protocol", label: "Mgmt protocol", type: "enum", group: "Access", enumValues: ["ssh", "telnet", "https", "http", "snmp"] },
    { key: "default_creds", label: "Default creds", type: "bool", group: "Access" },
    { key: "snmp_community", label: "SNMP community", type: "text", group: "Access" },
    { key: "ip_addresses", label: "IP addresses", type: "tags", group: "Network" },
  ],
  hypervisor: [
    { key: "product", label: "Product", type: "enum", group: "System", enumValues: ["esxi", "hyper-v", "proxmox", "kvm", "xen", "other"] },
    { key: "version", label: "Version / build", type: "text", group: "System" },
    { key: "cluster", label: "Cluster", type: "text", group: "System" },
    { key: "management_url", label: "Management URL", type: "text", group: "Network" },
    { key: "ip_addresses", label: "IP addresses", type: "tags", group: "Network" },
    { key: "vm_count", label: "VM count", type: "number", group: "System" },
  ],
  virtual_machine: [
    { key: "os", label: "Guest OS", type: "text", group: "System" },
    { key: "os_version", label: "OS version", type: "text", group: "System" },
    { key: "network_role", label: "Role", type: "enum", group: "System", enumValues: ROLE },
    { key: "power_state", label: "Power state", type: "enum", group: "System", enumValues: ["running", "stopped", "suspended"] },
    { key: "snapshot_count", label: "Snapshots", type: "number", group: "System" },
    { key: "ip_addresses", label: "IP addresses", type: "tags", group: "Network" },
  ],
  container: [
    { key: "image", label: "Image", type: "text", group: "System" },
    { key: "image_digest", label: "Image digest", type: "text", group: "System" },
    { key: "runtime", label: "Runtime", type: "enum", group: "System", enumValues: ["docker", "containerd", "cri-o", "other"] },
    { key: "privileged", label: "Privileged", type: "bool", group: "Access" },
    { key: "capabilities", label: "Capabilities", type: "tags", group: "Access" },
    { key: "mounts", label: "Host mounts", type: "tags", group: "Access" },
    { key: "exposed_ports", label: "Exposed ports", type: "tags", group: "Network" },
    { key: "ip_addresses", label: "IP addresses", type: "tags", group: "Network" },
  ],
  container_host: [
    { key: "orchestrator", label: "Orchestrator", type: "enum", group: "System", enumValues: ["kubernetes", "docker-swarm", "nomad", "none"] },
    { key: "cluster", label: "Cluster", type: "text", group: "System" },
    { key: "node_role", label: "Node role", type: "enum", group: "System", enumValues: ["control-plane", "worker", "etcd", "standalone"] },
    { key: "kubelet_version", label: "Kubelet / runtime version", type: "text", group: "System" },
    { key: "rbac", label: "RBAC notes", type: "text", group: "Access" },
    { key: "os_version", label: "OS version", type: "text", group: "System" },
    { key: "ip_addresses", label: "IP addresses", type: "tags", group: "Network" },
  ],
  domain_controller: [
    { key: "os_version", label: "OS version", type: "text", group: "System" },
    { key: "domain", label: "Domain", type: "text", group: "Identity" },
    { key: "functional_level", label: "Functional level", type: "text", group: "Identity" },
    { key: "fsmo_roles", label: "FSMO roles", type: "tags", group: "Identity" },
    { key: "ip_addresses", label: "IP addresses", type: "tags", group: "Network" },
  ],
  domain: [
    { key: "functional_level", label: "Functional level", type: "text", group: "Identity" },
    { key: "netbios", label: "NetBIOS", type: "text", group: "Identity" },
    { key: "sid", label: "Domain SID", type: "text", group: "Identity" },
    { key: "forest_root", label: "Forest root", type: "text", group: "Identity" },
    { key: "ms_ds_machineaccountquota", label: "MachineAccountQuota", type: "number", group: "Identity" },
  ],
  forest: [
    { key: "functional_level", label: "Functional level", type: "text", group: "Identity" },
    { key: "root_domain", label: "Root domain", type: "text", group: "Identity" },
    { key: "child_domains", label: "Child domains", type: "tags", group: "Identity" },
    { key: "schema_version", label: "Schema version", type: "text", group: "Identity" },
    { key: "adcs_present", label: "ADCS present", type: "bool", group: "Access" },
    { key: "tier_zero", label: "Tier-zero / high-value", type: "bool", group: "Access" },
  ],
  organizational_unit: [
    { key: "distinguished_name", label: "Distinguished name", type: "text", group: "Identity" },
    { key: "blocks_inheritance", label: "Blocks GPO inheritance", type: "bool", group: "Identity" },
    { key: "delegated_admins", label: "Delegated admins", type: "tags", group: "Access" },
    { key: "laps_scoped", label: "LAPS scoped here", type: "bool", group: "Access" },
    { key: "is_tier_zero", label: "Tier-zero OU", type: "bool", group: "Access" },
    { key: "description", label: "Description", type: "text", group: "Identity" },
  ],
  gpo: [
    { key: "guid", label: "GUID", type: "text", group: "Identity" },
    { key: "enabled", label: "Enabled", type: "bool", group: "Identity" },
    { key: "scope", label: "Scope of management", type: "text", group: "Identity" },
    { key: "interesting_settings", label: "Interesting settings", type: "multiline", group: "Access" },
  ],
  certificate_authority: [
    { key: "ca_name", label: "CA name", type: "text", group: "Identity" },
    { key: "dns", label: "DNS host", type: "text", group: "Network" },
    { key: "subject", label: "Subject", type: "text", group: "Identity" },
    { key: "is_enterprise_ca", label: "Enterprise CA", type: "bool", group: "Identity" },
    { key: "web_enrollment_http", label: "HTTP web enrollment (ESC8)", type: "bool", group: "ADCS abuse" },
    { key: "epa_enforced", label: "EPA enforced", type: "bool", group: "ADCS abuse" },
    { key: "editf_attributesubjectaltname2", label: "EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)", type: "bool", group: "ADCS abuse" },
    { key: "enforce_encrypt_cert_request", label: "Enforce encrypt request (false ⇒ ESC11)", type: "bool", group: "ADCS abuse" },
    { key: "disable_extension_list_has_szoid", label: "szOID security ext removed (ESC16)", type: "bool", group: "ADCS abuse" },
    { key: "strong_cert_binding_enforcement", label: "Strong cert binding (ESC9/10)", type: "enum", group: "ADCS abuse", enumValues: ["0_disabled", "1_compatibility", "2_full"] },
    { key: "certificate_mapping_methods", label: "Cert mapping methods (ESC10)", type: "text", group: "ADCS abuse" },
    { key: "private_key_exportable", label: "CA private key exportable (ESC12)", type: "bool", group: "ADCS abuse" },
    { key: "ca_managers", label: "CA managers (ManageCA → ESC7)", type: "tags", group: "ADCS abuse" },
    { key: "enrollment_agents", label: "Enrollment agents", type: "text", group: "Access" },
  ],
  cert_template: [
    { key: "template_name", label: "Template name", type: "text", group: "Identity" },
    { key: "schema_version", label: "Schema version (1 ⇒ ESC15)", type: "number", group: "Identity" },
    { key: "ekus", label: "EKUs", type: "tags", group: "Identity" },
    { key: "client_auth_eku", label: "Client-auth EKU", type: "bool", group: "ADCS abuse" },
    { key: "any_purpose_eku", label: "Any-purpose EKU (ESC2)", type: "bool", group: "ADCS abuse" },
    { key: "enrollment_agent_eku", label: "Enrollment-agent EKU (ESC3)", type: "bool", group: "ADCS abuse" },
    { key: "enrollee_supplies_subject", label: "Enrollee supplies subject (ESC1)", type: "bool", group: "ADCS abuse" },
    { key: "requires_manager_approval", label: "Requires manager approval", type: "bool", group: "ADCS abuse" },
    { key: "authorized_signatures_required", label: "Authorized signatures (0 ⇒ abusable)", type: "number", group: "ADCS abuse" },
    { key: "no_security_extension", label: "No security extension (ESC9)", type: "bool", group: "ADCS abuse" },
    { key: "low_priv_enroll", label: "Low-priv enrollment allowed", type: "bool", group: "ADCS abuse" },
    { key: "certificate_policy_oids", label: "Policy OIDs (msPKI-Certificate-Policy → ESC13)", type: "tags", group: "ADCS abuse" },
  ],
  service: [
    { key: "port", label: "Port", type: "number", group: "Service" },
    { key: "protocol", label: "Protocol", type: "enum", group: "Service", enumValues: ["tcp", "udp"] },
    { key: "product", label: "Product", type: "text", group: "Service" },
    { key: "version", label: "Version", type: "text", group: "Service" },
    { key: "cve", label: "CVEs", type: "tags", group: "Service" },
    { key: "auth_required", label: "Auth required", type: "bool", group: "Access" },
    { key: "default_creds", label: "Default creds work", type: "bool", group: "Access" },
    { key: "exploit_available", label: "Public exploit", type: "bool", group: "Access" },
    { key: "banner", label: "Banner", type: "multiline", group: "Service" },
  ],
  share: [
    { key: "unc_path", label: "UNC path", type: "text", group: "Service" },
    { key: "readable", label: "Readable", type: "bool", group: "Access" },
    { key: "writable", label: "Writable", type: "bool", group: "Access" },
    { key: "owner", label: "Owner", type: "text", group: "Access" },
    { key: "acl", label: "ACL", type: "multiline", group: "Access" },
    { key: "comment", label: "Comment", type: "text", group: "Service" },
  ],
  user_account: [
    { key: "upn", label: "UPN", type: "text", group: "Identity" },
    { key: "sam", label: "sAMAccountName", type: "text", group: "Identity" },
    { key: "sid", label: "SID", type: "text", group: "Identity" },
    { key: "enabled", label: "Enabled", type: "bool", group: "Identity" },
    { key: "description", label: "Description", type: "text", group: "Identity" },
    { key: "pwd_last_set", label: "Password last set", type: "text", group: "Access" },
    { key: "admin_count", label: "adminCount=1", type: "bool", group: "Access" },
    { key: "password_never_expires", label: "Password never expires", type: "bool", group: "Access" },
    { key: "locked_out", label: "Locked out", type: "bool", group: "Access" },
    { key: "kerberoastable", label: "Kerberoastable", type: "bool", group: "Access" },
    { key: "asrep_roastable", label: "AS-REP roastable", type: "bool", group: "Access" },
    { key: "sid_history", label: "SID history", type: "tags", group: "Access" },
    { key: "alt_security_identities", label: "altSecurityIdentities (ESC14)", type: "text", group: "Access" },
    { key: "mfa", label: "MFA enabled", type: "bool", group: "Access" },
  ],
  computer_account: [
    { key: "sam", label: "sAMAccountName", type: "text", group: "Identity" },
    { key: "sid", label: "SID", type: "text", group: "Identity" },
    { key: "dns_name", label: "DNS name", type: "text", group: "Identity" },
    { key: "os_version", label: "OS version", type: "text", group: "System" },
    { key: "spn", label: "SPNs", type: "tags", group: "Identity" },
    { key: "delegation", label: "Delegation", type: "enum", group: "Access", enumValues: DELEGATION },
    { key: "unconstrained_delegation", label: "Unconstrained delegation", type: "bool", group: "Access" },
    { key: "rbcd_configured", label: "RBCD configured", type: "bool", group: "Access" },
    { key: "laps_enabled", label: "LAPS enabled", type: "bool", group: "Access" },
    { key: "laps_pw_known", label: "LAPS password known", type: "bool", group: "Access" },
    { key: "gmsa", label: "gMSA", type: "bool", group: "Access" },
    { key: "is_tier_zero", label: "Tier-zero", type: "bool", group: "Access" },
  ],
  service_account: [
    { key: "upn", label: "UPN", type: "text", group: "Identity" },
    { key: "sam", label: "sAMAccountName", type: "text", group: "Identity" },
    { key: "spn", label: "SPN", type: "text", group: "Identity" },
    { key: "description", label: "Description", type: "text", group: "Identity" },
    { key: "kerberoastable", label: "Kerberoastable", type: "bool", group: "Access" },
    { key: "delegation_type", label: "Delegation", type: "enum", group: "Access", enumValues: DELEGATION },
    { key: "constrained_targets", label: "Constrained targets", type: "tags", group: "Access" },
  ],
  group: [
    { key: "sid", label: "SID", type: "text", group: "Identity" },
    { key: "description", label: "Description", type: "text", group: "Identity" },
    { key: "member_count", label: "Members", type: "number", group: "Identity" },
    { key: "scope", label: "Scope", type: "enum", group: "Identity", enumValues: ["domain_local", "global", "universal"] },
    { key: "group_type", label: "Type", type: "enum", group: "Identity", enumValues: ["security", "distribution"] },
    { key: "is_tier_zero", label: "Tier-zero / high-value", type: "bool", group: "Access" },
    { key: "admin_count", label: "adminCount=1", type: "bool", group: "Access" },
    { key: "foreign_members", label: "Foreign-domain members", type: "bool", group: "Access" },
  ],
  network_segment: [
    { key: "cidr", label: "CIDR", type: "text", group: "Network" },
    { key: "gateway", label: "Gateway", type: "text", group: "Network" },
    { key: "vlan_id", label: "VLAN id", type: "text", group: "Network" },
    { key: "segmentation_enforced", label: "Segmentation enforced", type: "bool", group: "Access" },
    { key: "description", label: "Description", type: "text", group: "Network" },
  ],
  subnet: [
    { key: "cidr", label: "CIDR", type: "text", group: "Network" },
    { key: "gateway", label: "Gateway", type: "text", group: "Network" },
    { key: "site", label: "AD site", type: "text", group: "Network" },
    { key: "scanned", label: "Scanned", type: "bool", group: "Access" },
  ],
  vlan: [
    { key: "vlan_id", label: "VLAN id", type: "number", group: "Network" },
    { key: "name", label: "Name", type: "text", group: "Network" },
    { key: "cidr", label: "CIDR", type: "text", group: "Network" },
    { key: "inter_vlan_routing", label: "Inter-VLAN routing", type: "bool", group: "Access" },
    { key: "segmentation_enforced", label: "Segmentation enforced", type: "bool", group: "Access" },
  ],
  cloud_resource: [
    { key: "provider", label: "Provider", type: "enum", group: "System", enumValues: ["aws", "azure", "gcp", "other"] },
    { key: "resource_type", label: "Resource type", type: "text", group: "System" },
    { key: "resource_id", label: "Resource id / ARN", type: "text", group: "System" },
    { key: "region", label: "Region", type: "text", group: "Network" },
    { key: "public_access", label: "Public access", type: "bool", group: "Access" },
    { key: "encryption", label: "Encryption at rest", type: "bool", group: "Access" },
  ],
  cloud_identity: [
    { key: "provider", label: "Provider", type: "enum", group: "Identity", enumValues: ["aws", "azure", "gcp", "other"] },
    { key: "principal_type", label: "Principal type", type: "text", group: "Identity" },
    { key: "tenant_id", label: "Tenant / account id", type: "text", group: "Identity" },
    { key: "roles", label: "Roles / policies", type: "tags", group: "Access" },
    { key: "mfa_enabled", label: "MFA enabled", type: "bool", group: "Access" },
    { key: "last_signin", label: "Last sign-in", type: "text", group: "Access" },
  ],
};

const NOTES: FieldDef = { key: "notes", label: "Notes", type: "multiline", group: "Notes", placeholder: "Free-form observations..." };

// ---- Compromise / access vector -------------------------------------------
// "How this machine was compromised" is NOT a node kind and NOT an edge: it is
// an optional field on the compromised host — the narrative link between the
// loot / credential vault (a credential's `obtained_from` points back to this
// machine) and the specific machine. Only hosts (NodeClass::Host) carry it.

export const COMPROMISE_METHODS = [
  "exposed_service", "exploited_vuln", "valid_credentials", "password_spray",
  "phishing", "kerberoast", "asreproast", "pass_the_hash", "pass_the_ticket",
  "token_impersonation", "ntlm_relay", "rdp", "ssh", "winrm", "smb",
  "web_shell", "sql_injection", "misconfiguration", "physical", "wifi",
  "vpn_pivot", "social_engineering", "other",
] as const;

/** The Host NodeClass (mirrors domain `NodeClass::Host`) — the kinds
 * that can be a compromised machine / access point into the network. */
export const HOST_KINDS: ReadonlySet<NodeKind> = new Set<NodeKind>([
  "host_windows", "host_linux", "host_macos", "network_device", "hypervisor",
  "virtual_machine", "container", "container_host", "domain_controller",
]);

export const isHostKind = (k: NodeKind): boolean => HOST_KINDS.has(k);

// Appended to every Host kind. The access vector lives in its own "Compromise"
// group so it reads as a dossier (clear *how* it was compromised), not buried.
const COMPROMISE: FieldDef[] = [
  { key: "compromise_method", label: "How compromised", type: "enum", group: "Compromise", enumValues: [...COMPROMISE_METHODS] },
  { key: "compromise_note", label: "Access note", type: "multiline", group: "Compromise", placeholder: "e.g. OpenVPN gateway; creds from phishing" },
];

/** The typed fields for a node kind, in render order. Host kinds gain the
 * compromise / access-vector fields; `notes` is always last. */
export const schemaFor = (kind: NodeKind): FieldDef[] => [
  ...(SCHEMA[kind] ?? []),
  ...(HOST_KINDS.has(kind) ? COMPROMISE : []),
  NOTES,
];

/** The set of keys the typed editor owns, so the free-form editor shows only
 * extras and never duplicates a schema field. `findings` is panel-managed. */
export const schemaKeys = (kind: NodeKind): Set<string> =>
  new Set([...schemaFor(kind).map((f) => f.key), "findings"]);

// ---- Edge field schema ----------------------------------------------------
// Relations carry role-specific attributes too (trust direction, port, the
// technique that established them, evidence). Every edge gets the shared
// Evidence group; specific kinds add their own. Stored in the edge `fields` bag
// exactly like a node's, so there is no CRDT/Rust migration.

const EDGE_EVIDENCE: FieldDef[] = [
  { key: "technique_id", label: "MITRE technique", type: "text", group: "Evidence", placeholder: "T1021.001" },
  { key: "tool", label: "Tool", type: "text", group: "Evidence", placeholder: "evil-winrm" },
  { key: "evidence", label: "Evidence / note", type: "multiline", group: "Evidence", placeholder: "command, output, or proof reference" },
];

// Offensive tradecraft: detection risk + the action needed to revert the change,
// appended to edges that represent an attacker action/right an operator records
// during a live engagement (so OPSEC and cleanup are first-class, not buried).
const TRADECRAFT: FieldDef[] = [
  { key: "opsec_note", label: "OPSEC", type: "text", group: "Tradecraft", placeholder: "detection risk / artifacts left" },
  { key: "cleanup_action", label: "Cleanup", type: "text", group: "Tradecraft", placeholder: "what to revert (e.g. remove key, restore DACL)" },
  { key: "valid_until", label: "Valid until", type: "text", group: "Tradecraft", placeholder: "expiry / pw-change invalidation" },
];
const TRADECRAFT_EDGES: ReadonlySet<EdgeKind> = new Set<EdgeKind>([
  "shadow_credentials", "write_spn", "allowed_to_act", "allowed_to_delegate", "read_gmsa_password",
  "read_laps_password", "dc_sync", "manage_ca", "sql_admin", "coerce", "generic_all", "write_dacl",
  "owns", "force_change_password", "add_member", "priv_esc", "lateral_movement", "pivot_established",
  "dumped_from",
]);

const VIA = ["rid500", "local_group", "gpo", "restricted_groups", "other"];

const EDGE_SCHEMA: Partial<Record<EdgeKind, FieldDef[]>> = {
  // Identity & privilege
  member_of: [
    { key: "nested", label: "Nested (transitive)", type: "bool", group: "Membership" },
    { key: "foreign", label: "Foreign-domain principal", type: "bool", group: "Membership" },
  ],
  admin_to: [
    { key: "via", label: "Via", type: "enum", group: "Access", enumValues: VIA },
    { key: "confirmed_exec", label: "Confirmed code exec", type: "bool", group: "Access" },
  ],
  has_local_admin: [{ key: "via", label: "Via", type: "enum", group: "Access", enumValues: VIA }],
  owns: [{ key: "right_source", label: "Right source", type: "enum", group: "Abuse", enumValues: ["explicit", "inherited"] }],
  write_dacl: [{ key: "inherited", label: "Inherited", type: "bool", group: "Abuse" }],
  generic_all: [
    { key: "exploited_via", label: "Exploited via", type: "enum", group: "Abuse", enumValues: ["reset_password", "shadow_credentials", "rbcd", "targeted_kerberoast", "dc_sync", "other"] },
  ],
  shadow_credentials: [
    { key: "device_id", label: "KeyCredential device id", type: "text", group: "Abuse" },
    { key: "certificate_obtained", label: "Certificate obtained", type: "bool", group: "Abuse" },
  ],
  write_spn: [
    { key: "spn_set", label: "SPN set", type: "text", group: "Abuse", placeholder: "MSSQLSvc/host:1433" },
    { key: "hash_cracked", label: "Hash cracked", type: "bool", group: "Abuse" },
  ],
  allowed_to_act: [
    { key: "impersonated", label: "Impersonated principal", type: "text", group: "Abuse" },
    { key: "configured_by_operator", label: "Configured by us", type: "bool", group: "Abuse" },
  ],
  allowed_to_delegate: [
    { key: "spns", label: "Allowed-to SPNs", type: "tags", group: "Abuse" },
    { key: "protocol_transition", label: "Protocol transition (T2A4D)", type: "bool", group: "Abuse" },
  ],
  read_gmsa_password: [{ key: "recovered", label: "Password recovered", type: "bool", group: "Abuse" }],
  read_laps_password: [{ key: "recovered", label: "Password recovered", type: "bool", group: "Abuse" }],
  // AD structure & trust
  trusts: [
    { key: "direction", label: "Direction", type: "enum", group: "Trust", enumValues: ["inbound", "outbound", "bidirectional"] },
    { key: "trust_type", label: "Type", type: "enum", group: "Trust", enumValues: ["parent_child", "tree_root", "external", "forest", "realm"] },
    { key: "transitive", label: "Transitive", type: "bool", group: "Trust" },
    { key: "sid_filtering", label: "SID filtering", type: "bool", group: "Trust" },
    { key: "trust_keys_known", label: "Trust keys known", type: "bool", group: "Trust" },
  ],
  linked_gpo: [
    { key: "enforced", label: "Enforced", type: "bool", group: "Link" },
    { key: "precedence", label: "Precedence", type: "number", group: "Link" },
    { key: "can_write", label: "Can write GPO (WriteGPLink)", type: "bool", group: "Link" },
  ],
  dc_sync: [
    { key: "get_changes", label: "GetChanges", type: "bool", group: "Abuse" },
    { key: "get_changes_all", label: "GetChangesAll", type: "bool", group: "Abuse" },
    { key: "replicated", label: "Secrets replicated", type: "bool", group: "Abuse" },
  ],
  manage_ca: [
    { key: "can_issue", label: "Can issue / approve certs", type: "bool", group: "Abuse" },
    { key: "esc7_abused", label: "ESC7 abused", type: "bool", group: "Abuse" },
  ],
  // Sessions & credentials
  has_session: [
    { key: "logon_type", label: "Logon type", type: "enum", group: "Session", enumValues: ["interactive", "network", "service", "rdp", "batch", "unlock"] },
    { key: "stale", label: "Stale", type: "bool", group: "Session" },
    { key: "creds_recoverable", label: "Creds recoverable", type: "bool", group: "Session" },
  ],
  dumped_from: [
    { key: "secret_type", label: "Secret type", type: "enum", group: "Abuse", enumValues: ["ntlm", "aes", "tgt", "kerberos", "plaintext", "dpapi", "lsa"] },
    { key: "dump_method", label: "Method", type: "enum", group: "Abuse", enumValues: ["lsass", "sam", "ntds", "dc_sync", "registry", "dpapi", "lsa_secrets", "other"] },
  ],
  credential_valid_for: [{ key: "last_validated", label: "Last validated", type: "text", group: "Abuse" }],
  // Remote execution
  can_rdp: [
    { key: "port", label: "Port", type: "number", group: "Access" },
    { key: "nla", label: "NLA required", type: "bool", group: "Access" },
  ],
  can_ssh: [
    { key: "port", label: "Port", type: "number", group: "Access" },
    { key: "auth_method", label: "Auth method", type: "enum", group: "Access", enumValues: ["password", "key", "certificate"] },
  ],
  can_ps_remote: [
    { key: "port", label: "Port", type: "number", group: "Access" },
    { key: "encryption", label: "Encrypted", type: "bool", group: "Access" },
  ],
  sql_admin: [
    { key: "link_chain", label: "Linked-server chain", type: "text", group: "Access" },
    { key: "xp_cmdshell", label: "xp_cmdshell enabled", type: "bool", group: "Access" },
  ],
  coerce: [
    { key: "method", label: "Coercion method", type: "enum", group: "Abuse", enumValues: ["petitpotam", "printerbug", "shadowcoerce", "dfscoerce", "webclient", "other"] },
    { key: "relay_target", label: "Relay target", type: "text", group: "Abuse" },
  ],
  priv_esc: [{ key: "cve", label: "CVE", type: "text", group: "Abuse" }],
  exploitable_via: [
    { key: "cve", label: "CVE", type: "text", group: "Abuse" },
    { key: "mitigation", label: "Mitigation", type: "text", group: "Abuse" },
  ],
  // Operator actions
  lateral_movement: [
    { key: "technique", label: "Technique", type: "enum", group: "Action", enumValues: ["psexec", "wmiexec", "winrm", "dcom", "smbexec", "ssh", "rdp", "atexec", "other"] },
    { key: "success", label: "Success", type: "bool", group: "Action" },
    { key: "detected", label: "Detected", type: "bool", group: "Action" },
  ],
  pivot_established: [
    { key: "pivot_type", label: "Pivot type", type: "enum", group: "Action", enumValues: ["socks", "port_forward", "reverse_shell", "c2_beacon", "vpn", "other"] },
    { key: "c2_framework", label: "C2 / tool", type: "text", group: "Action" },
  ],
  // Hosting & network reach
  connects_to: [
    { key: "port", label: "Port", type: "number", group: "Network" },
    { key: "protocol", label: "Protocol", type: "text", group: "Network" },
  ],
  routes_through: [{ key: "hops", label: "Hops", type: "number", group: "Network" }],
  reachable_from: [
    { key: "port", label: "Port", type: "number", group: "Network" },
    { key: "protocol", label: "Protocol", type: "text", group: "Network" },
  ],
  listens_on: [{ key: "port", label: "Port", type: "number", group: "Network" }],
};

/** Typed fields for an edge kind, in render order: kind-specific, then offensive
 * Tradecraft (for action/right edges), then the shared Evidence group. */
export const schemaForEdge = (kind: EdgeKind): FieldDef[] => [
  ...(EDGE_SCHEMA[kind] ?? []),
  ...(TRADECRAFT_EDGES.has(kind) ? TRADECRAFT : []),
  ...EDGE_EVIDENCE,
];

/** Keys the edge typed editor owns, so the free-form editor shows only extras. */
export const edgeSchemaKeys = (kind: EdgeKind): Set<string> =>
  new Set(schemaForEdge(kind).map((f) => f.key));

// ---- Findings -------------------------------------------------------------
// A structured finding list, stored as one JSON array under fields["findings"].

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type FindingStatus = "open" | "in_progress" | "fixed" | "accepted";

export interface Finding {
  title: string;
  severity: Severity;
  status: FindingStatus;
  note?: string;
}

export const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
export const FINDING_STATUSES: FindingStatus[] = ["open", "in_progress", "fixed", "accepted"];

export const SEVERITY_COLOR: Record<Severity, string> = {
  info: "#6b7280",
  low: "#30a46c",
  medium: "#f5a623",
  high: "#f76808",
  critical: "#e5484d",
};

/** Read the findings array off a node's fields, tolerating malformed data. */
export function readFindings(fields: Record<string, unknown>): Finding[] {
  const raw = fields["findings"];
  if (!Array.isArray(raw)) return [];
  return raw.filter((f): f is Finding => !!f && typeof f === "object" && typeof (f as Finding).title === "string");
}
