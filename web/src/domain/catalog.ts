import type { EdgeKind, NodeKind } from "@/domain/types";

export interface KindInfo<K> {
  kind: K;
  label: string;
  desc: string;
}
export interface KindGroup<K> {
  group: string;
  kinds: KindInfo<K>[];
}

export const NODE_GROUPS: KindGroup<NodeKind>[] = [
  {
    group: "Hosts",
    kinds: [
      { kind: "host_windows", label: "Windows host", desc: "Windows workstation or server." },
      { kind: "host_linux", label: "Linux host", desc: "Linux / Unix host." },
      { kind: "host_macos", label: "macOS host", desc: "macOS host." },
      { kind: "network_device", label: "Network device", desc: "Router, switch, firewall, or other appliance." },
    ],
  },
  {
    group: "Virtualization",
    kinds: [
      { kind: "hypervisor", label: "Hypervisor", desc: "Virtualization host running VMs." },
      { kind: "virtual_machine", label: "Virtual machine", desc: "Guest VM running on a hypervisor." },
      { kind: "container", label: "Container", desc: "Container instance." },
      { kind: "container_host", label: "Container host", desc: "Host running a container runtime / orchestrator node." },
    ],
  },
  {
    group: "Active Directory",
    kinds: [
      { kind: "domain", label: "Domain", desc: "Active Directory domain." },
      { kind: "forest", label: "Forest", desc: "AD forest." },
      { kind: "organizational_unit", label: "Organizational unit", desc: "AD OU containing objects, with linked GPOs." },
      { kind: "gpo", label: "GPO", desc: "Group Policy Object applied to OUs / domains." },
      { kind: "domain_controller", label: "Domain controller", desc: "Authenticates the domain." },
      { kind: "certificate_authority", label: "Certificate authority", desc: "AD Certificate Services CA (ADCS)." },
      { kind: "cert_template", label: "Cert template", desc: "ADCS certificate template." },
    ],
  },
  {
    group: "Network",
    kinds: [
      { kind: "network_segment", label: "Network segment", desc: "Logical network zone / segment." },
      { kind: "subnet", label: "Subnet", desc: "An IP subnet." },
      { kind: "vlan", label: "VLAN", desc: "A VLAN." },
    ],
  },
  {
    group: "Services & data",
    kinds: [
      { kind: "service", label: "Service", desc: "A listening service (port / protocol / product / version / CVE)." },
      { kind: "share", label: "Share", desc: "SMB / NFS file share." },
      { kind: "web_application", label: "Web application", desc: "A web app / API / virtual host served over HTTP(S)." },
    ],
  },
  {
    group: "Identity",
    kinds: [
      { kind: "user_account", label: "User account", desc: "AD or local user account." },
      { kind: "computer_account", label: "Computer account", desc: "AD computer account." },
      { kind: "service_account", label: "Service account", desc: "Service account (has an SPN)." },
      { kind: "group", label: "Group", desc: "AD or local security group." },
    ],
  },
  {
    group: "Cloud",
    kinds: [
      { kind: "cloud_resource", label: "Cloud resource", desc: "Cloud resource (VM, storage, function)." },
      { kind: "cloud_identity", label: "Cloud identity", desc: "Cloud principal (Entra ID / IAM)." },
    ],
  },
  {
    group: "Findings & loot",
    kinds: [
      { kind: "finding", label: "Finding", desc: "A vulnerability / finding affecting one or more assets (CVE, plugin, ESC)." },
      { kind: "loot", label: "Loot", desc: "A captured artifact (NTDS.dit, KeePass, config, screenshot) with chain-of-custody." },
    ],
  },
  { group: "Other", kinds: [{ kind: "custom", label: "Custom", desc: "Anything the taxonomy doesn't cover." }] },
];

export const EDGE_GROUPS: KindGroup<EdgeKind>[] = [
  {
    group: "Identity & privilege",
    kinds: [
      { kind: "member_of", label: "member_of", desc: "Source is a member of the target group." },
      { kind: "admin_to", label: "admin_to", desc: "Source has administrative rights on the target host." },
      { kind: "has_local_admin", label: "has_local_admin", desc: "Source is a local administrator of the target." },
      { kind: "owns", label: "owns", desc: "Source owns the target AD object (can rewrite its DACL)." },
      { kind: "write_dacl", label: "write_dacl", desc: "Source can write the target's DACL." },
      { kind: "generic_all", label: "generic_all", desc: "Source has GenericAll (full control) over the target." },
      { kind: "force_change_password", label: "force_change_password", desc: "Source can reset the target account's password." },
      { kind: "add_member", label: "add_member", desc: "Source can add members to the target group." },
      { kind: "priv_esc", label: "priv_esc", desc: "A privilege-escalation path from source to target." },
      { kind: "shadow_credentials", label: "shadow_credentials", desc: "Source can write msDS-KeyCredentialLink -> PKINIT auth as the target (Shadow Credentials)." },
      { kind: "write_spn", label: "write_spn", desc: "Source can set the target's SPN -> targeted Kerberoast." },
      { kind: "allowed_to_act", label: "allowed_to_act", desc: "Resource-based constrained delegation (RBCD) onto the target computer." },
      { kind: "allowed_to_delegate", label: "allowed_to_delegate", desc: "Constrained delegation: impersonate to a service on the target." },
      { kind: "read_gmsa_password", label: "read_gmsa_password", desc: "Source can read the target gMSA's managed password." },
      { kind: "read_laps_password", label: "read_laps_password", desc: "Source can read the target's LAPS local-admin password." },
      { kind: "generic_write", label: "generic_write", desc: "Source has GenericWrite over the target (set SPN / shadow creds / etc.)." },
      { kind: "write_owner", label: "write_owner", desc: "Source can set the target's owner, then rewrite its DACL." },
      { kind: "all_extended_rights", label: "all_extended_rights", desc: "Source has all extended rights (e.g. DCSync on a domain, force-reset)." },
      { kind: "write_gp_link", label: "write_gp_link", desc: "Source can link a GPO to the target OU / domain (gPLink)." },
      { kind: "add_self", label: "add_self", desc: "Source can add itself to the target group (AddSelf)." },
      { kind: "unconstrained_delegation", label: "unconstrained_delegation", desc: "Source host has unconstrained delegation → capture a DC TGT → domain." },
      { kind: "can_kerberoast", label: "can_kerberoast", desc: "Source can Kerberoast the target service principal (request + crack)." },
      { kind: "can_asrep_roast", label: "can_asrep_roast", desc: "Source can AS-REP roast the target (no pre-auth) and crack offline." },
    ],
  },
  {
    group: "ADCS (certificate services)",
    kinds: [
      { kind: "enroll", label: "enroll", desc: "Source can enroll in the target certificate template (ESC1/2/3…)." },
      { kind: "enroll_on_behalf_of", label: "enroll_on_behalf_of", desc: "Enrollment agent: enroll on behalf of another principal (ESC3)." },
      { kind: "published_to", label: "published_to", desc: "Template (source) is published to the target CA (structural)." },
      { kind: "authenticates_as", label: "authenticates_as", desc: "A cert from the source template/CA authenticates as the target (PKINIT)." },
    ],
  },
  {
    group: "AD structure & trust",
    kinds: [
      { kind: "member_of_domain", label: "member_of_domain", desc: "Source belongs to the target domain." },
      { kind: "contains_ou", label: "contains_ou", desc: "Target is contained under the source OU (structural)." },
      { kind: "linked_gpo", label: "linked_gpo", desc: "GPO (source) is linked to the target OU / domain." },
      { kind: "dc_for", label: "dc_for", desc: "Source is a domain controller for the target domain." },
      { kind: "trusts", label: "trusts", desc: "Source domain trusts the target (set direction / transitive)." },
      { kind: "dc_sync", label: "dc_sync", desc: "Source can DCSync (GetChanges + GetChangesAll) secrets from the domain." },
      { kind: "manage_ca", label: "manage_ca", desc: "Source has ManageCA over the certificate authority (ADCS ESC7)." },
      { kind: "gpo_applies_to", label: "gpo_applies_to", desc: "GPO (source) applies to the target host/principal (expanded scope → code exec)." },
    ],
  },
  {
    group: "Sessions & credentials",
    kinds: [
      { kind: "has_session", label: "has_session", desc: "An account has an active session on the host." },
      { kind: "credential_valid_for", label: "credential_valid_for", desc: "A credential authenticates to the target host/service/account." },
      { kind: "dumped_from", label: "dumped_from", desc: "A credential was dumped from the source host." },
    ],
  },
  {
    group: "Remote execution",
    kinds: [
      { kind: "can_rdp", label: "can_rdp", desc: "Source can RDP into the target." },
      { kind: "can_ps_remote", label: "can_ps_remote", desc: "Source can use PowerShell Remoting (WinRM) on the target." },
      { kind: "execute_dcom", label: "execute_dcom", desc: "Source can execute via DCOM on the target." },
      { kind: "can_ssh", label: "can_ssh", desc: "Source can SSH into the target." },
      { kind: "sql_admin", label: "sql_admin", desc: "Source is a sysadmin on the target MSSQL host/service." },
      { kind: "coerce", label: "coerce", desc: "Source can coerce the target to authenticate (PetitPotam/PrinterBug) -> relay." },
      { kind: "sql_link", label: "sql_link", desc: "Linked-server hop from one MSSQL instance to another (EXECUTE AS / RPC)." },
      { kind: "relay_to", label: "relay_to", desc: "Coerced auth can be relayed to the target (SMB/LDAP/ADCS-HTTP) — signing/EPA off." },
    ],
  },
  {
    group: "Hosting & network",
    kinds: [
      { kind: "hosts_vm", label: "hosts_vm", desc: "Hypervisor (source) hosts the target VM." },
      { kind: "vm_hosted_on", label: "vm_hosted_on", desc: "VM (source) is hosted on the target hypervisor." },
      { kind: "runs_container", label: "runs_container", desc: "Host (source) runs the target container." },
      { kind: "listens_on", label: "listens_on", desc: "Service (source) listens on the target host." },
      { kind: "hosted_on", label: "hosted_on", desc: "Web application (source) is hosted on the target service / host." },
      { kind: "connects_to", label: "connects_to", desc: "Source has a network connection to the target." },
      { kind: "routes_through", label: "routes_through", desc: "Traffic from source routes through the target." },
      { kind: "same_segment", label: "same_segment", desc: "Both ends share a segment (structural, not traversable)." },
      { kind: "parent_segment", label: "parent_segment", desc: "Target is the parent segment of the source (structural)." },
      { kind: "reachable_from", label: "reachable_from", desc: "Target is reachable from the source." },
    ],
  },
  {
    group: "Operator actions",
    kinds: [
      { kind: "pivot_established", label: "pivot_established", desc: "A pivot has been established along this link." },
      { kind: "lateral_movement", label: "lateral_movement", desc: "Lateral movement was performed along this link." },
      { kind: "exploitable_via", label: "exploitable_via", desc: "Target is exploitable via the linked finding / technique." },
    ],
  },
  {
    group: "Findings & loot",
    kinds: [
      { kind: "affects", label: "affects", desc: "Finding (source) affects the target asset(s)." },
      { kind: "looted_from", label: "looted_from", desc: "Loot artifact (source) was captured from the target host/principal." },
      { kind: "yields_credential", label: "yields_credential", desc: "Loot (source) yields a credential for the target principal." },
      { kind: "evidence_for", label: "evidence_for", desc: "Loot/artifact (source) is evidence for the target node/finding." },
    ],
  },
  { group: "Other", kinds: [{ kind: "custom", label: "custom", desc: "Anything the taxonomy doesn't cover." }] },
];

const NODE_INFO = new Map<NodeKind, KindInfo<NodeKind>>(
  NODE_GROUPS.flatMap((g) => g.kinds).map((k) => [k.kind, k]),
);
const EDGE_INFO = new Map<EdgeKind, KindInfo<EdgeKind>>(
  EDGE_GROUPS.flatMap((g) => g.kinds).map((k) => [k.kind, k]),
);

export const nodeKindLabel = (k: NodeKind): string => NODE_INFO.get(k)?.label ?? k;
export const nodeKindDesc = (k: NodeKind): string => NODE_INFO.get(k)?.desc ?? "";
export const edgeKindLabel = (k: EdgeKind): string => EDGE_INFO.get(k)?.label ?? k;
export const edgeKindDesc = (k: EdgeKind): string => EDGE_INFO.get(k)?.desc ?? "";

export const IDENTITY_KINDS: { kind: string; label: string }[] = [
  { kind: "ip_address", label: "IP address" },
  { kind: "fqdn", label: "FQDN" },
  { kind: "hostname", label: "Hostname" },
  { kind: "mac_address", label: "MAC address" },
  { kind: "ad_sid", label: "AD SID" },
  { kind: "ad_object_guid", label: "AD object GUID" },
  { kind: "domain_name", label: "Domain name" },
  { kind: "account_upn", label: "Account UPN" },
  { kind: "account_sam", label: "Account SAM" },
  { kind: "azure_object_id", label: "Entra object id" },
  { kind: "azure_app_id", label: "Entra app id" },
  { kind: "spn", label: "SPN" },
  { kind: "cert_thumbprint", label: "Certificate thumbprint" },
  { kind: "smtp_address", label: "Email (SMTP)" },
  { kind: "url", label: "URL" },
  { kind: "file_sha256", label: "File SHA-256" },
  { kind: "custom", label: "Custom" },
];

const FIELD_SUGGESTIONS: Partial<Record<NodeKind, string[]>> = {
  host_windows: ["os_version", "ip_addresses", "mac", "domain", "av_edr", "patch_level", "last_logon"],
  host_linux: ["os_version", "ip_addresses", "mac", "kernel", "ssh_version", "sudo_rights"],
  host_macos: ["os_version", "ip_addresses", "mac"],
  network_device: ["model", "os_version", "ip_addresses", "mgmt_protocol"],
  domain_controller: ["os_version", "ip_addresses", "domain", "functional_level"],
  domain: ["functional_level", "sid", "netbios", "ms_ds_machineaccountquota"],
  forest: ["functional_level", "root_domain"],
  service: ["port", "protocol", "product", "version", "cve", "banner"],
  share: ["unc_path", "permissions", "readable", "writable"],
  user_account: ["upn", "sam", "sid", "enabled", "pwd_last_set", "description", "admin_count"],
  service_account: ["upn", "sam", "sid", "spn", "description"],
  computer_account: ["sam", "sid", "os_version", "delegation"],
  group: ["sid", "description", "member_count"],
  certificate_authority: ["dns", "ca_name", "subject"],
  cert_template: ["template_name", "eku", "enrollee_supplies_subject", "client_auth"],
  network_segment: ["cidr", "gateway", "description"],
  subnet: ["cidr", "gateway"],
  vlan: ["vlan_id", "cidr"],
};

const DEFAULT_FIELDS = ["ip_addresses", "notes", "owner"];

export const fieldSuggestions = (kind: NodeKind): string[] => FIELD_SUGGESTIONS[kind] ?? DEFAULT_FIELDS;

export const COMMON_TAGS = ["crown-jewel", "high-value", "foothold", "pivot", "todo", "blocker", "verified", "owned"];

export type NodeClass =
  | "host" | "ad_structure" | "principal" | "group" | "network"
  | "service" | "share" | "cloud" | "finding" | "artifact" | "custom";

export const NODE_CLASS: Record<NodeKind, NodeClass> = {
  host_windows: "host", host_linux: "host", host_macos: "host", network_device: "host",
  hypervisor: "host", virtual_machine: "host", container: "host", container_host: "host",
  domain_controller: "host",
  domain: "ad_structure", forest: "ad_structure", organizational_unit: "ad_structure",
  gpo: "ad_structure", certificate_authority: "ad_structure", cert_template: "ad_structure",
  network_segment: "network", subnet: "network", vlan: "network",
  service: "service", share: "share", web_application: "service",
  user_account: "principal", computer_account: "principal", service_account: "principal",
  group: "group",
  cloud_resource: "cloud", cloud_identity: "cloud",
  finding: "finding", loot: "artifact",
  custom: "custom",
};

export interface EdgeRule {
  src_classes: NodeClass[];
  dst_classes: NodeClass[];
  src_kinds: NodeKind[];
  dst_kinds: NodeKind[];
}

const cls = (src_classes: NodeClass[], dst_classes: NodeClass[]): EdgeRule => ({
  src_classes, dst_classes, src_kinds: [], dst_kinds: [],
});
const kinds = (src_kinds: NodeKind[], dst_kinds: NodeKind[]): EdgeRule => ({
  src_classes: [], dst_classes: [], src_kinds, dst_kinds,
});

export const EDGE_RULES: Record<EdgeKind, EdgeRule> = {
  member_of: cls(["principal", "group"], ["group"]),
  admin_to: cls(["principal", "group", "host"], ["host"]),
  has_local_admin: cls(["principal", "group", "host"], ["host"]),
  owns: cls(["principal", "group"], ["principal", "group", "ad_structure"]),
  write_dacl: cls(["principal", "group"], ["principal", "group", "ad_structure"]),
  generic_all: cls(["principal", "group"], ["principal", "group", "ad_structure", "host"]),
  force_change_password: cls(["principal", "group"], ["principal"]),
  add_member: cls(["principal", "group"], ["group"]),
  priv_esc: cls(["principal", "group", "host"], ["principal", "group", "host", "ad_structure"]),
  shadow_credentials: cls(["principal", "group"], ["principal", "host"]),
  write_spn: cls(["principal", "group"], ["principal"]),
  allowed_to_act: cls(["principal", "group", "host"], ["host"]),
  allowed_to_delegate: cls(["principal", "host"], ["host", "service"]),
  read_gmsa_password: cls(["principal", "group"], ["principal"]),
  read_laps_password: cls(["principal", "group"], ["host"]),

  member_of_domain: { src_classes: ["host", "principal", "group"], dst_classes: [], src_kinds: [], dst_kinds: ["domain"] },
  contains_ou: kinds(["organizational_unit", "domain"], ["organizational_unit"]),
  linked_gpo: kinds(["gpo"], ["organizational_unit", "domain"]),
  dc_for: kinds(["domain_controller"], ["domain"]),
  trusts: kinds(["domain", "forest"], ["domain", "forest"]),
  dc_sync: { src_classes: ["principal", "group"], dst_classes: [], src_kinds: [], dst_kinds: ["domain"] },
  manage_ca: { src_classes: ["principal", "group"], dst_classes: [], src_kinds: [], dst_kinds: ["certificate_authority"] },

  has_session: cls(["principal"], ["host"]),
  credential_valid_for: cls(["principal", "host"], ["host", "service", "principal", "cloud"]),
  dumped_from: cls(["host", "principal"], ["host", "principal"]),

  can_rdp: cls(["principal", "group", "host"], ["host"]),
  can_ps_remote: cls(["principal", "group", "host"], ["host"]),
  execute_dcom: cls(["principal", "group", "host"], ["host"]),
  can_ssh: cls(["principal", "group", "host"], ["host"]),
  sql_admin: cls(["principal", "group", "host"], ["host", "service"]),
  coerce: cls(["host", "principal"], ["host"]),

  hosts_vm: kinds(["hypervisor"], ["virtual_machine"]),
  vm_hosted_on: kinds(["virtual_machine"], ["hypervisor"]),
  runs_container: { src_classes: ["host"], dst_classes: [], src_kinds: [], dst_kinds: ["container"] },
  listens_on: cls(["service"], ["host"]),
  connects_to: cls(["host", "network", "cloud"], ["host", "network", "service", "cloud"]),
  routes_through: cls(["host", "network"], ["host", "network"]),
  same_segment: cls(["host", "network"], ["host", "network"]),
  parent_segment: cls(["host", "network"], ["network"]),
  reachable_from: cls(["host", "network"], ["host", "network", "service", "cloud"]),

  pivot_established: cls(["host", "network"], ["host", "network"]),
  lateral_movement: cls(["host", "principal"], ["host"]),
  exploitable_via: cls(
    ["host", "service", "principal", "group", "ad_structure", "cloud"],
    ["host", "service", "principal", "group", "ad_structure", "cloud"],
  ),

  generic_write: cls(["principal", "group"], ["principal", "group", "ad_structure", "host"]),
  write_owner: cls(["principal", "group"], ["principal", "group", "ad_structure"]),
  all_extended_rights: cls(["principal", "group"], ["principal", "group", "ad_structure"]),
  write_gp_link: { src_classes: ["principal", "group"], dst_classes: [], src_kinds: [], dst_kinds: ["organizational_unit", "domain"] },
  add_self: cls(["principal", "group"], ["group"]),
  unconstrained_delegation: { src_classes: ["host"], dst_classes: [], src_kinds: ["computer_account"], dst_kinds: ["domain"] },
  can_kerberoast: cls(["principal", "group"], ["principal"]),
  can_asrep_roast: cls(["principal", "group"], ["principal"]),
  enroll: { src_classes: ["principal", "group"], dst_classes: [], src_kinds: [], dst_kinds: ["cert_template"] },
  enroll_on_behalf_of: { src_classes: ["principal", "group"], dst_classes: [], src_kinds: [], dst_kinds: ["cert_template"] },
  published_to: kinds(["cert_template"], ["certificate_authority"]),
  authenticates_as: { src_classes: [], dst_classes: ["principal"], src_kinds: ["cert_template", "certificate_authority"], dst_kinds: ["domain"] },
  gpo_applies_to: { src_classes: [], dst_classes: ["host", "principal", "group"], src_kinds: ["gpo"], dst_kinds: [] },
  sql_link: cls(["service"], ["service"]),
  relay_to: { src_classes: ["host", "service", "principal"], dst_classes: ["host", "service"], src_kinds: [], dst_kinds: ["certificate_authority"] },
  hosted_on: { src_classes: [], dst_classes: ["service", "host"], src_kinds: ["web_application"], dst_kinds: [] },
  affects: { src_classes: [], dst_classes: ["host", "service", "principal", "group", "ad_structure", "cloud"], src_kinds: ["finding"], dst_kinds: [] },
  looted_from: { src_classes: [], dst_classes: ["host", "principal"], src_kinds: ["loot"], dst_kinds: [] },
  yields_credential: { src_classes: [], dst_classes: ["principal"], src_kinds: ["loot"], dst_kinds: [] },
  evidence_for: { src_classes: [], dst_classes: ["host", "service", "principal", "group", "ad_structure", "cloud"], src_kinds: ["loot"], dst_kinds: [] },

  custom: cls([], []),
};

export const ALL_NODE_KINDS: NodeKind[] = [
  "host_windows", "host_linux", "host_macos", "network_device", "hypervisor", "virtual_machine",
  "container", "container_host", "domain", "forest", "organizational_unit", "gpo",
  "domain_controller", "certificate_authority", "cert_template", "network_segment", "subnet",
  "vlan", "service", "share", "web_application", "user_account", "computer_account", "service_account", "group",
  "cloud_resource", "cloud_identity", "finding", "loot", "custom",
];
export const ALL_EDGE_KINDS: EdgeKind[] = [
  "member_of", "admin_to", "has_local_admin", "owns", "write_dacl", "generic_all",
  "force_change_password", "add_member", "priv_esc", "shadow_credentials", "write_spn",
  "allowed_to_act", "allowed_to_delegate", "read_gmsa_password", "read_laps_password",
  "member_of_domain", "contains_ou", "linked_gpo", "dc_for", "trusts", "dc_sync", "manage_ca",
  "has_session", "credential_valid_for", "dumped_from", "can_rdp", "can_ps_remote",
  "execute_dcom", "can_ssh", "sql_admin", "coerce", "hosts_vm", "vm_hosted_on",
  "runs_container", "listens_on", "connects_to", "routes_through", "same_segment",
  "parent_segment", "reachable_from", "pivot_established", "lateral_movement", "exploitable_via",
  "generic_write", "write_owner", "all_extended_rights", "write_gp_link", "add_self",
  "unconstrained_delegation", "can_kerberoast", "can_asrep_roast",
  "enroll", "enroll_on_behalf_of", "published_to", "authenticates_as",
  "gpo_applies_to", "sql_link", "relay_to", "hosted_on",
  "affects", "looted_from", "yields_credential", "evidence_for",
  "custom",
];

export function edgePermits(kind: EdgeKind, src: NodeKind, dst: NodeKind): boolean {
  if (kind === "custom")
      return true;

  const r = EDGE_RULES[kind];
  const srcOk = r.src_classes.includes(NODE_CLASS[src]) || r.src_kinds.includes(src);
  const dstOk = r.dst_classes.includes(NODE_CLASS[dst]) || r.dst_kinds.includes(dst);
  return srcOk && dstOk;
}

export const edgeKindsFor = (src: NodeKind, dst: NodeKind): EdgeKind[] =>
  ALL_EDGE_KINDS.filter((k) => edgePermits(k, src, dst));
