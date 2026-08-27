// A small, realistic demo campaign so the app opens onto a legible network with
// a live attack path (WS01 → FS01 → DC01 → CORP), and exercises the richer model:
// a hypervisor hosting real VMs, a cross-domain trust, a service with structured
// fields, host findings, and a credential linked to the principal it belongs to
// and the host it came from. All edges are canonical for their endpoint kinds.

import type { Campaign } from "@/campaign/document";
import type { CompromiseLevel, EdgeKind, GraphNode, NodeKind, Provenance } from "@/domain/types";

export function seedDemoCampaign(c: Campaign, prov: () => Provenance): void {
  const node = (
    id: string,
    kind: NodeKind,
    label: string,
    level: CompromiseLevel = "unknown",
    fields: Record<string, unknown> = {},
  ): GraphNode => ({
    id,
    kind,
    label,
    identity_keys: [{ kind: "hostname", value: label.toLowerCase(), is_primary: true }],
    compromise_level: level,
    fields,
    tags: [],
    provenance: prov(),
  });

  c.upsertNode(node("ws01", "host_windows", "WS01", "user", {
    os: "Windows 10", os_version: "22H2", network_role: "workstation", ip_addresses: ["10.0.1.20"],
  }));
  c.upsertNode(node("fs01", "host_windows", "FS01", "admin", {
    os: "Windows Server 2019", network_role: "file_server", ip_addresses: ["10.0.1.10"],
    findings: [{ title: "SMB signing disabled", severity: "medium", status: "open" }],
  }));
  c.upsertNode(node("dc01", "domain_controller", "DC01", "unknown", {
    os_version: "Windows Server 2019", domain: "CORP.LOCAL", ip_addresses: ["10.0.1.5"], functional_level: "2016",
  }));
  c.upsertNode(node("corp", "domain", "CORP.LOCAL", "unknown", { functional_level: "2016", netbios: "CORP" }));
  c.upsertNode(node("partner", "domain", "PARTNER.LOCAL", "unknown", { netbios: "PARTNER" }));
  c.upsertNode(node("ca01", "certificate_authority", "CA01", "unknown", { ca_name: "CORP-CA01" }));
  c.upsertNode(node("esx01", "hypervisor", "ESX01", "unknown", { product: "esxi", version: "7.0", ip_addresses: ["10.0.1.2"] }));
  c.upsertNode(node("vmapp", "virtual_machine", "VM-APP01", "admin", { os: "Windows Server 2022", network_role: "server" }));
  c.upsertNode(node("vmdb", "virtual_machine", "VM-DB01", "unknown", { os: "Ubuntu 22.04", network_role: "database" }));
  c.upsertNode(node("smb", "service", "SMB/445", "unknown", { port: 445, protocol: "tcp", product: "Windows SMB" }));
  c.upsertNode(node("admin", "user_account", "administrator", "unknown", { sam: "administrator", admin_count: true }));

  const edge = (s: string, kind: EdgeKind, t: string) =>
    c.addEdge({
      id: `${s}|${kind}|${t}`,
      kind,
      source: s,
      target: t,
      confidence: "confirmed",
      provenance: prov(),
    });

  edge("ws01", "admin_to", "fs01");       // principal/foothold → host
  edge("fs01", "can_ps_remote", "dc01");  // foothold host → DC
  edge("dc01", "dc_for", "corp");         // DC → domain
  edge("corp", "trusts", "partner");      // domain → domain trust
  edge("esx01", "hosts_vm", "vmapp");     // hypervisor → VM
  edge("esx01", "hosts_vm", "vmdb");      // hypervisor → VM
  edge("smb", "listens_on", "fs01");      // service → host
  edge("admin", "admin_to", "fs01");      // account is admin on the file server

  c.addCredential({
    id: "cred_seed_admin",
    username: "administrator",
    domain: "CORP",
    credential_type: "password_ntlm",
    validity: "valid",
    validity_as_of: 0,
    source: "dump",
    belongs_to: "admin",        // the principal it authenticates as
    obtained_from: "fs01",      // dumped from the file server
    tested_against: [{ host: "fs01", succeeded: true, at: 0 }],
    provenance: prov(),
  });

  c.appendEvent({ author: "op_local", at: 0, action: "seed", summary: "demo campaign seeded" });
  c.commit();
}
