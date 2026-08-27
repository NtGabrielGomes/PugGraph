// Tradecraft annotation for the attack graph: the MITRE ATT&CK technique, the
// tool an operator would reach for, and the relative detection noise of each
// edge kind. The path engine uses `EDGE_RISK` for quiet-vs-fast routing and
// `EDGE_TECHNIQUE` to turn a computed path into an ordered, ATT&CK-mapped
// playbook (and to feed the report's technique-coverage matrix). Pure data +
// lookups — no graph state — so it is trivially testable and reusable.

import type { EdgeKind } from "@/domain/types";

export interface Technique {
  /** MITRE ATT&CK technique id(s), most-specific first. */
  mitre: string[];
  /** The canonical tool/command an operator uses for this hop. */
  tool: string;
  /** One-line "what to run / what this does". */
  note: string;
}

/** Per-edge-kind ATT&CK mapping. Only edges that correspond to a real attacker
 * action are listed; structural edges are intentionally absent. */
export const EDGE_TECHNIQUE: Partial<Record<EdgeKind, Technique>> = {
  member_of: { mitre: ["T1078"], tool: "—", note: "Inherit the group's rights (nested membership)." },
  admin_to: { mitre: ["T1078.002"], tool: "psexec/wmiexec", note: "Local admin → code execution as SYSTEM." },
  has_local_admin: { mitre: ["T1078.002"], tool: "psexec/wmiexec", note: "Local admin → code execution." },
  has_session: { mitre: ["T1003.001"], tool: "mimikatz/nanodump", note: "Dump LSASS for the session's credentials." },
  dumped_from: { mitre: ["T1003"], tool: "secretsdump/mimikatz", note: "Secrets dumped from this host." },
  dc_sync: { mitre: ["T1003.006"], tool: "secretsdump -just-dc", note: "Replicate the domain's secrets (DCSync)." },
  generic_all: { mitre: ["T1098"], tool: "PowerView/targetedKerberoast", note: "Full control → reset pw / shadow creds / RBCD." },
  generic_write: { mitre: ["T1098"], tool: "PowerView", note: "GenericWrite → set SPN (roast) or msDS-KeyCredentialLink." },
  write_dacl: { mitre: ["T1222"], tool: "PowerView (Add-DomainObjectAcl)", note: "Rewrite the DACL to grant yourself control." },
  write_owner: { mitre: ["T1222"], tool: "PowerView (Set-DomainObjectOwner)", note: "Take ownership, then rewrite the DACL." },
  owns: { mitre: ["T1222"], tool: "PowerView", note: "Owner → rewrite the object's DACL." },
  all_extended_rights: { mitre: ["T1003.006", "T1098"], tool: "secretsdump / net rpc", note: "All extended rights (e.g. DCSync on a domain)." },
  force_change_password: { mitre: ["T1098"], tool: "net rpc password / Set-DomainUserPassword", note: "Reset the target's password." },
  add_member: { mitre: ["T1098"], tool: "net group / Add-DomainGroupMember", note: "Add a principal to the group." },
  add_self: { mitre: ["T1098"], tool: "Add-DomainGroupMember", note: "Add yourself to the group (AddSelf)." },
  write_gp_link: { mitre: ["T1484.001"], tool: "SharpGPOAbuse", note: "Link a malicious GPO to the OU/domain." },
  linked_gpo: { mitre: ["T1484.001"], tool: "SharpGPOAbuse", note: "Abuse the linked GPO for code exec on its scope." },
  gpo_applies_to: { mitre: ["T1484.001"], tool: "SharpGPOAbuse/pyGPOAbuse", note: "Writable GPO → scheduled task on every linked host." },
  shadow_credentials: { mitre: ["T1556.005"], tool: "pyWhisker/Whisker + gettgtpkinit", note: "Write msDS-KeyCredentialLink → PKINIT as target." },
  write_spn: { mitre: ["T1558.003"], tool: "targetedKerberoast", note: "Set an SPN → targeted Kerberoast → crack." },
  can_kerberoast: { mitre: ["T1558.003"], tool: "Rubeus kerberoast / GetUserSPNs", note: "Request the SPN ticket and crack it offline." },
  can_asrep_roast: { mitre: ["T1558.004"], tool: "Rubeus asreproast / GetNPUsers", note: "No pre-auth → request AS-REP and crack it." },
  allowed_to_act: { mitre: ["T1134.001"], tool: "rbcd.py + getST", note: "RBCD: impersonate any user to the target computer." },
  allowed_to_delegate: { mitre: ["T1558.003"], tool: "getST (S4U)", note: "Constrained delegation → impersonate to the SPN." },
  unconstrained_delegation: { mitre: ["T1558"], tool: "Rubeus monitor + PetitPotam", note: "Coerce a DC → capture its TGT off this host." },
  read_laps_password: { mitre: ["T1555"], tool: "LAPSToolkit / pyLAPS", note: "Read the LAPS local-admin password." },
  read_gmsa_password: { mitre: ["T1555"], tool: "gMSADumper", note: "Read the gMSA managed password." },
  coerce: { mitre: ["T1187"], tool: "PetitPotam/Coercer", note: "Coerce the target to authenticate to you." },
  relay_to: { mitre: ["T1557.001"], tool: "ntlmrelayx", note: "Relay the coerced auth (signing/EPA off)." },
  manage_ca: { mitre: ["T1649"], tool: "Certipy ca / ESC7", note: "ManageCA → issue/approve a malicious cert." },
  enroll: { mitre: ["T1649"], tool: "Certipy req", note: "Enroll in the vulnerable template (ESC1/2/3…)." },
  enroll_on_behalf_of: { mitre: ["T1649"], tool: "Certipy req -on-behalf-of", note: "Enrollment agent → cert for another principal." },
  authenticates_as: { mitre: ["T1649"], tool: "Certipy auth / gettgtpkinit", note: "PKINIT with the cert → TGT as the target." },
  can_rdp: { mitre: ["T1021.001"], tool: "xfreerdp/mstsc", note: "RDP into the host." },
  can_ps_remote: { mitre: ["T1021.006"], tool: "evil-winrm", note: "WinRM/PowerShell Remoting onto the host." },
  execute_dcom: { mitre: ["T1021.003"], tool: "dcomexec", note: "DCOM → code execution on the host." },
  can_ssh: { mitre: ["T1021.004"], tool: "ssh", note: "SSH into the host." },
  sql_admin: { mitre: ["T1190"], tool: "mssqlclient / PowerUpSQL", note: "sysadmin → xp_cmdshell → OS code exec." },
  sql_link: { mitre: ["T1190"], tool: "PowerUpSQL (Get-SQLServerLinkCrawl)", note: "Hop across the linked-server trust." },
  trusts: { mitre: ["T1482"], tool: "mimikatz /sids: / raiseChild", note: "Cross-domain via the trust (SID history / trust key)." },
  credential_valid_for: { mitre: ["T1078"], tool: "nxc/CrackMapExec", note: "Reuse the valid credential here." },
  lateral_movement: { mitre: ["T1021"], tool: "—", note: "Lateral movement performed along this link." },
  exploitable_via: { mitre: ["T1190"], tool: "—", note: "Exploit the linked finding / technique." },
};

/** Relative detection noise of traversing each edge kind, for quiet-vs-fast
 * routing. 0 = silent (an ACL right exists, no action), up to ~3 = loud (touches
 * LSASS, mass DCSync). Unlisted kinds default to 1 (moderate). */
export const EDGE_RISK: Partial<Record<EdgeKind, number>> = {
  // Silent: rights/relationships that need no loud action to traverse.
  member_of: 0, member_of_domain: 0, owns: 0.3, write_dacl: 0.3, generic_all: 0.3,
  generic_write: 0.3, write_owner: 0.3, all_extended_rights: 0.4, add_member: 0.4, add_self: 0.4,
  shadow_credentials: 0.5, allowed_to_act: 0.5, allowed_to_delegate: 0.6, read_laps_password: 0.4,
  read_gmsa_password: 0.4, enroll: 0.6, enroll_on_behalf_of: 0.6, authenticates_as: 0.5, write_spn: 0.7,
  can_kerberoast: 0.8, can_asrep_roast: 0.7, write_gp_link: 0.8, gpo_applies_to: 1,
  // Moderate: remote exec leaves logs.
  can_rdp: 1.2, can_ps_remote: 1, execute_dcom: 1.2, can_ssh: 0.8, sql_admin: 1, sql_link: 1,
  force_change_password: 1.4, admin_to: 1, has_local_admin: 1,
  // Loud: touches LSASS, coercion/relay, replication.
  has_session: 1.6, dumped_from: 1.8, dc_sync: 2, coerce: 1.8, relay_to: 1.6,
  unconstrained_delegation: 1.5, manage_ca: 1.2, trusts: 1,
};

export const techniqueFor = (k: EdgeKind): Technique | undefined => EDGE_TECHNIQUE[k];
export const edgeRisk = (k: EdgeKind): number => EDGE_RISK[k] ?? 1;
