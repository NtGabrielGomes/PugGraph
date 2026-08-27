// Pre-built queries (BloodHound/Pughound-style): a declarative catalog over the
// campaign graph. Each query resolves to a node/edge scope — the map dims
// everything outside it — and carries a description plus exploitation commands
// from the abuse catalog (abuseCommands.ts), with template variables resolved
// against the campaign (domain, DC, first matched target).

import { ABUSE_COMMANDS, type AbuseCommand } from "@/data/abuseCommands";
import type { GraphEdge, GraphNode } from "@/domain/types";

export interface QueryScope {
  nodeIds: string[];
  edgeIds: string[];
}

/** A focus scope: the given nodes plus every edge touching any of them, with
 * the other endpoints pulled in — so focusing a host shows its neighborhood,
 * and focusing a navigator group shows the category and its relationships. */
export function incidentScope(nodeIds: Iterable<string>, edges: GraphEdge[]): QueryScope {
  const seeds = new Set(nodeIds);
  const ns = new Set(seeds);
  const es: string[] = [];
  for (const e of edges) {
    // Incident to a SEED only — membership of the pulled-in endpoint must not
    // expand the scope transitively.
    if (seeds.has(e.source) || seeds.has(e.target)) {
      es.push(e.id);
      ns.add(e.source);
      ns.add(e.target);
    }
  }
  return { nodeIds: [...ns], edgeIds: es };
}

export interface PrebuiltQuery {
  name: string;
  /** One-liner shown on the detail card. */
  description: string;
  /** Keys into ABUSE_COMMANDS, in display order. */
  commandKeys: string[];
  /** Resolve the query over the current graph. */
  match: (nodes: GraphNode[], edges: GraphEdge[]) => QueryScope;
}

export interface PrebuiltQueryGroup {
  group: string;
  items: PrebuiltQuery[];
}

const scope = (nodes: Iterable<string>, edges: Iterable<string> = []): QueryScope => ({
  nodeIds: [...nodes],
  edgeIds: [...edges],
});

/** Nodes carrying a true boolean field. */
const withField =
  (key: string): PrebuiltQuery["match"] =>
  (nodes) =>
    scope(nodes.filter((n) => n.fields[key] === true).map((n) => n.id));

/** Edges of the given kinds, plus both endpoints. */
const withEdges =
  (...kinds: GraphEdge["kind"][]): PrebuiltQuery["match"] =>
  (_nodes, edges) => {
    const hit = edges.filter((e) => kinds.includes(e.kind));
    const ns = new Set<string>();
    for (const e of hit) {
      ns.add(e.source);
      ns.add(e.target);
    }
    return scope(ns, hit.map((e) => e.id));
  };

export const PREBUILT_QUERIES: PrebuiltQueryGroup[] = [
  {
    group: "Domain dominance",
    items: [
      {
        name: "High-value targets",
        description: "Tier-zero / crown-jewel assets — domain controllers, admin accounts, anything flagged high-value.",
        commandKeys: [],
        match: (nodes) =>
          scope(
            nodes
              .filter(
                (n) =>
                  n.fields["is_tier_zero"] === true ||
                  n.kind === "domain_controller" ||
                  n.tags.includes("crown-jewel"),
              )
              .map((n) => n.id),
          ),
      },
      {
        name: "Privileged group members",
        description: "Members of groups holding adminCount/tier-zero — blast radius of the protected groups.",
        commandKeys: ["MemberOf", "AddMember"],
        match: (nodes, edges) => {
          const priv = new Set(
            nodes
              .filter((n) => n.kind === "group" && (n.fields["admin_count"] === true || n.fields["is_tier_zero"] === true))
              .map((n) => n.id),
          );
          const hit = edges.filter((e) => e.kind === "member_of" && priv.has(e.target));
          const ns = new Set(priv);
          for (const e of hit) ns.add(e.source);
          return scope(ns, hit.map((e) => e.id));
        },
      },
      {
        name: "DCSync rights",
        description: "Principals holding replication rights on the domain — full credential theft without touching a DC.",
        commandKeys: ["GetChangesAll", "GetChanges"],
        match: withEdges("dc_sync"),
      },
      {
        name: "SID History",
        description: "Accounts carrying a SID history — legacy migration artifact that smuggles old privileges across domains.",
        commandKeys: ["HasSIDHistory"],
        match: (nodes) => scope(nodes.filter((n) => Array.isArray(n.fields["sid_history"])).map((n) => n.id)),
      },
    ],
  },
  {
    group: "Kerberos",
    items: [
      {
        name: "Kerberoastable users",
        description: "Accounts with an SPN — request the service ticket and crack the password offline.",
        commandKeys: ["HasSPN"],
        match: withField("kerberoastable"),
      },
      {
        name: "AS-REP roastable users",
        description: "Accounts with DONT_REQ_PREAUTH — grab the AS-REP with no credentials and crack it offline.",
        commandKeys: ["ASREPRoast"],
        match: withField("asrep_roastable"),
      },
      {
        name: "Constrained delegation",
        description: "Accounts trusted for constrained delegation (S4U2Proxy) — impersonate users to the allowed services.",
        commandKeys: ["AllowedToDelegate", "TrustedToAuth"],
        match: (nodes, edges) => {
          const a = withEdges("allowed_to_delegate")(nodes, edges);
          const b = withField("protocol_transition")(nodes, edges);
          const c = scope(nodes.filter((n) => n.fields["delegation"] === "constrained").map((n) => n.id));
          return scope(
            new Set([...a.nodeIds, ...b.nodeIds, ...c.nodeIds]),
            new Set(a.edgeIds),
          );
        },
      },
      {
        name: "Resource-based constrained (RBCD)",
        description: "Computers allowing a principal to act on their behalf — configure RBCD and take the host.",
        commandKeys: ["AllowedToAct"],
        match: withEdges("allowed_to_act"),
      },
    ],
  },
  {
    group: "ACL abuse",
    items: [
      {
        name: "GenericAll (full control)",
        description: "Full control over the target — reset passwords, write keys, take the object.",
        commandKeys: ["GenericAll"],
        match: withEdges("generic_all"),
      },
      {
        name: "WriteDacl / WriteOwner / GenericWrite",
        description: "Write the DACL, take ownership, or write attributes — each escalates to full control.",
        commandKeys: ["WriteDacl", "WriteOwner", "GenericWrite"],
        match: withEdges("write_dacl", "write_owner", "generic_write"),
      },
      {
        name: "ForceChangePassword",
        description: "Reset the target account's password without knowing the current one.",
        commandKeys: ["ForceChangePassword"],
        match: withEdges("force_change_password"),
      },
      {
        name: "Owns",
        description: "Ownership of the object — grant yourself full control via the DACL.",
        commandKeys: ["Owns"],
        match: withEdges("owns"),
      },
      {
        name: "GMSA password readers",
        description: "Principals allowed to read the gMSA password — a service account credential for free.",
        commandKeys: ["ReadGMSAPassword"],
        match: withEdges("read_gmsa_password"),
      },
      {
        name: "LAPS password readers",
        description: "Principals allowed to read LAPS passwords — local admin on every managed host.",
        commandKeys: ["ReadLAPSPassword"],
        match: withEdges("read_laps_password"),
      },
      {
        name: "Shadow credentials",
        description: "Write msDS-KeyCredentialLink on the target and authenticate via PKINIT — no password reset needed.",
        commandKeys: ["AddKeyCredentialLink"],
        match: withEdges("shadow_credentials"),
      },
    ],
  },
  {
    group: "Legacy & misconfig",
    items: [
      {
        name: "MS17-010 candidates",
        description: "Hosts likely unpatched against EternalBlue (SMBv1 RCE).",
        commandKeys: [],
        match: withField("ms17_010"),
      },
      {
        name: "Pre2k candidates",
        description: "Pre-Windows-2000 compatible computer accounts — password defaults to the machine name.",
        commandKeys: [],
        match: withField("pre2k"),
      },
    ],
  },
  {
    group: "AD CS",
    items: [
      {
        name: "Enrollment rights",
        description: "Principals with Enroll/AutoEnroll on a certificate template — the ESC1-style foothold.",
        commandKeys: ["Enroll", "AutoEnroll"],
        match: withEdges("enroll", "enroll_on_behalf_of"),
      },
      {
        name: "ManageCA",
        description: "ManageCA over the CA — approve your own pending requests (ESC7).",
        commandKeys: [],
        match: withEdges("manage_ca"),
      },
    ],
  },
  {
    group: "Infrastructure",
    items: [
      {
        name: "Domain controllers",
        description: "Every domain controller in the campaign.",
        commandKeys: [],
        match: (nodes) => scope(nodes.filter((n) => n.kind === "domain_controller").map((n) => n.id)),
      },
      {
        name: "GPOs and links",
        description: "Group Policy Objects and where they apply — edit a linked GPO to run code on its targets.",
        commandKeys: ["GPLink"],
        match: (nodes, edges) => {
          const a = withEdges("gpo_applies_to")(nodes, edges);
          const gpos = nodes.filter((n) => n.kind === "gpo").map((n) => n.id);
          return scope(new Set([...a.nodeIds, ...gpos]), new Set(a.edgeIds));
        },
      },
      {
        name: "Domain trusts",
        description: "Trust relationships to other domains/forests — cross-domain attack surface.",
        commandKeys: [],
        match: withEdges("trusts"),
      },
    ],
  },
];

/** All commands for a query, catalog order preserved. */
export function commandsFor(q: PrebuiltQuery): AbuseCommand[] {
  return q.commandKeys.flatMap((k) => ABUSE_COMMANDS[k] ?? []);
}

export interface CommandVars {
  domain?: string;
  dc?: string;
  target?: string;
  source?: string;
  targetDN?: string;
}

/** Fill the template variables we can resolve from the campaign; {{user}} and
 * {{password}} stay literal for the operator. */
export function fillCommand(tpl: string, vars: CommandVars): string {
  return tpl
    .replaceAll("{{domain}}", vars.domain ?? "<domain>")
    .replaceAll("{{dc}}", vars.dc ?? "<dc-ip>")
    .replaceAll("{{targetDN}}", vars.targetDN ?? "<target-dn>")
    .replaceAll("{{target}}", vars.target ?? "<target>")
    .replaceAll("{{source}}", vars.source ?? "<source>");
}
