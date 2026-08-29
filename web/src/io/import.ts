// Browser-side recon import. Parses Nmap XML, BloodHound/SharpHound JSON (both
// legacy v5 and CE v6 shapes), Pughound tables, NetExec/CME console output, and
// Nessus `.nessus` XML entirely in the client and applies the results through
// `Campaign.resolveOrCreate` — so imports reconcile onto existing nodes (the
// same host seen by two tools collapses). The Nmap parser mirrors the verified
// Rust importer in `import`; all parsers are total (bad input throws or yields
// fewer results, never corrupts the document).

import type { Campaign } from "@/campaign/document";
import type { Credential, GraphEdge, GraphNode, IdentityKey, NodeKind, Provenance } from "@/domain/types";

export interface ImportCtx {
  author: string;
  now: number;
  /** Seals a secret under the campaign vault key (present only when this operator
   * holds the vault). Used by the secretsdump importer to seal NT hashes into the
   * folded collection so the dump's secrets are stored, but never as plaintext. */
  seal?: (plaintext: string) => string;
}

export interface ImportSummary {
  hosts: number;
  services: number;
  edges: number;
  nodes: number;
  credentials: number;
}

const empty = (): ImportSummary => ({ hosts: 0, services: 0, edges: 0, nodes: 0, credentials: 0 });

const prov = (tool: string, ctx: ImportCtx): Provenance => ({
  author: ctx.author,
  source: { kind: "import", tool },
  confidence: "confirmed",
  first_seen: ctx.now,
  last_verified: ctx.now,
});

const node = (id: string, kind: NodeKind, label: string, ikeys: IdentityKey[], p: Provenance): GraphNode => ({
  id,
  kind,
  label,
  identity_keys: ikeys,
  compromise_level: "unknown",
  fields: {},
  tags: [],
  provenance: p,
});

const hostKindFromOs = (os?: string): NodeKind => {
  const s = (os ?? "").toLowerCase();
  if (s.includes("windows")) return "host_windows";
  if (s.includes("linux")) return "host_linux";
  if (s.includes("mac") || s.includes("darwin")) return "host_macos";
  return "host_windows";
};

// ---------------------------------------------------------------------------
// Nmap XML
// ---------------------------------------------------------------------------

interface NmapPort {
  portid: number;
  protocol: string;
  state: string;
  service?: string;
  product?: string;
  version?: string;
}
interface NmapHost {
  ipv4?: string;
  mac?: string;
  hostnames: string[];
  os?: string;
  ports: NmapPort[];
}

function xmlDoc(text: string): Document {
  const doc = new DOMParser().parseFromString(text, "application/xml");
  if (doc.querySelector("parsererror")) throw new Error("invalid XML");
  return doc;
}

export function parseNmap(xml: string): NmapHost[] {
  const doc = xmlDoc(xml);
  return Array.from(doc.querySelectorAll("host")).map((host) => {
    let ipv4: string | undefined;
    let mac: string | undefined;
    for (const a of Array.from(host.querySelectorAll("address"))) {
      const t = a.getAttribute("addrtype");
      if (t === "ipv4") ipv4 = a.getAttribute("addr") ?? undefined;
      else if (t === "mac") mac = a.getAttribute("addr") ?? undefined;
    }
    const hostnames = Array.from(host.querySelectorAll("hostname"))
      .map((h) => h.getAttribute("name"))
      .filter((n): n is string => !!n);
    const os = host.querySelector("osmatch")?.getAttribute("name") ?? undefined;
    const ports: NmapPort[] = [];
    for (const p of Array.from(host.querySelectorAll("port"))) {
      const portid = Number(p.getAttribute("portid"));
      if (!Number.isInteger(portid) || portid < 0 || portid > 65535) continue;
      const svc = p.querySelector("service");
      ports.push({
        portid,
        protocol: p.getAttribute("protocol") ?? "tcp",
        state: p.querySelector("state")?.getAttribute("state") ?? "unknown",
        service: svc?.getAttribute("name") ?? undefined,
        product: svc?.getAttribute("product") ?? undefined,
        version: svc?.getAttribute("version") ?? undefined,
      });
    }
    return { ipv4, mac, hostnames, os, ports };
  });
}

export function applyNmap(c: Campaign, hosts: NmapHost[], ctx: ImportCtx): ImportSummary {
  const p = prov("nmap", ctx);
  const s = empty();
  for (const h of hosts) {
    const ikeys: IdentityKey[] = [];
    if (h.ipv4) ikeys.push({ kind: "ip_address", value: h.ipv4, is_primary: true });
    if (h.mac) ikeys.push({ kind: "mac_address", value: h.mac, is_primary: false });
    for (const hn of h.hostnames) ikeys.push({ kind: "fqdn", value: hn.toLowerCase(), is_primary: false });
    if (!ikeys.length) continue;
    const label = h.hostnames[0] ?? h.ipv4 ?? "host";
    const hostId = c.resolveOrCreate(ikeys, (id) => node(id, hostKindFromOs(h.os), label, ikeys, p));
    s.hosts++;
    s.nodes++;
    if (h.os) c.setField(hostId, "os_version", h.os);
    for (const port of h.ports) {
      if (port.state !== "open") continue;
      const key: IdentityKey = { kind: "custom", value: `svc:${hostId}:${port.protocol}/${port.portid}`, is_primary: true };
      const label = `${port.protocol}/${port.portid} ${port.service ?? ""}`.trim();
      const svcId = c.resolveOrCreate([key], (id) => node(id, "service", label, [key], p));
      s.services++;
      c.setField(svcId, "port", port.portid);
      c.setField(svcId, "protocol", port.protocol);
      if (port.product) c.setField(svcId, "product", port.product);
      if (port.version) c.setField(svcId, "version", port.version);
      c.addEdge({ id: `${hostId}|listens_on|${svcId}`, kind: "listens_on", source: hostId, target: svcId, confidence: "confirmed", provenance: p });
      s.edges++;
    }
  }
  return s;
}

// ---------------------------------------------------------------------------
// BloodHound / SharpHound JSON
// ---------------------------------------------------------------------------

type BhType = "users" | "computers" | "groups" | "domains" | "gpos" | "ous" | "unknown";
type Json = Record<string, unknown>;
export interface BloodHoundFile {
  objectType: BhType;
  objects: Json[];
}

const bhType = (t: string): BhType => {
  const k = t.toLowerCase();
  return (["users", "computers", "groups", "domains", "gpos", "ous"] as BhType[]).find((x) => k === x || k === x.slice(0, -1)) ?? "unknown";
};

const str = (o: unknown, ...keys: string[]): string | undefined => {
  if (!o || typeof o !== "object") return undefined;
  for (const k of keys) {
    const v = (o as Json)[k];
    if (typeof v === "string") return v;
  }
  return undefined;
};
const arr = (o: unknown, ...keys: string[]): Json[] => {
  if (!o || typeof o !== "object") return [];
  for (const k of keys) {
    const v = (o as Json)[k];
    if (Array.isArray(v)) return v as Json[];
  }
  return [];
};
const resultsOf = (v: unknown): Json[] => {
  if (Array.isArray(v)) return v as Json[];
  if (v && typeof v === "object" && Array.isArray((v as Json)["Results"])) return (v as Json)["Results"] as Json[];
  return [];
};
const boolp = (o: unknown, key: string): boolean => !!o && typeof o === "object" && (o as Json)[key] === true;
const strArr = (o: unknown, key: string): string[] => {
  const v = o && typeof o === "object" ? (o as Json)[key] : undefined;
  return Array.isArray(v) ? v.map(String) : [];
};

export function parseBloodhound(json: string): BloodHoundFile {
  const f = JSON.parse(json) as Json; // throws on malformed → caught by the dispatcher
  return {
    objectType: bhType(str(f["meta"], "type") ?? ""),
    objects: Array.isArray(f["data"]) ? (f["data"] as Json[]) : [],
  };
}

/** SharpHound <=v5 uses lowercase `properties`; CE/v6 uses `Properties`. */
const bhProps = (o: Json): Json => (o["properties"] ?? o["Properties"]) as Json;

const bhSid = (o: Json): string | undefined => str(o, "objectid", "ObjectIdentifier") ?? str(bhProps(o), "objectid");
const bhName = (o: Json): string | undefined => str(o, "name") ?? str(bhProps(o), "name");
const bhDefaultKind: Record<BhType, NodeKind> = {
  users: "user_account",
  computers: "host_windows",
  groups: "group",
  domains: "domain",
  gpos: "gpo",
  ous: "organizational_unit",
  unknown: "custom",
};
// Mirror of the Rust `ace_edge_kind` (crates/import/src/bloodhound.rs) — where
// both exist, the same SharpHound file must yield the same graph either side.
const aceEdgeKind = (right: string): GraphEdge["kind"] | undefined => {
  switch (right.toLowerCase()) {
    case "genericall":
      return "generic_all";
    case "genericwrite":
      return "generic_write";
    case "writedacl":
      return "write_dacl";
    case "owns":
    case "owner":
      return "owns";
    case "writeowner":
    case "writeownerlimitedrights":
      return "write_owner";
    case "allextendedrights":
      return "all_extended_rights";
    case "forcechangepassword":
      return "force_change_password";
    case "addmember":
    case "addmembers":
      return "add_member";
    case "addself":
      return "add_self";
    case "addkeycredentiallink":
    case "writekeycredentiallink":
      return "shadow_credentials";
    case "writespn":
    case "addspn":
    case "writeserviceprincipalname":
      return "write_spn";
    case "addallowedtoact":
    case "allowedtoact":
    case "writeaccountrestrictions":
      return "allowed_to_act";
    case "allowedtodelegate":
      return "allowed_to_delegate";
    case "readgmsapassword":
      return "read_gmsa_password";
    case "readlapspassword":
    case "synclapspassword":
      return "read_laps_password";
    case "writegplink":
      return "write_gp_link";
    case "dcsync":
    case "getchanges":
    case "getchangesall":
      return "dc_sync";
    case "manageca":
    case "managecertificates":
      return "manage_ca";
    case "coercetotgt":
      return "coerce";
    default:
      return undefined;
  }
};

export function applyBloodhound(c: Campaign, files: BloodHoundFile[], ctx: ImportCtx): ImportSummary {
  const p = prov("bloodhound", ctx);
  const s = empty();
  const bySid = new Map<string, string>();
  // v6 GPOs key by bare GUID, and Links reference them by GUID — a second index
  // (lowercased) bridges them.
  const byGuid = new Map<string, string>();
  const byFqdn = new Map<string, string>();

  // Pass 1: nodes.
  for (const file of files) {
    for (const o of file.objects) {
      const sid = bhSid(o);
      if (!sid) continue;
      const name = bhName(o);
      const props = bhProps(o);
      const hasSpn = boolp(props, "hasspn") || strArr(props, "serviceprincipalnames").length > 0;
      // A SPN-bearing user IS a service account (and Kerberoastable).
      let kind: NodeKind =
        file.objectType === "computers" ? hostKindFromOs(str(props, "operatingsystem")) : bhDefaultKind[file.objectType];
      if (file.objectType === "users" && hasSpn) kind = "service_account";
      const ikeys: IdentityKey[] = [{ kind: "ad_sid", value: sid, is_primary: true }];
      if (file.objectType === "computers" && name) ikeys.push({ kind: "fqdn", value: name.toLowerCase(), is_primary: false });
      else if (file.objectType === "domains" && name) ikeys.push({ kind: "domain_name", value: name.toLowerCase(), is_primary: false });
      else if (file.objectType === "users" && name && name.includes("@")) ikeys.push({ kind: "account_upn", value: name.toLowerCase(), is_primary: false });
      const id = c.resolveOrCreate(ikeys, (nid) => node(nid, kind, name ?? sid, ikeys, p));
      if (str(props, "domain")) c.setField(id, "domain", str(props, "domain"));
      if (file.objectType === "domains" && str(props, "functionallevel")) c.setField(id, "functional_level", str(props, "functionallevel"));
      if (file.objectType === "computers" && str(props, "operatingsystem")) c.setField(id, "os_version", str(props, "operatingsystem"));
      if (file.objectType === "users" && name) c.setField(id, "upn", name);
      // Abuse-surface properties SharpHound ships that the path engine reasons over
      // (previously dropped on import). These feed the roast/delegation derivations.
      if (file.objectType === "users") {
        if (hasSpn) {
          c.setField(id, "kerberoastable", true);
          const spns = strArr(props, "serviceprincipalnames");
          if (spns.length) c.setField(id, "spn", spns);
        }
        if (boolp(props, "dontreqpreauth")) c.setField(id, "asrep_roastable", true);
        if (boolp(props, "admincount")) c.setField(id, "admin_count", true);
        const sh = strArr(props, "sidhistory");
        if (sh.length) c.setField(id, "sid_history", sh);
      }
      if (file.objectType === "computers" && boolp(props, "unconstraineddelegation")) {
        c.setField(id, "unconstrained_delegation", true);
        c.setField(id, "delegation", "unconstrained");
      }
      if (boolp(props, "highvalue")) c.setField(id, "is_tier_zero", true);
      // v6 flags the path engine and the pre-built queries reason over.
      if (boolp(props, "trustedtoauth")) c.setField(id, "protocol_transition", true);
      if (boolp(props, "haslaps")) c.setField(id, "laps_enabled", true);
      if (boolp(props, "enabled") === false && props && "enabled" in (props as object)) c.setField(id, "enabled", false);
      if (file.objectType === "gpos") byGuid.set(sid.toLowerCase(), id);
      if (file.objectType === "computers" && name) byFqdn.set(name.toLowerCase(), id);
      if (!bySid.has(sid)) {
        bySid.set(sid, id);
        s.nodes++;
        if (file.objectType === "computers") s.hosts++;
      }
    }
  }

  const addEdge = (kind: string, source: string, target: string, fields?: Record<string, unknown>): void => {
    if (source === target) return;
    c.addEdge({ id: `${source}|${kind}|${target}`, kind: kind as GraphEdge["kind"], source, target, confidence: "confirmed", fields, provenance: p });
    s.edges++;
  };

  // SharpHound TrustDirection is a 0..3 enum (newer) or a string (older) — normalize.
  const trustDir = (v: unknown): string => {
    const labels = ["disabled", "inbound", "outbound", "bidirectional"];
    if (typeof v === "number") return labels[v] ?? "unknown";
    if (typeof v === "string") return labels.includes(v.toLowerCase()) ? v.toLowerCase() : "unknown";
    return "unknown";
  };

  // Pass 2: relationships.
  for (const file of files) {
    for (const o of file.objects) {
      const sid = bhSid(o);
      if (!sid) continue;
      const self = bySid.get(sid);
      if (!self) continue;

      for (const m of arr(o, "Members", "members")) {
        const msid = str(m, "ObjectIdentifier", "objectid");
        const src = msid && bySid.get(msid);
        if (src) addEdge("member_of", src, self);
      }
      for (const ace of arr(o, "Aces", "aces")) {
        const psid = str(ace, "PrincipalSID", "principalsid");
        const right = str(ace, "RightName", "rightname");
        const src = psid && bySid.get(psid);
        const kind = right && aceEdgeKind(right);
        if (src && kind) addEdge(kind, src, self);
      }
      for (const t of arr(o, "Trusts", "trusts")) {
        const tsid = str(t, "TargetDomainSid", "targetdomainsid");
        if (!tsid) continue;
        let tgt = bySid.get(tsid);
        if (!tgt) {
          const tname = str(t, "TargetDomainName", "targetdomainname");
          const ik: IdentityKey[] = [{ kind: "ad_sid", value: tsid, is_primary: true }];
          if (tname) ik.push({ kind: "domain_name", value: tname.toLowerCase(), is_primary: false });
          tgt = c.resolveOrCreate(ik, (nid) => node(nid, "domain", tname ?? tsid, ik, p));
          if (!bySid.has(tsid)) {
            bySid.set(tsid, tgt);
            s.nodes++;
          }
        }
        // Mirror the Rust importer: carry trust semantics the cost model routes on.
        const tr = t as Record<string, unknown>;
        const tf: Record<string, unknown> = {};
        const dir = tr["TrustDirection"] ?? tr["trustdirection"];
        if (dir !== undefined) tf["direction"] = trustDir(dir);
        const tt = str(t, "TrustType", "trusttype");
        if (tt) tf["trust_type"] = tt;
        const trans = tr["IsTransitive"] ?? tr["istransitive"];
        if (typeof trans === "boolean") tf["transitive"] = trans;
        const sf = tr["SidFilteringEnabled"] ?? tr["sidfilteringenabled"];
        if (typeof sf === "boolean") tf["sid_filtering"] = sf;
        addEdge("trusts", self, tgt, Object.keys(tf).length ? tf : undefined);
      }
      for (const sess of resultsOf(o["Sessions"] ?? o["sessions"])) {
        const cs = str(sess, "ComputerSID", "computersid");
        const us = str(sess, "UserSID", "usersid");
        const cn = cs && bySid.get(cs);
        const un = us && bySid.get(us);
        if (cn && un) addEdge("has_session", cn, un);
      }
      // v6 splits sessions into privileged/registry collections too.
      for (const key of ["PrivilegedSessions", "RegistrySessions"] as const) {
        for (const sess of resultsOf(o[key])) {
          const cs = str(sess, "ComputerSID", "computersid");
          const us = str(sess, "UserSID", "usersid");
          const cn = cs && bySid.get(cs);
          const un = us && bySid.get(us);
          if (cn && un) addEdge("has_session", cn, un);
        }
      }
      for (const la of resultsOf(o["LocalAdmins"] ?? o["local_admins"])) {
        const psid = str(la, "ObjectIdentifier", "objectid");
        const src = psid && bySid.get(psid);
        if (src) addEdge("admin_to", src, self);
      }
      // v6: LocalGroups carries local group memberships — the Administrators
      // group is admin_to; the rest are noise for path purposes.
      for (const lg of arr(o, "LocalGroups")) {
        if ((str(lg, "Name") ?? "").toLowerCase() !== "administrators") continue;
        for (const m of arr(lg, "Members")) {
          const psid = str(m, "ObjectIdentifier", "objectid");
          const src = psid && bySid.get(psid);
          if (src) addEdge("admin_to", src, self);
        }
      }
      // v6: RBCD principals listed directly on the target.
      for (const m of arr(o, "AllowedToAct")) {
        const psid = str(m, "ObjectIdentifier", "objectid");
        const src = psid && bySid.get(psid);
        if (src) addEdge("allowed_to_act", src, self);
      }
      // Constrained delegation targets: SPN strings (older) or object refs (v6).
      const adele = o["AllowedToDelegate"];
      if (Array.isArray(adele)) {
        for (const m of adele as unknown[]) {
          if (typeof m === "string") {
            const fqdn = m.split("/")[1]?.split(":")[0]?.toLowerCase();
            const tgt = fqdn && byFqdn.get(fqdn);
            if (tgt) addEdge("allowed_to_delegate", self, tgt);
          } else if (m && typeof m === "object") {
            const psid = str(m, "ObjectIdentifier", "objectid");
            const tgt = psid && bySid.get(psid);
            if (tgt) addEdge("allowed_to_delegate", self, tgt);
          }
        }
        if (adele.length) c.setField(self, "delegation", "constrained");
      }
      // v6: DumpSMSAPassword — principals allowed to read the sMSA password.
      for (const m of arr(o, "DumpSMSAPassword")) {
        const psid = str(m, "ObjectIdentifier", "objectid");
        const src = psid && bySid.get(psid);
        if (src) addEdge("read_gmsa_password", src, self);
      }
      // v6: GPO links on domains/OUs/containers — GUID references the GPO.
      for (const l of arr(o, "Links")) {
        const g = str(l, "GUID");
        const gpo = g && byGuid.get(g.toLowerCase());
        if (gpo) addEdge("gpo_applies_to", gpo, self, { enforced: boolp(l, "IsEnforced") === true });
      }
      // v6: GPOChanges — effective local rights the linked GPOs grant.
      const gpochanges = o["GPOChanges"];
      if (gpochanges && typeof gpochanges === "object") {
        const affected = arr(gpochanges, "AffectedComputers")
          .map((m) => str(m, "ObjectIdentifier", "objectid"))
          .filter((x): x is string => !!x);
        const grants: [string, GraphEdge["kind"]][] = [
          ["LocalAdmins", "admin_to"],
          ["RemoteDesktopUsers", "can_rdp"],
          ["PSRemoteUsers", "can_ps_remote"],
          ["DcomUsers", "execute_dcom"],
        ];
        for (const [key, kind] of grants) {
          for (const m of arr(gpochanges, key)) {
            const psid = str(m, "ObjectIdentifier", "objectid");
            const src = psid && bySid.get(psid);
            if (!src) continue;
            for (const csid of affected) {
              const cn = bySid.get(csid);
              if (cn) addEdge(kind, src, cn);
            }
          }
        }
      }
      // v6: OU/container child objects.
      for (const ch of arr(o, "ChildObjects")) {
        const csid = str(ch, "ObjectIdentifier", "objectid");
        const child = csid && bySid.get(csid);
        if (child) addEdge("contains_ou", self, child);
      }
    }
  }

  return s;
}

// ---------------------------------------------------------------------------
// NetExec / CrackMapExec console output
// ---------------------------------------------------------------------------

const stripAnsi = (s: string): string => s.replace(/\[[0-9;]*[A-Za-z]/g, "");
const looksLikeIp = (s: string): boolean => /^[0-9.]+$/.test(s) && s.split(".").length === 4;

interface NxcParsed {
  hosts: { protocol: string; ip: string; hostname?: string; os?: string }[];
  creds: { ip: string; domain?: string; username: string; secret: string; valid: boolean; admin: boolean }[];
}

export function parseNetexec(text: string): NxcParsed {
  const hosts = new Map<string, NxcParsed["hosts"][number]>();
  const creds: NxcParsed["creds"] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = stripAnsi(raw);
    const parts = line.split(/\s+/).filter(Boolean);
    if (parts.length < 5) continue;
    const proto = parts[0]!;
    if (!/^[A-Za-z0-9]+$/.test(proto)) continue;
    const ip = parts[1]!;
    if (!looksLikeIp(ip)) continue;
    const hostname = parts[3] && !parts[3].startsWith("[") ? parts[3] : undefined;
    let host = hosts.get(ip);
    if (!host) {
      host = { protocol: proto.toLowerCase(), ip, hostname };
      hosts.set(ip, host);
    } else if (!host.hostname && hostname) host.hostname = hostname;

    const star = line.indexOf("[*]");
    const plus = line.indexOf("[+]");
    const minus = line.indexOf("[-]");
    if (star >= 0 && plus < 0 && minus < 0) {
      const msg = line.slice(star + 3).trim();
      const os = msg.split(" (")[0]!.trim();
      if (os && !host.os) host.os = os;
    } else if (plus >= 0 || minus >= 0) {
      const valid = plus >= 0;
      const msg = line.slice((valid ? plus : minus) + 3).trim();
      const cand = msg.split(/\s+/)[0] ?? "";
      const colon = cand.indexOf(":");
      if (colon > 0) {
        const userpart = cand.slice(0, colon);
        const secret = cand.slice(colon + 1);
        const slash = userpart.indexOf("\\");
        const domain = slash >= 0 ? userpart.slice(0, slash) : undefined;
        const username = slash >= 0 ? userpart.slice(slash + 1) : userpart;
        if (username) creds.push({ ip, domain, username, secret, valid, admin: msg.includes("Pwn3d") });
      }
    }
  }
  return { hosts: [...hosts.values()], creds };
}

const guessCredType = (secret: string): Credential["credential_type"] => {
  const parts = secret.split(":");
  const hexish = parts.every((p) => p.length === 32 && /^[0-9a-fA-F]+$/.test(p));
  return (parts.length === 1 || parts.length === 2) && hexish && secret ? "password_ntlm" : "password_plaintext";
};

export function applyNetexec(c: Campaign, out: NxcParsed, ctx: ImportCtx): ImportSummary {
  const p = prov("netexec", ctx);
  const s = empty();
  const hostIds = new Map<string, string>();
  const ensure = (ip: string, hostname: string | undefined, os: string | undefined): string => {
    const existing = hostIds.get(ip);
    if (existing) return existing;
    const ikeys: IdentityKey[] = [{ kind: "ip_address", value: ip, is_primary: true }];
    if (hostname) ikeys.push({ kind: "hostname", value: hostname.toLowerCase(), is_primary: false });
    const id = c.resolveOrCreate(ikeys, (nid) => node(nid, hostKindFromOs(os), hostname ?? ip, ikeys, p));
    hostIds.set(ip, id);
    s.hosts++;
    s.nodes++;
    return id;
  };

  for (const h of out.hosts) {
    const id = ensure(h.ip, h.hostname, h.os);
    if (h.os) c.setField(id, "os_version", h.os);
  }

  // Aggregate by principal: one vault record listing every host it opened.
  const byPrincipal = new Map<string, { domain?: string; username: string; type: Credential["credential_type"]; anyValid: boolean; tests: { host: string; succeeded: boolean }[] }>();
  for (const cr of out.creds) {
    if (cr.admin && cr.valid) c.setCompromise(ensure(cr.ip, undefined, undefined), "admin");
    const host = ensure(cr.ip, undefined, undefined);
    const k = `${(cr.domain ?? "").toLowerCase()}\\${cr.username.toLowerCase()}`;
    const e = byPrincipal.get(k) ?? { domain: cr.domain, username: cr.username, type: guessCredType(cr.secret), anyValid: false, tests: [] };
    e.anyValid ||= cr.valid;
    e.tests.push({ host, succeeded: cr.valid });
    byPrincipal.set(k, e);
  }
  for (const [k, e] of byPrincipal) {
    const cred: Credential = {
      id: `nxc:${k}`,
      username: e.username,
      domain: e.domain,
      credential_type: e.type,
      validity: e.anyValid ? "valid" : "invalid",
      validity_as_of: ctx.now,
      source: "spray",
      tested_against: e.tests.map((t) => ({ host: t.host, succeeded: t.succeeded, at: ctx.now })),
      provenance: p,
    };
    c.addCredential(cred);
    s.credentials++;
  }
  return s;
}

// ---------------------------------------------------------------------------
// Nessus (.nessus v2)
// ---------------------------------------------------------------------------

const severityLabel = (sev: number): string => (sev >= 4 ? "critical" : sev === 3 ? "high" : sev === 2 ? "medium" : sev === 1 ? "low" : "info");

interface NessusHostT {
  ip?: string;
  fqdn?: string;
  os?: string;
  items: { port: number; protocol: string; svc?: string; plugin: string; severity: number }[];
}

export function parseNessus(xml: string): NessusHostT[] {
  const doc = xmlDoc(xml);
  return Array.from(doc.querySelectorAll("ReportHost")).map((rh) => {
    const host: NessusHostT = { ip: rh.getAttribute("name") ?? undefined, items: [] };
    for (const tag of Array.from(rh.querySelectorAll("tag"))) {
      const name = tag.getAttribute("name");
      const text = tag.textContent ?? undefined;
      if (name === "host-ip") host.ip = text;
      else if (name === "host-fqdn") host.fqdn = text;
      else if (name === "operating-system") host.os = text;
    }
    for (const it of Array.from(rh.querySelectorAll("ReportItem"))) {
      const port = Number(it.getAttribute("port") ?? "0") || 0;
      const svc = it.getAttribute("svc_name") ?? undefined;
      host.items.push({
        port,
        protocol: it.getAttribute("protocol") ?? "tcp",
        svc: svc && svc !== "general" ? svc : undefined,
        plugin: it.getAttribute("pluginName") ?? "Nessus finding",
        severity: Number(it.getAttribute("severity") ?? "0") || 0,
      });
    }
    return host;
  });
}

function mergeFindings(c: Campaign, id: string, incoming: unknown[]): void {
  const cur = c.nodes().find((n) => n.id === id);
  const existing = Array.isArray(cur?.fields["findings"]) ? (cur!.fields["findings"] as unknown[]) : [];
  const titles = new Set(existing.map((f) => (f as Json)["title"]));
  const merged = [...existing];
  for (const f of incoming) {
    const t = (f as Json)["title"];
    if (!titles.has(t)) {
      titles.add(t);
      merged.push(f);
    }
  }
  c.setField(id, "findings", merged);
}

export function applyNessus(c: Campaign, hosts: NessusHostT[], ctx: ImportCtx): ImportSummary {
  const p = prov("nessus", ctx);
  const s = empty();
  for (const h of hosts) {
    const ikeys: IdentityKey[] = [];
    if (h.ip) ikeys.push({ kind: "ip_address", value: h.ip, is_primary: true });
    if (h.fqdn) ikeys.push({ kind: "fqdn", value: h.fqdn.toLowerCase(), is_primary: false });
    if (!ikeys.length) continue;
    const label = h.fqdn ?? h.ip ?? "host";
    const hostId = c.resolveOrCreate(ikeys, (id) => node(id, hostKindFromOs(h.os), label, ikeys, p));
    s.hosts++;
    s.nodes++;
    if (h.os) c.setField(hostId, "os_version", h.os);

    const hostFindings: unknown[] = [];
    for (const item of h.items) {
      if (item.severity === 0) continue;
      const finding = { title: item.plugin, severity: severityLabel(item.severity), status: "open" };
      if (item.port === 0) {
        hostFindings.push(finding);
        continue;
      }
      const key: IdentityKey = { kind: "custom", value: `svc:${hostId}:${item.protocol}/${item.port}`, is_primary: true };
      const label = `${item.protocol}/${item.port} ${item.svc ?? ""}`.trim();
      const svcId = c.resolveOrCreate([key], (id) => node(id, "service", label, [key], p));
      s.services++;
      c.setField(svcId, "port", item.port);
      c.setField(svcId, "protocol", item.protocol);
      if (item.svc) c.setField(svcId, "product", item.svc);
      mergeFindings(c, svcId, [finding]);
      c.addEdge({ id: `${hostId}|listens_on|${svcId}`, kind: "listens_on", source: hostId, target: svcId, confidence: "confirmed", provenance: p });
      s.edges++;
    }
    if (hostFindings.length) mergeFindings(c, hostId, hostFindings);
  }
  return s;
}

// ---------------------------------------------------------------------------
// secretsdump / NTDS.dit  (→ folded collection + sealed vault, NOT graph nodes)
// ---------------------------------------------------------------------------
// The crown-jewel artifact of an AD engagement is the full hash set. Materializing
// one node per account would bury the map, so the whole dump becomes ONE folded
// collection: each account is an off-canvas member whose NT hash is sealed into the
// member blob, lifted into the vault only if/when the principal is promoted.

interface SecretsdumpAccount {
  domain?: string;
  sam: string;
  rid?: number;
  nt?: string;
  is_machine: boolean;
  is_krbtgt: boolean;
}
interface SecretsdumpParsed {
  domain?: string;
  accounts: SecretsdumpAccount[];
}

// `DOMAIN\sam:rid:lmhash:nthash:::` (the canonical `-just-dc` line; domain optional).
const NTDS_LINE = /^([^:]*?):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::\s*$/;

export function parseSecretsdump(text: string): SecretsdumpParsed {
  const accounts: SecretsdumpAccount[] = [];
  const seen = new Set<string>();
  let domain: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const m = NTDS_LINE.exec(raw.trim());
    if (!m) continue;
    const principal = m[1]!;
    const slash = principal.indexOf("\\");
    const dom = slash >= 0 ? principal.slice(0, slash) : undefined;
    const sam = slash >= 0 ? principal.slice(slash + 1) : principal;
    if (!sam || /_history\d*$/i.test(sam)) continue; // skip password-history rows
    const key = `${(dom ?? "").toLowerCase()}\\${sam.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (dom && !domain) domain = dom;
    accounts.push({
      domain: dom,
      sam,
      rid: Number(m[2]),
      nt: m[4]!.toLowerCase(),
      is_machine: sam.endsWith("$"),
      is_krbtgt: sam.toLowerCase() === "krbtgt",
    });
  }
  return { domain, accounts };
}

export function applySecretsdump(c: Campaign, parsed: SecretsdumpParsed, ctx: ImportCtx): ImportSummary {
  const s = empty();
  if (!parsed.accounts.length) return s;
  const dom = parsed.domain ?? "unknown";
  const collId = `coll:secretsdump:${dom.toLowerCase()}`;
  c.addCollection({
    id: collId,
    tool: "secretsdump",
    object_type: "ntds",
    domain: dom,
    label: `NTDS: ${dom}`,
    created_by: ctx.author,
    created_at: ctx.now,
    last_collected_at: ctx.now,
    stats: {},
    count: 0,
  });
  let machines = 0;
  let krbtgt = 0;
  for (const a of parsed.accounts) {
    if (a.is_machine) machines++;
    if (a.is_krbtgt) krbtgt++;
    const account = `${(a.domain ?? dom).toLowerCase()}\\${a.sam.toLowerCase()}`;
    const sealed = a.nt && ctx.seal ? ctx.seal(a.nt) : undefined;
    c.addCollectionMember(collId, {
      key: account,
      kind: a.is_machine ? "computer_account" : "user_account",
      label: a.sam,
      identity_keys: [{ kind: "account_sam", value: account, is_primary: true }],
      fields: { sam: a.sam, ...(a.rid !== undefined ? { rid: a.rid } : {}), ...(a.is_krbtgt ? { is_krbtgt: true } : {}) },
      tags: a.is_krbtgt ? ["golden-ticket"] : [],
      sealed_secrets: [{ type: "password_ntlm", username: a.sam, domain: a.domain ?? dom, sealed }],
    });
    s.credentials++;
  }
  c.setCollectionStat(collId, "total", parsed.accounts.length);
  c.setCollectionStat(collId, "machines", machines);
  if (krbtgt) c.setCollectionStat(collId, "krbtgt", krbtgt);
  return s;
}

// ---------------------------------------------------------------------------
// Pughound (AD enumeration — JSON tables)
// ---------------------------------------------------------------------------
//
// Pughound emits one JSON per query (`json/*.json`, shape `{query, columns,
// rows}`) plus a consolidated `pughound-report.json` (`categories[].tables[]`
// wrapping the same rows). Both parse to the same `PughoundTable` list and are
// applied together, so cross-table references (DNs, SIDs, sAMAccountNames)
// resolve. Reconciliation rides `resolveOrCreate`: the same DC seen by Pughound
// and Nmap collapses onto one node.

export interface PughoundTable {
  name: string;
  rows: Record<string, unknown>[];
}

export function parsePughound(json: string): PughoundTable[] {
  const f = JSON.parse(json) as Json; // throws on malformed → caught by the dispatcher
  // Consolidated report: categories[] of tables[].
  if (Array.isArray(f["categories"])) {
    const out: PughoundTable[] = [];
    for (const cat of f["categories"] as Json[]) {
      for (const t of arr(cat, "tables")) {
        const name = str(t, "name");
        if (name) out.push({ name, rows: arr(t, "rows") as Record<string, unknown>[] });
      }
    }
    return out;
  }
  // Single table file.
  const name = str(f, "query");
  if (name && Array.isArray(f["rows"])) return [{ name, rows: f["rows"] as Record<string, unknown>[] }];
  throw new Error("not a pughound file");
}

/** Well-known SIDs Pughound prints bare (no object lookup), given a readable label. */
const WELL_KNOWN_SID: Record<string, string> = {
  "S-1-1-0": "Everyone",
  "S-1-5-9": "Enterprise Domain Controllers",
  "S-1-5-10": "Principal Self",
  "S-1-5-11": "Authenticated Users",
  "S-1-5-18": "Local System",
  "S-1-5-32-544": "Administrators (builtin)",
  "S-1-5-32-545": "Users (builtin)",
  "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
  "S-1-5-32-560": "Windows Authorization Access Group",
  "S-1-5-32-561": "Terminal Server License Servers",
};

const WELL_KNOWN_RID: Record<string, string> = {
  "498": "Enterprise Read-only Domain Controllers",
  "512": "Domain Admins",
  "516": "Domain Controllers",
  "517": "Cert Publishers",
  "518": "Schema Admins",
  "519": "Enterprise Admins",
  "520": "Group Policy Creator Owners",
  "521": "Read-only Domain Controllers",
};

/** Trustees that never become attack edges (SharpHound Helpers.PreProcessSID). */
const FILTERED_ACE_SIDS = new Set(["S-1-5-18", "S-1-3-0", "S-1-5-10"]);

/** ACE objectType GUIDs (SharpHoundCommon ACEGuids.cs), lowercase. */
const PH_GUID = {
  all: "00000000-0000-0000-0000-000000000000",
  forceChangePassword: "00299570-246d-11d0-a768-00aa006e0529",
  writeSpn: "f3a64788-5306-11d1-a9c5-0000f80367c1",
  addKeyCredentialLink: "5b47d60f-6090-40b2-9f37-2a4de88f3063",
  getChanges: "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
  getChangesAll: "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
  getChangesFiltered: "89e95b76-444d-4c62-991a-0facbeda640c",
  member: "bf9679c0-0de6-11d0-a285-00aa003049e2",
  membershipPropertySet: "bc0ac240-79a9-11d0-9020-00c04fc2d4cf",
  writeAllowedToAct: "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79",
  userAccountRestrictions: "4c164200-20c0-11d0-a768-00aa006e0529",
  writeGpLink: "f30e3bbe-9ff0-11d1-b603-0000f80367c1",
  writeAltSecurityIdentities: "00fbf30c-91fe-11d1-aebc-0000f80367c1",
  writePublicInformation: "e48d0154-bcf8-11d1-8702-00c04fb96050",
  pkiNameFlag: "ea1dddc4-60ff-416e-8cc0-17cee534bce7",
  pkiEnrollmentFlag: "d15ef7d8-f226-46db-ae79-b34e560bd12c",
  enroll: "0e10c968-78fb-11d2-90d4-00c04f79dc55",
  autoEnroll: "a05b8cc2-17bc-4802-a710-e7c15ab866a2",
} as const;

/** Schema class GUIDs (SharpHound ACLProcessor.BaseGuids) per class key. */
const CLASS_SCHEMA_GUID: Record<string, string> = {
  user: "bf967aba-0de6-11d0-a285-00aa003049e2",
  computer: "bf967a86-0de6-11d0-a285-00aa003049e2",
  group: "bf967a9c-0de6-11d0-a285-00aa003049e2",
  domain: "19195a5a-6da0-11d0-afd3-00c04fd930c9",
  gpo: "f30e3bc2-9ff0-11d1-b603-0000f80367c1",
  ou: "bf967aa5-0de6-11d0-a285-00aa003049e2",
  container: "bf967a8b-0de6-11d0-a285-00aa003049e2",
  certtemplate: "e5209ca2-3bba-11d2-90cc-00c04fd91ab1",
  ca: "ee4aa692-3bba-11d2-90cc-00c04fd91ab1",
};

/** LDAP structural objectClass (last of chain) → class key used for gating. */
const OBJECT_CLASS: Record<string, string> = {
  user: "user",
  computer: "computer",
  group: "group",
  organizationalunit: "ou",
  grouppolicycontainer: "gpo",
  domaindns: "domain",
  container: "container",
  pkicertificatetemplate: "certtemplate",
  certificationauthority: "ca",
};

/** Node kind for stubs created from ACL rows, by structural objectClass. */
const phNodeKind = (objClass: string): NodeKind => {
  switch (objClass) {
    case "user": return "user_account";
    case "computer": return "host_windows";
    case "group": return "group";
    case "organizationalunit": return "organizational_unit";
    case "grouppolicycontainer": return "gpo";
    case "domaindns": return "domain";
    case "pkicertificatetemplate": return "cert_template";
    case "certificationauthority": return "certificate_authority";
    default: return "custom";
  }
};

/** Only Allow ACEs become edges (collector spelling or legacy ACCESS_ALLOWED). */
const isAllowAce = (aceType: string): boolean => {
  const norm = aceType.replace(/[\s_]/g, "");
  return norm === "" || norm === "accessallowed" || norm === "accessallowedobject";
};

/**
 * Port of SharpHound's IsAceInheritedFrom: an ACE applies to the object iff it
 * is inherited AND its inheritedObjectType is All/empty or matches the target's
 * schema class GUID, or it is NOT inherited and NOT inherit-only. flagsHex is
 * the collector's Flags column (0x10=inherited, 0x08=inherit-only).
 */
const aceAppliesToTarget = (flagsHex: string | undefined, inheritedObjectType: string, targetClass: string | undefined): boolean => {
  let flags = 0;
  const f = (flagsHex ?? "").trim().toLowerCase();
  if (f) {
    const v = parseInt(f.replace(/^0x/, ""), 16);
    if (!Number.isNaN(v)) flags = v;
  }
  const inherited = (flags & 0x10) !== 0;
  const inheritOnly = (flags & 0x08) !== 0;
  if (inherited) {
    if (!inheritedObjectType || inheritedObjectType === PH_GUID.all) return true;
    const classGuid = targetClass ? CLASS_SCHEMA_GUID[targetClass] : undefined;
    return classGuid !== undefined && inheritedObjectType === classGuid;
  }
  return !inheritOnly;
};

/**
 * Port of the SharpHound ACL edge mapping (rights × objectType GUID × target
 * class) → BloodHound edge names, which aceEdgeKind then maps to our kinds.
 * lapsGuids resolves schema-defined LAPS attribute GUIDs (SchemaAttrs table).
 */
const aclEdgeNames = (rights: string, objectType: string, targetClass: string | undefined, lapsGuids: Set<string>): string[] => {
  const kinds: string[] = [];
  const add = (k: string): void => { if (!kinds.includes(k)) kinds.push(k); };
  const tokens = new Set(rights.split(/[|;,]/).map((t) => t.trim().toLowerCase()).filter(Boolean));
  const guid = objectType === "{..}" ? "" : objectType;
  const allOrEmpty = guid === "" || guid === PH_GUID.all;

  // GenericAll/WriteDacl/WriteOwner apply to every type, only when unscoped.
  if (allOrEmpty) {
    if (tokens.has("genericall")) return ["GenericAll"]; // exclusive: subsumes all
    if (tokens.has("writedacl")) add("WriteDacl");
    if (tokens.has("writeowner")) add("WriteOwner");
  }

  if (tokens.has("self") && !tokens.has("writeproperty") && !tokens.has("genericwrite") &&
      targetClass === "group" && (guid === PH_GUID.member || guid === PH_GUID.membershipPropertySet || allOrEmpty)) {
    add("AddSelf");
  }

  if (tokens.has("extendedright") || tokens.has("genericall")) {
    switch (targetClass) {
      case "domain":
        if (guid === PH_GUID.getChanges) add("GetChanges");
        else if (guid === PH_GUID.getChangesAll) add("GetChangesAll");
        else if (guid === PH_GUID.getChangesFiltered) add("GetChangesInFilteredSet");
        else if (allOrEmpty) add("AllExtendedRights");
        break;
      case "user":
        if (guid === PH_GUID.forceChangePassword) add("ForceChangePassword");
        else if (allOrEmpty) add("AllExtendedRights");
        break;
      case "computer":
        if (lapsGuids.has(guid)) add("ReadLAPSPassword");
        else if (allOrEmpty) add("AllExtendedRights");
        break;
      case "certtemplate":
        if (guid === PH_GUID.enroll) add("Enroll");
        else if (allOrEmpty) add("AllExtendedRights");
        break;
      case "ca":
        if (guid === PH_GUID.enroll) add("Enroll");
        break;
    }
  }

  if (tokens.has("genericwrite") || tokens.has("writeproperty") || tokens.has("genericall")) {
    if (targetClass && ["user", "group", "computer", "gpo", "ou", "domain", "certtemplate", "ca"].includes(targetClass) && allOrEmpty) {
      add("GenericWrite");
    }
    if (targetClass === "user" && guid === PH_GUID.writeSpn) add("WriteSPN");
    else if (targetClass === "computer" && guid === PH_GUID.writeAllowedToAct) add("AddAllowedToAct");
    else if (targetClass === "computer" && guid === PH_GUID.userAccountRestrictions) add("WriteAccountRestrictions");
    else if ((targetClass === "ou" || targetClass === "domain") && guid === PH_GUID.writeGpLink) add("WriteGPLink");
    else if (targetClass === "group" && (guid === PH_GUID.member || guid === PH_GUID.membershipPropertySet)) add("AddMember");
    else if ((targetClass === "user" || targetClass === "computer") && guid === PH_GUID.addKeyCredentialLink) add("AddKeyCredentialLink");
    else if ((targetClass === "user" || targetClass === "computer") && guid === PH_GUID.writeAltSecurityIdentities) add("WriteAltSecurityIdentities");
    else if ((targetClass === "user" || targetClass === "computer") && guid === PH_GUID.writePublicInformation) add("WritePublicInformation");
    else if (targetClass === "certtemplate" && guid === PH_GUID.pkiEnrollmentFlag) add("WritePKIEnrollmentFlag");
    else if (targetClass === "certtemplate" && guid === PH_GUID.pkiNameFlag) add("WritePKINameFlag");
  }

  // CA DACLs use CertificationAuthorityRights (0x1=ManageCA, 0x2=ManageCertificates);
  // the collector decodes masks generically, so reinterpret only on CA targets.
  if (targetClass === "ca") {
    if (tokens.has("createchild")) add("ManageCA");
    if (tokens.has("deletechild")) add("ManageCertificates");
  }

  // Enrollment extended rights on templates (collector may also emit GUIDs raw).
  if (guid === PH_GUID.autoEnroll) add("AutoEnroll");

  return kinds;
};

/** BloodHound edge name → our EdgeKind, extending aceEdgeKind's coverage. */
const phAceKind = (edgeName: string): GraphEdge["kind"] | undefined => {
  const viaShared = aceEdgeKind(edgeName);
  if (viaShared) return viaShared;
  switch (edgeName) {
    case "GetChangesInFilteredSet": return "dc_sync";
    case "Enroll": case "AutoEnroll": return "enroll";
    case "WriteAltSecurityIdentities": case "WritePublicInformation":
    case "WritePKIEnrollmentFlag": case "WritePKINameFlag":
      return "generic_write";
    default: return undefined;
  }
};

/** Offensive AdminSDHolder rights worth an edge; pure read noise is skipped. */
const aceRightEdge = (right: string): GraphEdge["kind"] | undefined => {
  switch (right.toLowerCase()) {
    case "genericall": return "generic_all";
    case "writedacl": return "write_dacl";
    case "writeowner": return "write_owner";
    case "extendedright": return "all_extended_rights";
    case "writeproperty": return "generic_write";
    case "createchild": case "deletechild": case "self": case "delete": case "deletetree": return "generic_write";
    default: return undefined;
  }
};

export function applyPughound(c: Campaign, tables: PughoundTable[], ctx: ImportCtx): ImportSummary {
  const p = prov("pughound", ctx);
  const s = empty();
  const byName = new Map<string, PughoundTable>();
  for (const t of tables) byName.set(t.name, t);
  const rows = (name: string): Record<string, unknown>[] => byName.get(name)?.rows ?? [];

  // Indexes built as nodes are created.
  const bySid = new Map<string, string>();
  const bySam = new Map<string, string>();
  const byDn = new Map<string, string>();
  const byFqdn = new Map<string, string>();

  const addEdge = (kind: GraphEdge["kind"], source: string, target: string, fields?: Record<string, unknown>): void => {
    if (source === target) return;
    c.addEdge({ id: `${source}|${kind}|${target}`, kind, source, target, confidence: "confirmed", fields, provenance: p });
    s.edges++;
  };

  // ---- domain -------------------------------------------------------------
  const domainSid = str(rows("DomainSID")[0], "DomainSID");
  const sampleDn =
    str(rows("Users")[0], "distinguishedName") ??
    str(rows("DomainGroups")[0], "dn") ??
    str(rows("Computers")[0], "distinguishedName") ??
    "";
  const domainName = (sampleDn.match(/DC=([^,]+)/gi) ?? [])
    .map((p) => p.slice(3))
    .join(".")
    .toLowerCase();
  const domIkeys: IdentityKey[] = [];
  if (domainSid) domIkeys.push({ kind: "ad_sid", value: domainSid, is_primary: true });
  if (domainName) domIkeys.push({ kind: "domain_name", value: domainName, is_primary: !domainSid });
  let domainId: string | null = null;
  if (domIkeys.length) {
    domainId = c.resolveOrCreate(domIkeys, (nid) => node(nid, "domain", domainName || domainSid || "domain", domIkeys, p));
    if (domainSid) bySid.set(domainSid, domainId);
    s.nodes++;
    const ver = str(rows("DomainVersion")[0], "objectVersion");
    if (ver) c.setField(domainId, "functional_level", ver);
    const maq = str(rows("MAQ")[0], "MAQ") ?? str(rows("MAQ")[0], "ms-DS-MachineAccountQuota");
    if (maq) c.setField(domainId, "machine_account_quota", maq);
    const krbtgt = str(rows("Krbtgt_PwdLastSet")[0], "pwdLastSet");
    if (krbtgt) c.setField(domainId, "krbtgt_pwd_last_set", krbtgt);
    const pol = rows("Policy")[0];
    if (pol) {
      for (const [col, key] of [
        ["minPwdLength", "min_pwd_length"],
        ["maxPwdAge", "max_pwd_age_days"],
        ["lockoutThreshold", "lockout_threshold"],
        ["lockoutDuration", "lockout_duration_min"],
      ] as const) {
        const v = str(pol, col);
        if (v) c.setField(domainId, key, v);
      }
    }
  }

  // ---- computers & domain controllers --------------------------------------
  for (const r of rows("Computers")) {
    const sam = str(r, "sAMAccountName");
    const fqdn = str(r, "dNSHostName")?.toLowerCase();
    const sid = str(r, "objectSid");
    const ikeys: IdentityKey[] = [];
    if (sid) ikeys.push({ kind: "ad_sid", value: sid, is_primary: true });
    if (fqdn) ikeys.push({ kind: "fqdn", value: fqdn, is_primary: !sid });
    if (sam) ikeys.push({ kind: "account_sam", value: sam.toLowerCase(), is_primary: false });
    if (!ikeys.length) continue;
    const id = c.resolveOrCreate(ikeys, (nid) =>
      node(nid, hostKindFromOs(str(r, "operatingSystem")), fqdn ?? sam ?? sid ?? "computer", ikeys, p),
    );
    const os = [str(r, "operatingSystem"), str(r, "operatingSystemVersion")].filter(Boolean).join(" ");
    if (os) c.setField(id, "os_version", os);
    // LAPS presence (SharpHound hasLaps equivalent) for ReadLAPSPassword gating.
    if (str(r, "ms-Mcs-AdmPwdExpirationTime") || str(r, "msLAPS-PasswordExpirationTime")) {
      c.setField(id, "laps_installed", true);
    }
    const dn = str(r, "distinguishedName");
    if (sid) bySid.set(sid, id);
    if (sam) bySam.set(sam.toLowerCase(), id);
    if (fqdn) byFqdn.set(fqdn, id);
    if (dn) byDn.set(dn.toLowerCase(), id);
    s.nodes++;
    s.hosts++;
  }
  for (const r of rows("DomainControllers")) {
    const sam = str(r, "sAMAccountName");
    const fqdn = str(r, "dNSHostName")?.toLowerCase();
    const ikeys: IdentityKey[] = [];
    if (fqdn) ikeys.push({ kind: "fqdn", value: fqdn, is_primary: true });
    if (sam) ikeys.push({ kind: "account_sam", value: sam.toLowerCase(), is_primary: false });
    if (!ikeys.length) continue;
    const id = c.resolveOrCreate(ikeys, (nid) => node(nid, "domain_controller", fqdn ?? sam ?? "dc", ikeys, p));
    // A name in the DC list upgrades the kind even if Computers saw it first.
    const existing = c.nodes().find((n) => n.id === id);
    if (existing && existing.kind !== "domain_controller") c.upsertNode({ ...existing, kind: "domain_controller" });
    c.setField(id, "network_role", "domain_controller");
    c.setField(id, "is_tier_zero", true);
    if (domainId) addEdge("dc_for", id, domainId);
    for (const ip of (str(r, "dcip") ?? "").split(/\s+/).filter(Boolean)) {
      c.addIdentityKey(id, { kind: "ip_address", value: ip, is_primary: false });
    }
    const os = [str(r, "operatingSystem"), str(r, "operatingSystemVersion")].filter(Boolean).join(" ");
    if (os) c.setField(id, "os_version", os);
    if (sam) bySam.set(sam.toLowerCase(), id);
    if (fqdn) byFqdn.set(fqdn, id);
    s.hosts++;
  }

  // ---- users ----------------------------------------------------------------
  for (const r of rows("Users")) {
    const sam = str(r, "sAMAccountName");
    const sid = str(r, "objectSid");
    const upn = str(r, "userPrincipalName")?.toLowerCase();
    const ikeys: IdentityKey[] = [];
    if (sid) ikeys.push({ kind: "ad_sid", value: sid, is_primary: true });
    if (upn) ikeys.push({ kind: "account_upn", value: upn, is_primary: false });
    if (sam) ikeys.push({ kind: "account_sam", value: sam.toLowerCase(), is_primary: !sid && !upn });
    if (!ikeys.length) continue;
    const id = c.resolveOrCreate(ikeys, (nid) => node(nid, "user_account", sam ?? upn ?? sid ?? "user", ikeys, p));
    if (sam) c.setField(id, "sam", sam);
    if (upn) c.setField(id, "upn", upn);
    if (str(r, "adminCount") === "1") c.setField(id, "admin_count", true);
    if (str(r, "description")) c.setField(id, "description", str(r, "description"));
    const dn = str(r, "distinguishedName");
    if (sid) bySid.set(sid, id);
    if (sam) bySam.set(sam.toLowerCase(), id);
    if (dn) byDn.set(dn.toLowerCase(), id);
    s.nodes++;
  }

  // ---- groups -----------------------------------------------------------------
  for (const r of rows("DomainGroups")) {
    const sam = str(r, "sAMAccountName");
    const sid = str(r, "objectSid");
    const dn = str(r, "dn");
    const ikeys: IdentityKey[] = [];
    if (sid) ikeys.push({ kind: "ad_sid", value: sid, is_primary: true });
    if (sam) ikeys.push({ kind: "account_sam", value: sam.toLowerCase(), is_primary: !sid });
    if (!ikeys.length) continue;
    const id = c.resolveOrCreate(ikeys, (nid) => node(nid, "group", sam ?? sid ?? "group", ikeys, p));
    if (str(r, "description")) c.setField(id, "description", str(r, "description"));
    if (str(r, "adminCount") === "1") { c.setField(id, "admin_count", true); c.setField(id, "is_tier_zero", true); }
    if (sid) bySid.set(sid, id);
    if (sam) bySam.set(sam.toLowerCase(), id);
    if (dn) byDn.set(dn.toLowerCase(), id);
    s.nodes++;
  }

  // ---- OUs & GPOs ---------------------------------------------------------------
  for (const r of rows("Domain_OUs")) {
    const dn = str(r, "dn");
    const name = str(r, "ou") ?? dn;
    if (!dn || !name) continue;
    const id = c.resolveOrCreate([{ kind: "ad_dn", value: dn.toLowerCase(), is_primary: true }], (nid) =>
      node(nid, "organizational_unit", name, [{ kind: "ad_dn", value: dn.toLowerCase(), is_primary: true }], p),
    );
    byDn.set(dn.toLowerCase(), id);
    if (domainId) addEdge("contains_ou", domainId, id);
    s.nodes++;
  }
  const gpoByGuid = new Map<string, string>();
  for (const r of rows("GPO")) {
    const dn = str(r, "dn") ?? "";
    const guid = (dn.match(/\{([0-9a-fA-F-]+)\}/)?.[1] ?? "").toLowerCase();
    const name = str(r, "displayName") ?? guid;
    if (!guid) continue;
    const id = c.resolveOrCreate([{ kind: "ad_gpo_guid", value: guid, is_primary: true }], (nid) =>
      node(nid, "gpo", name, [{ kind: "ad_gpo_guid", value: guid, is_primary: true }], p),
    );
    gpoByGuid.set(guid, id);
    s.nodes++;
  }
  for (const r of rows("GPLink")) {
    const gpo = gpoByGuid.get((str(r, "GPO_GUID") ?? "").toLowerCase());
    const targetDn = str(r, "ObjectDN")?.toLowerCase();
    if (!gpo || !targetDn) continue;
    const tgt = targetDn.startsWith("dc=") ? domainId : byDn.get(targetDn);
    if (!tgt) continue;
    addEdge("gpo_applies_to", gpo, tgt, {
      enabled: str(r, "LinkEnabled") === "true",
      link_order: str(r, "LinkOrder"),
      block_inheritance: str(r, "BlockInheritance") === "1",
    });
  }

  // ---- user flag tables (set fields on the account node) -------------------------
  const userByRow = (r: Record<string, unknown>): string | undefined => {
    const sam = str(r, "sAMAccountName")?.toLowerCase();
    return sam ? bySam.get(sam) : undefined;
  };
  const flagUsers = (table: string, apply: (id: string, r: Record<string, unknown>) => void): void => {
    for (const r of rows(table)) {
      const id = userByRow(r);
      if (id) apply(id, r);
    }
  };
  flagUsers("Disabled_Users", (id) => c.setField(id, "enabled", false));
  flagUsers("Locked_Users", (id) => c.setField(id, "locked_out", true));
  flagUsers("NoExpirePasswords_Users", (id) => c.setField(id, "password_never_expires", true));
  flagUsers("admincount_Users", (id) => c.setField(id, "admin_count", true));
  flagUsers("SIDHistory_User", (id, r) => {
    const sh = str(r, "sidHistory") ?? str(r, "sIDHistory");
    c.setField(id, "sid_history", sh ? [sh] : ["present"]);
  });
  flagUsers("AsReproast_User", (id) => c.setField(id, "asrep_roastable", true));
  flagUsers("SensitiveDelegate_User", (id) => c.setField(id, "delegation_sensitive", true));

  // SPNs: collected across the SPN and Kerberoast tables, applied once per account.
  const spnBySam = new Map<string, string[]>();
  const kerbSams = new Set<string>();
  for (const r of rows("SPN")) {
    const sam = str(r, "sAMAccountName")?.toLowerCase();
    const spn = str(r, "servicePrincipalName");
    if (sam && spn) (spnBySam.get(sam) ?? spnBySam.set(sam, []).get(sam)!).push(spn);
  }
  for (const r of rows("Kerberoast_User")) {
    const sam = str(r, "sAMAccountName")?.toLowerCase();
    const spn = str(r, "servicePrincipalName");
    if (!sam) continue;
    kerbSams.add(sam);
    if (spn) (spnBySam.get(sam) ?? spnBySam.set(sam, []).get(sam)!).push(spn);
  }
  for (const [sam, spns] of spnBySam) {
    const id = bySam.get(sam);
    if (id) c.setField(id, "spn", [...new Set(spns)]);
  }
  for (const sam of kerbSams) {
    const id = bySam.get(sam);
    if (id) c.setField(id, "kerberoastable", true);
  }

  // ---- computer flag tables --------------------------------------------------------
  const computerByRow = (r: Record<string, unknown>): string | undefined => {
    const sam = str(r, "sAMAccountName")?.toLowerCase();
    return sam ? bySam.get(sam) : undefined;
  };
  for (const r of rows("UnconstrainedDeligation")) {
    const id = computerByRow(r);
    if (id) { c.setField(id, "unconstrained_delegation", true); c.setField(id, "delegation", "unconstrained"); }
  }
  for (const r of rows("MS17_Candidates")) {
    const id = computerByRow(r);
    if (id) c.setField(id, "ms17_010", true);
  }
  for (const r of rows("Pre2k_Candidates")) {
    const id = computerByRow(r);
    if (id) c.setField(id, "pre2k", true);
  }
  for (const r of rows("ConstrainedDeligation")) {
    const id = computerByRow(r) ?? userByRow(r);
    if (!id) continue;
    c.setField(id, "delegation", "constrained");
    const uac = str(r, "userAccountControl") ?? "";
    if (uac.includes("TRUSTED_TO_AUTH_FOR_DELEGATION")) c.setField(id, "protocol_transition", true);
    const targets = (str(r, "msDS-AllowedToDelegateTo") ?? "").split(/\s*[|,]\s*/).filter(Boolean);
    if (targets.length) {
      c.setField(id, "constrained_targets", targets);
      for (const spn of targets) {
        const fqdn = spn.split("/")[1]?.split(":")[0]?.toLowerCase();
        const tgt = fqdn && byFqdn.get(fqdn);
        if (tgt) addEdge("allowed_to_delegate", id, tgt);
      }
    }
  }
  for (const r of rows("RBCD")) {
    const tgtId = computerByRow(r);
    const psid = str(r, "AllowedPrincipalSID");
    const src = psid ? bySid.get(psid) : undefined;
    if (tgtId && src) addEdge("allowed_to_act", src, tgtId);
  }

  // ---- DNS: extra IPs onto known hosts -----------------------------------------------
  for (const r of rows("All_DNS")) {
    const name = str(r, "name")?.toLowerCase();
    const ip = str(r, "dnsRecord");
    if (!name || !ip) continue;
    const id =
      byFqdn.get(`${name}.${domainName}`) ?? bySam.get(`${name}$`) ?? byFqdn.get(name);
    if (id) c.addIdentityKey(id, { kind: "ip_address", value: ip, is_primary: false });
  }

  // ---- membership ----------------------------------------------------------------------
  // A member DN we have not seen becomes a stub node typed by MemberType.
  const stubKind = (t: string): NodeKind =>
    t.toLowerCase() === "group" ? "group" : t.toLowerCase() === "computer" ? "computer_account" : "user_account";
  const resolveDn = (dn: string, label?: string, kindHint?: string): string | undefined => {
    const hit = byDn.get(dn.toLowerCase());
    if (hit) return hit;
    if (!label) return undefined;
    const ikeys: IdentityKey[] = [{ kind: "ad_dn", value: dn.toLowerCase(), is_primary: true }];
    const id = c.resolveOrCreate(ikeys, (nid) => node(nid, stubKind(kindHint ?? ""), label, ikeys, p));
    byDn.set(dn.toLowerCase(), id);
    s.nodes++;
    return id;
  };
  for (const r of rows("GroupMembership")) {
    const gdn = str(r, "GroupDN");
    const mdn = str(r, "MemberDN");
    if (!gdn || !mdn) continue;
    const g = resolveDn(gdn, str(r, "Group"), "group");
    const m = resolveDn(mdn, str(r, "Member"), str(r, "MemberType"));
    if (g && m) addEdge("member_of", m, g);
  }
  // The privileged-group tables ("Domain Admins", "Enterprise Admins", …) carry
  // members GroupMembership may miss; memberOf holds the group name.
  for (const t of ["Domain Admins", "Enterprise Admins", "administrators", "Backup Operators"]) {
    const gid = bySam.get(t.toLowerCase());
    if (!gid) continue;
    for (const r of rows(t)) {
      const mid = userByRow(r) ?? (str(r, "distinguishedName") ? byDn.get(str(r, "distinguishedName")!.toLowerCase()) : undefined);
      if (mid) addEdge("member_of", mid, gid);
    }
  }

  // ---- security descriptors ---------------------------------------------------------------
  // A principal Pughound prints as a bare SID becomes a readable stub.
  const resolvePrincipal = (sid: string): string => {
    const hit = bySid.get(sid);
    if (hit) return hit;
    const rid = sid.startsWith(`${domainSid}-`) ? sid.slice(domainSid!.length + 1) : null;
    const label = WELL_KNOWN_SID[sid] ?? (rid ? WELL_KNOWN_RID[rid] : undefined) ?? sid;
    const ikeys: IdentityKey[] = [{ kind: "ad_sid", value: sid, is_primary: true }];
    const id = c.resolveOrCreate(ikeys, (nid) => node(nid, "group", label, ikeys, p));
    bySid.set(sid, id);
    s.nodes++;
    return id;
  };
  for (const r of rows("DCSync_Rights")) {
    const sid = str(r, "PrincipalSID");
    const right = str(r, "Right");
    if (!sid || !right || !domainId) continue;
    addEdge("dc_sync", resolvePrincipal(sid), domainId, { right });
  }
  // AdminSDHolder ACEs guard every protected object in the domain — target the
  // domain node so the path engine routes through them.
  for (const r of rows("AdminSDHolder")) {
    const sid = str(r, "PrincipalSID");
    if (!sid || !domainId) continue;
    const src = resolvePrincipal(sid);
    if (str(r, "ACE_Type") === "Owner") addEdge("owns", src, domainId, { object: "AdminSDHolder" });
    for (const right of (str(r, "Rights") ?? "").split(" | ")) {
      const kind = aceRightEdge(right);
      if (kind) addEdge(kind, src, domainId, { object: "AdminSDHolder" });
    }
  }

  // ---- trusts --------------------------------------------------------------------------------
  for (const r of rows("DomainTrusts")) {
    const partner = str(r, "trustPartner");
    if (!partner || !domainId) continue;
    const ik: IdentityKey[] = [{ kind: "domain_name", value: partner.toLowerCase(), is_primary: true }];
    const tgt = c.resolveOrCreate(ik, (nid) => node(nid, "domain", partner, ik, p));
    const tf: Record<string, unknown> = {};
    if (str(r, "trustDirection")) tf["direction"] = str(r, "trustDirection");
    if (str(r, "trustType")) tf["trust_type"] = str(r, "trustType");
    if (str(r, "trustAttributes")) tf["attributes"] = str(r, "trustAttributes");
    addEdge("trusts", domainId, tgt, Object.keys(tf).length ? tf : undefined);
    s.nodes++;
  }

  // ---- full DACL dump (ACLs table) ----------------------------------------------------------
  // SharpHound-parity derivation (~/Pughound docs/store-contract.md): only
  // Allow ACEs become edges; filtered trustees dropped; inherited ACEs must
  // match the target's schema class (IsAceInheritedFrom port).
  const aclLapsGuids = new Set<string>();
  for (const r of rows("SchemaAttrs")) {
    const name = (str(r, "Name") ?? "").toLowerCase();
    const guid = (str(r, "SchemaIDGUID") ?? "").toLowerCase();
    if (guid && (name === "ms-mcs-admpwd" || name === "ms-laps-password" || name === "ms-laps-encryptedpassword")) {
      aclLapsGuids.add(guid);
    }
  }
  for (const r of rows("ACLs")) {
    const dn = str(r, "DN");
    if (!dn) continue;
    const objClass = (str(r, "ObjectClass") ?? "").toLowerCase();
    const targetClass = OBJECT_CLASS[objClass];
    const sid = str(r, "SID");
    const aceType = (str(r, "ACE_Type") ?? "").toLowerCase();
    // Target: reuse the indexed node when known, else a typed stub.
    let target = byDn.get(dn.toLowerCase());
    if (!target) {
      const label = str(r, "Object") ?? dn;
      const keys: IdentityKey[] = [{ kind: "ad_dn", value: dn.toLowerCase(), is_primary: true }];
      if (objClass === "domaindns" && domainSid) keys.push({ kind: "ad_sid", value: domainSid, is_primary: false });
      target = c.resolveOrCreate(keys, (nid) => node(nid, phNodeKind(objClass), label, keys, p));
      byDn.set(dn.toLowerCase(), target);
      s.nodes++;
    }
    if (aceType === "owner") {
      if (sid && !FILTERED_ACE_SIDS.has(sid.toUpperCase())) addEdge("owns", resolvePrincipal(sid), target);
      continue;
    }
    if (!sid || !isAllowAce(aceType) || FILTERED_ACE_SIDS.has(sid.toUpperCase())) continue;
    if (!aceAppliesToTarget(str(r, "Flags"), (str(r, "InheritedObjectType") ?? "").toLowerCase(), targetClass)) continue;
    const rights = str(r, "Rights") ?? "";
    const objType = (str(r, "ObjectType") ?? "").toLowerCase();
    for (const edgeName of aclEdgeNames(rights, objType, targetClass, aclLapsGuids)) {
      const kind = phAceKind(edgeName);
      if (!kind) continue;
      addEdge(kind, resolvePrincipal(sid), target, { rights, object_type: objType || undefined, auto: edgeName === "AutoEnroll" ? true : undefined });
    }
  }

  // ---- ForceChangePassword tables ------------------------------------------------------------
  for (const r of rows("ForceChangePassword_ACL")) {
    const attackerSid = str(r, "AttackerSID");
    const dn = str(r, "TargetDN");
    if (!attackerSid || !dn) continue;
    const tgt = byDn.get(dn.toLowerCase());
    if (tgt) addEdge("force_change_password", resolvePrincipal(attackerSid), tgt, { right: str(r, "Right") });
  }
  for (const r of rows("ForceChangePassword_Users")) {
    const id = userByRow(r);
    if (id) c.setField(id, "must_change_password", true);
  }

  // ---- gMSA / sMSA ----------------------------------------------------------------------------
  for (const r of rows("GMSA")) {
    const sam = str(r, "sAMAccountName");
    const dn = str(r, "distinguishedName");
    if (!sam && !dn) continue;
    const ik: IdentityKey[] = dn ? [{ kind: "ad_dn", value: dn.toLowerCase(), is_primary: true }] : [{ kind: "account_sam", value: sam!.toLowerCase(), is_primary: true }];
    const id = c.resolveOrCreate(ik, (nid) => node(nid, "service_account", sam ?? dn ?? "gmsa", ik, p));
    if (sam) bySam.set(sam.toLowerCase(), id);
    if (dn) byDn.set(dn.toLowerCase(), id);
    c.setField(id, "gmsa", true);
    s.nodes++;
  }
  for (const r of rows("GMSA_Readers")) {
    const gmsaDn = str(r, "GMSA_DN");
    const readerSid = str(r, "ReaderSID");
    if (!gmsaDn || !readerSid) continue;
    const tgt = byDn.get(gmsaDn.toLowerCase());
    if (tgt) addEdge("read_gmsa_password", resolvePrincipal(readerSid), tgt);
  }

  // ---- PSOs → domain fields ---------------------------------------------------------------------
  const psos = rows("PSO").map((r) => str(r, "cn")).filter((v): v is string => !!v);
  if (psos.length && domainId) c.setField(domainId, "psos", psos);

  // ---- Azure / Entra ID ----------------------------------------------------------------------------
  applyPughoundAzure(c, { rows }, { domainName, p, s, addEdge });

  // ---- LAPS passwords (sealed into the vault when held) ------------------------------------------
  for (const r of rows("LAPS_Passwords")) {
    const passCol = Object.keys(r).find((k) => /pass/i.test(k));
    const hostCol = Object.keys(r).find((k) => /sam|computer|host|name/i.test(k) && !/pass/i.test(k));
    const secret = passCol ? str(r, passCol) : undefined;
    if (!secret) continue;
    const hostSam = hostCol ? str(r, hostCol)?.toLowerCase() : undefined;
    const hostId = hostSam ? bySam.get(hostSam) ?? bySam.get(`${hostSam}$`) : undefined;
    const sealed = ctx.seal?.(secret);
    c.addCredential({
      id: `cred:pughound-laps:${hostSam ?? secret.slice(0, 8)}`,
      username: `${hostSam ?? "host"}$ (LAPS)`,
      domain: domainName,
      credential_type: "password_plaintext",
      source: "dump",
      validity: "unknown",
      validity_as_of: ctx.now,
      secret_sealed: sealed,
      belongs_to: hostId,
      tested_against: [],
      provenance: p,
    });
    if (hostId) c.setField(hostId, "laps_pw_known", true);
    s.credentials++;
  }

  return s;
}

// ---- Pughound Azure / Entra ID tables -------------------------------------------
//
// AzureAD_* tables (~/Pughound docs/store-contract.md). Users/SPs become
// cloud_identity, devices/apps/tenant become cloud_resource, groups and
// directory roles become group nodes; membership/ownership/role edges ride
// the same member_of/owns kinds the AD side uses, so path reasoning works
// across the hybrid graph.
function applyPughoundAzure(
  c: Campaign,
  tables: { rows: (name: string) => Record<string, unknown>[] },
  ctx: { domainName: string; p: Provenance; s: ImportSummary; addEdge: (kind: GraphEdge["kind"], source: string, target: string, fields?: Record<string, unknown>) => void },
): void {
  const { rows } = tables;
  const { p, s, addEdge } = ctx;
  const byId = new Map<string, string>(); // azure object id (GUID) → node id

  const azNode = (
    objectId: string | undefined,
    kind: NodeKind,
    label: string,
    extraKeys: IdentityKey[] = [],
  ): string | undefined => {
    if (!objectId) return undefined;
    const hit = byId.get(objectId.toLowerCase());
    if (hit) return hit;
    const ikeys: IdentityKey[] = [{ kind: "azure_object_id", value: objectId.toLowerCase(), is_primary: true }, ...extraKeys];
    const id = c.resolveOrCreate(ikeys, (nid) => node(nid, kind, label, ikeys, p));
    byId.set(objectId.toLowerCase(), id);
    s.nodes++;
    return id;
  };

  // Tenant (organization).
  const org = rows("AzureAD_Organization")[0];
  let tenantId: string | null = null;
  if (org) {
    tenantId = azNode(str(org, "ID"), "cloud_resource", str(org, "DisplayName") ?? "tenant") ?? null;
    if (tenantId && str(org, "VerifiedDomains")) c.setField(tenantId, "verified_domains", str(org, "VerifiedDomains"));
    if (tenantId) c.setField(tenantId, "azure_tenant", true);
  }

  for (const r of rows("AzureAD_Users")) {
    const upn = (str(r, "userPrincipalName") ?? "").toLowerCase();
    const id = azNode(str(r, "id"), "cloud_identity", str(r, "displayName") ?? upn ?? "azure-user",
      upn ? [{ kind: "account_upn", value: upn, is_primary: false }] : []);
    if (id && upn) c.setField(id, "upn", upn);
  }
  for (const r of rows("AzureAD_Groups")) {
    azNode(str(r, "id"), "group", str(r, "displayName") ?? "azure-group");
  }
  for (const r of rows("AzureAD_Devices")) {
    azNode(str(r, "id"), "cloud_resource", str(r, "displayName") ?? "azure-device");
  }
  for (const r of rows("AzureAD_ServicePrincipals")) {
    const appId = (str(r, "appId") ?? "").toLowerCase();
    const id = azNode(str(r, "id"), "cloud_identity", str(r, "displayName") ?? "service-principal",
      appId ? [{ kind: "azure_app_id", value: appId, is_primary: false }] : []);
    if (id) c.setField(id, "service_principal", true);
  }
  for (const r of rows("AzureAD_DirectoryRoles")) {
    const id = azNode(str(r, "id"), "group", str(r, "displayName") ?? "azure-role");
    if (id) c.setField(id, "azure_role", true);
  }
  for (const r of rows("AzureAD_Applications")) {
    const appId = (str(r, "AppID") ?? "").toLowerCase();
    const id = azNode(str(r, "ObjectID"), "cloud_resource", str(r, "DisplayName") ?? "app-registration",
      appId ? [{ kind: "azure_app_id", value: appId, is_primary: false }] : []);
    if (id) c.setField(id, "app_registration", true);
  }

  // Role definitions: templateId is what roleAssignments reference as RoleID.
  const roleNameByTemplate = new Map<string, string>();
  for (const r of rows("AzureAD_RoleDefinitions")) {
    const templateId = (str(r, "TemplateID") ?? "").toLowerCase();
    const name = str(r, "DisplayName");
    if (templateId && name) roleNameByTemplate.set(templateId, name);
  }

  // Membership / ownership / roles.
  for (const r of rows("AzureAD_GroupMembers")) {
    const g = azNode(str(r, "GroupID"), "group", str(r, "GroupName") ?? "azure-group");
    const m = byId.get((str(r, "MemberID") ?? "").toLowerCase());
    if (g && m) addEdge("member_of", m, g);
  }
  for (const [table, kind, label, nameCol, idCol] of [
    ["AzureAD_GroupOwners", "group", "azure-group", "GroupName", "GroupID"],
    ["AzureAD_ServicePrincipalOwners", "cloud_identity", "service-principal", "SPName", "SPObjectID"],
    ["AzureAD_ApplicationOwners", "cloud_resource", "app-registration", "AppName", "AppObjectID"],
    ["AzureAD_DeviceRegisteredOwners", "cloud_resource", "azure-device", "DeviceName", "DeviceID"],
  ] as const) {
    for (const r of rows(table)) {
      const tgt = azNode(str(r, idCol), kind, str(r, nameCol) ?? label);
      const owner = byId.get((str(r, "OwnerID") ?? "").toLowerCase());
      if (tgt && owner) addEdge("owns", owner, tgt);
    }
  }
  for (const r of rows("AzureAD_RoleAssignments")) {
    const roleId = str(r, "RoleID") ?? "";
    const principal = byId.get((str(r, "PrincipalID") ?? "").toLowerCase());
    if (!principal) continue;
    const roleName = str(r, "RoleName") || roleNameByTemplate.get(roleId.toLowerCase()) || roleId;
    // Roles are groups the principal is a member of — path engine treats them
    // like any other membership. Global Admin gets the high-value marker.
    const role = azNode(roleId || roleName, "group", roleName);
    if (!role) continue;
    c.setField(role, "azure_role", true);
    if (roleId.toLowerCase() === "62e90394-69f5-4237-9190-012177145e10") c.setField(role, "is_tier_zero", true);
    addEdge("member_of", principal, role);
  }

  // Federated identity credentials: abuse-relevant (workload identity), kept
  // as structured fields on the app node.
  for (const r of rows("AzureAD_FederatedIdentityCredentials")) {
    const appId = byId.get((str(r, "AppObjectID") ?? "").toLowerCase());
    if (!appId) continue;
    const fic = [str(r, "Issuer"), str(r, "Subject")].filter(Boolean).join(" | ");
    if (!fic) continue;
    const existing = c.nodes().find((n) => n.id === appId);
    const list = Array.isArray(existing?.fields["fics"]) ? [...(existing!.fields["fics"] as string[])] : [];
    if (!list.includes(fic)) list.push(fic);
    c.setField(appId, "fics", list);
  }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export type ImportFormat = "nmap" | "bloodhound" | "netexec" | "nessus" | "secretsdump" | "pughound";

export function detectFormat(name: string, content: string): ImportFormat {
  const n = name.toLowerCase();
  const t = content.trimStart();
  if (n.endsWith(".nessus") || /<(NessusClientData|ReportHost)/.test(t)) return "nessus";
  if (t.startsWith("{") || t.startsWith("[")) {
    // Pughound's consolidated report and per-table files are both JSON — sniff
    // their shapes before falling through to BloodHound.
    if (t.includes('"categories"') || (t.includes('"query"') && t.includes('"columns"') && t.includes('"rows"')))
      return "pughound";
    return "bloodhound";
  }
  if (t.startsWith("<")) return "nmap";
  if (n.endsWith(".ntds") || /^[^:\n]*:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::/m.test(t)) return "secretsdump";
  return "netexec";
}

const addSummary = (a: ImportSummary, b: ImportSummary): ImportSummary => ({
  hosts: a.hosts + b.hosts,
  services: a.services + b.services,
  edges: a.edges + b.edges,
  nodes: a.nodes + b.nodes,
  credentials: a.credentials + b.credentials,
});

export function importFiles(c: Campaign, files: { name: string; content: string }[], ctx: ImportCtx): ImportSummary {
  let total = empty();
  const bh: BloodHoundFile[] = [];
  const ph: PughoundTable[] = [];
  for (const f of files) {
    const fmt = detectFormat(f.name, f.content);
    if (fmt === "bloodhound") {
      try {
        bh.push(parseBloodhound(f.content));
      } catch {
        /* */
      }
    } else if (fmt === "pughound") {
      try {
        ph.push(...parsePughound(f.content));
      } catch {
        /* */
      }
    } else if (fmt === "nessus") {
      total = addSummary(total, applyNessus(c, parseNessus(f.content), ctx));
    } else if (fmt === "nmap") {
      total = addSummary(total, applyNmap(c, parseNmap(f.content), ctx));
    } else if (fmt === "secretsdump") {
      total = addSummary(total, applySecretsdump(c, parseSecretsdump(f.content), ctx));
    } else {
      total = addSummary(total, applyNetexec(c, parseNetexec(f.content), ctx));
    }
  }
  if (bh.length)
      total = addSummary(total, applyBloodhound(c, bh, ctx));
  if (ph.length)
      total = addSummary(total, applyPughound(c, ph, ctx));
  return total;
}
