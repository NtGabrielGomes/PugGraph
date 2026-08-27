// Attack paths emerge from the graph's structure, not from manual annotation.
// We project the campaign into a weighted directed graph of attacker-traversable
// edges and compute the *cheapest* path from each compromised foothold to each
// goal — high-value kinds plus anything the team flags `goal`/`crown-jewel`.
// Weighting (per edge-kind difficulty × confidence) means the path a real
// operator would take ranks above a longer-but-flimsier one; `avoid` lets you
// ask "what if this chokepoint is blocked (EDR, 2FA)?".

import Graph from "graphology";
import { isHighValue, isTraversable, type Credential, type EdgeKind, type GraphEdge, type GraphNode } from "@/domain/types";
import { edgeRisk, techniqueFor } from "@/graph/techniques";

export interface AttackPath {
  from: string;
  to: string;
  /** Ordered node ids from foothold to goal. */
  hops: string[];
  /** Total traversal cost (lower = easier / more reliable). */
  cost: number;
  /** The edge kind traversed at each hop (hops.length - 1 entries). */
  edges: EdgeKind[];
}

// Per-kind base difficulty: privilege/credential edges are cheap (a real
// abuse), raw network reachability is expensive (still has to be weaponized).
const KIND_COST: Partial<Record<EdgeKind, number>> = {
  member_of: 0.5, member_of_domain: 0.5, dc_for: 0.5, dc_sync: 0.5,
  admin_to: 1, has_local_admin: 1, generic_all: 1, owns: 1, has_session: 1,
  credential_valid_for: 1, hosts_vm: 1, vm_hosted_on: 1, runs_container: 1,
  listens_on: 1, pivot_established: 1, lateral_movement: 1,
  shadow_credentials: 1, allowed_to_act: 1, allowed_to_delegate: 1,
  read_gmsa_password: 1, read_laps_password: 1, manage_ca: 1,
  can_ps_remote: 1.2, can_ssh: 1.2, sql_admin: 1.2,
  write_dacl: 1.5, force_change_password: 1.5, add_member: 1.5, priv_esc: 1.5,
  dumped_from: 1.5, can_rdp: 1.5, execute_dcom: 1.5, linked_gpo: 1.5, exploitable_via: 1.5,
  write_spn: 1.5, coerce: 1.5,
  trusts: 2,
  reachable_from: 2.5, connects_to: 2.5, routes_through: 3,
  // ACL abuse + delegation/roasting (cheap, real abuses).
  generic_write: 1.2, write_owner: 1.5, all_extended_rights: 1, write_gp_link: 1.5, add_self: 1.2,
  unconstrained_delegation: 1, can_kerberoast: 1.2, can_asrep_roast: 1.2,
  // ADCS chain: enroll into a vuln template, the cert authenticates as the target.
  enroll: 1, enroll_on_behalf_of: 1.2, authenticates_as: 0.5,
  // GPO mass code-exec, SQL linked-server, coercion relay, web-app host pivot.
  gpo_applies_to: 1, sql_link: 1.2, relay_to: 1.5, hosted_on: 1,
  custom: 2,
};
const DEFAULT_COST = 2;
const CONF_MULT: Record<string, number> = { confirmed: 1, suspected: 1.6, possible: 2.4 };

/** How to rank routes: cheapest to pull off, quietest (avoid loud TTPs / EDR /
 * MFA targets), or most reliable (penalize unconfirmed relations harder). */
export type Objective = "fast" | "quiet" | "reliable";

const edgeCost = (e: GraphEdge, objective: Objective = "fast"): number => {
  // A relay needs the target's SMB/LDAP signing OFF; signing required ⇒ impossible.
  if (e.kind === "relay_to" && e.fields?.["signing_required"] === true) return Infinity;
  const conf = CONF_MULT[e.confidence] ?? 1.6;
  let cost = (KIND_COST[e.kind] ?? DEFAULT_COST) * conf;
  if (e.kind === "trusts") {
    if (e.fields?.["sid_filtering"] === true) cost *= 3; // SID filtering blocks SID-history abuse
    if (e.fields?.["trust_keys_known"] === true) cost *= 0.5; // a captured trust key is cheap
  }
  if (objective === "quiet") cost *= 1 + edgeRisk(e.kind);
  else if (objective === "reliable") cost *= conf; // double-weight low confidence
  return cost;
};

const GOAL_TAGS = new Set(["goal", "crown-jewel"]);
const isCompromised = (n: GraphNode): boolean =>
  n.compromise_level !== "unknown" && n.compromise_level !== "none";

// Tier-0 = game over: the well-known privileged RIDs (Domain/Enterprise/Schema
// Admins, Domain Controllers, GPO Creators), krbtgt, anything flagged tier-zero /
// adminCount, and the high-value kinds — PLUS every principal that is, transitively
// over group membership, a member of one of those. Owning ANY of these is the win,
// not "reaching the DC node".
const TIER0_RID = /-(512|516|518|519|520)$/;

function tier0Set(nodes: GraphNode[], edges: GraphEdge[]): Set<string> {
  const t0 = new Set<string>();
  for (const n of nodes) {
    const sid = n.identity_keys.find((k) => k.kind === "ad_sid")?.value ?? "";
    const isApex =
      isHighValue(n.kind) ||
      n.fields["is_tier_zero"] === true ||
      n.fields["tier_zero"] === true ||
      n.fields["admin_count"] === true ||
      n.fields["is_krbtgt"] === true ||
      (n.label || "").toLowerCase() === "krbtgt" ||
      TIER0_RID.test(sid);
    if (isApex) t0.add(n.id);
  }
  // Propagate down group membership: a member of a Tier-0 group is Tier-0.
  const memberOf = edges.filter((e) => e.kind === "member_of");
  let changed = true;
  while (changed) {
    changed = false;
    for (const e of memberOf) {
      if (t0.has(e.target) && !t0.has(e.source)) {
        t0.add(e.source);
        changed = true;
      }
    }
  }
  return t0;
}

/** The set of goal node ids: Tier-0 closure + operator-flagged #goal/#crown-jewel. */
export function goalNodes(nodes: GraphNode[], edges: GraphEdge[]): Set<string> {
  const goals = tier0Set(nodes, edges);
  for (const n of nodes) if (n.tags.some((t) => GOAL_TAGS.has(t))) goals.add(n.id);
  return goals;
}

export interface PathOptions {
  /** Node ids to exclude from traversal (blocked chokepoints). */
  avoid?: ReadonlySet<string>;
  /** Restrict footholds to a single starting node. */
  footholdId?: string | null;
  /** Routing objective (default "fast" = cheapest). */
  objective?: Objective;
}

interface EdgeInfo {
  kind: EdgeKind;
  cost: number;
}

/** Build the weighted directed graph of traversable edges, plus a per-pair edge
 * lookup. Keeps the cheapest relation when several connect the same pair. */
export function buildAttackGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  avoid?: ReadonlySet<string>,
  objective: Objective = "fast",
): { g: Graph; info: Map<string, EdgeInfo> } {
  const g = new Graph({ type: "directed", multi: false, allowSelfLoops: false });
  const info = new Map<string, EdgeInfo>();
  for (const n of nodes) if (!avoid?.has(n.id)) g.mergeNode(n.id, { kind: n.kind });
  for (const e of edges) {
    if (!isTraversable(e.kind)) continue;
    if (avoid?.has(e.source) || avoid?.has(e.target)) continue;
    if (!g.hasNode(e.source) || !g.hasNode(e.target)) continue;
    const cost = edgeCost(e, objective);
    if (!Number.isFinite(cost)) continue; // impossible edge (e.g. relay to a signed target)
    const key = `${e.source}->${e.target}`;
    if (g.hasEdge(e.source, e.target)) {
      const prev = info.get(key);
      if (!prev || cost < prev.cost) {
        g.setEdgeAttribute(e.source, e.target, "weight", cost);
        info.set(key, { kind: e.kind, cost });
      }
    } else {
      g.addEdge(e.source, e.target, { weight: cost });
      info.set(key, { kind: e.kind, cost });
    }
  }
  return { g, info };
}

/** Single-source Dijkstra returning the whole shortest-cost tree (dist + predecessor)
 * in ONE pass — so paths to every goal are read off one run per foothold, instead of
 * a fresh bidirectional search per (foothold, goal) pair. */
function dijkstraTree(g: Graph, info: Map<string, EdgeInfo>, source: string): {
  dist: Map<string, number>;
  prev: Map<string, string>;
} {
  const dist = new Map<string, number>([[source, 0]]);
  const prev = new Map<string, string>();
  const done = new Set<string>();
  for (;;) {
    let u: string | null = null;
    let best = Infinity;
    for (const [node, d] of dist) if (!done.has(node) && d < best) { best = d; u = node; }
    if (u === null) break;
    done.add(u);
    g.forEachOutNeighbor(u, (v: string) => {
      const nd = best + (info.get(`${u}->${v}`)?.cost ?? 1);
      if (nd < (dist.get(v) ?? Infinity)) { dist.set(v, nd); prev.set(v, u); }
    });
  }
  return { dist, prev };
}

/** Walk the predecessor chain back from `target` to `source`; [] if disconnected. */
function reconstruct(prev: Map<string, string>, source: string, target: string): string[] {
  const hops = [target];
  let cur = target;
  while (cur !== source && prev.has(cur)) {
    cur = prev.get(cur)!;
    hops.unshift(cur);
  }
  return hops[0] === source ? hops : [];
}

/** Turn a hop list into a costed, edge-kinded AttackPath using the per-pair lookup. */
function toAttackPath(from: string, to: string, hops: string[], info: Map<string, EdgeInfo>): AttackPath {
  let cost = 0;
  const ek: EdgeKind[] = [];
  for (let i = 0; i + 1 < hops.length; i++) {
    const inf = info.get(`${hops[i]}->${hops[i + 1]}`);
    if (inf) { cost += inf.cost; ek.push(inf.kind); }
  }
  return { from, to, hops, cost, edges: ek };
}

/** Cheapest path from every compromised foothold to every goal. Credentials, when
 * supplied, become derived `credential_valid_for` edges so a host you have working
 * creds for is reachable even with no graph edge to it (B7). */
export function surfaceAttackPaths(
  nodes: GraphNode[],
  edges: GraphEdge[],
  opts: PathOptions = {},
  credentials: Credential[] = [],
): AttackPath[] {
  const footholdSet = new Set(nodes.filter(isCompromised).map((n) => n.id));
  const allEdges = [...edges, ...inferAbuseEdges(nodes, edges, footholdSet, credentials)];
  const { g, info } = buildAttackGraph(nodes, allEdges, opts.avoid, opts.objective);
  let footholds = [...footholdSet].filter((id) => g.hasNode(id));
  if (opts.footholdId) footholds = footholds.filter((id) => id === opts.footholdId);
  const goalIds = goalNodes(nodes, edges);
  const goals = nodes.map((n) => n.id).filter((id) => goalIds.has(id) && g.hasNode(id));

  const paths: AttackPath[] = [];
  // One shortest-path tree per foothold yields the cheapest route to EVERY goal.
  for (const from of footholds) {
    const { dist, prev } = dijkstraTree(g, info, from);
    for (const to of goals) {
      if (from === to || !dist.has(to)) continue;
      const hops = reconstruct(prev, from, to);
      if (hops.length <= 1) continue;
      paths.push(toAttackPath(from, to, hops, info));
    }
  }
  // Cheapest (most reliable / closest) first.
  return paths.sort((a, b) => a.cost - b.cost || a.hops.length - b.hops.length);
}

/** Cheapest path to a CHOSEN target node from any foothold (or a given one), even
 * when the target is not a Tier-0 goal — drives "path to here" from the map/UI. */
export function pathTo(
  nodes: GraphNode[],
  edges: GraphEdge[],
  target: string,
  opts: PathOptions = {},
  credentials: Credential[] = [],
): AttackPath | null {
  const footholdSet = new Set(nodes.filter(isCompromised).map((n) => n.id));
  const allEdges = [...edges, ...inferAbuseEdges(nodes, edges, footholdSet, credentials)];
  const { g, info } = buildAttackGraph(nodes, allEdges, opts.avoid, opts.objective);
  if (!g.hasNode(target)) return null;
  let footholds = [...footholdSet].filter((id) => g.hasNode(id) && id !== target);
  if (opts.footholdId) footholds = footholds.filter((id) => id === opts.footholdId);
  let best: AttackPath | null = null;
  for (const from of footholds) {
    const { dist, prev } = dijkstraTree(g, info, from);
    if (!dist.has(target)) continue;
    const hops = reconstruct(prev, from, target);
    if (hops.length <= 1) continue;
    const p = toAttackPath(from, target, hops, info);
    if (!best || p.cost < best.cost) best = p;
  }
  return best;
}

// ---------------------------------------------------------------------------
// Reachability, blast radius, chokepoints — the "what can I touch / who can
// touch this / which node breaks the most paths" questions operators ask most.
// ---------------------------------------------------------------------------

/** Single-source shortest cost from `source` over OUT edges (forward closure). */
function shortestFrom(g: Graph, info: Map<string, EdgeInfo>, source: string): Map<string, number> {
  const dist = new Map<string, number>([[source, 0]]);
  const done = new Set<string>();
  for (;;) {
    let u: string | null = null;
    let best = Infinity;
    for (const [n, d] of dist) if (!done.has(n) && d < best) { best = d; u = n; }
    if (u === null) break;
    done.add(u);
    g.forEachOutNeighbor(u, (v: string) => {
      const nd = best + (info.get(`${u}->${v}`)?.cost ?? 1);
      if (nd < (dist.get(v) ?? Infinity)) dist.set(v, nd);
    });
  }
  dist.delete(source);
  return dist;
}

/** Single-source shortest cost TO `target` over IN edges (reverse closure). */
function shortestTo(g: Graph, info: Map<string, EdgeInfo>, target: string): Map<string, number> {
  const dist = new Map<string, number>([[target, 0]]);
  const done = new Set<string>();
  for (;;) {
    let u: string | null = null;
    let best = Infinity;
    for (const [n, d] of dist) if (!done.has(n) && d < best) { best = d; u = n; }
    if (u === null) break;
    done.add(u);
    g.forEachInNeighbor(u, (v: string) => {
      const nd = best + (info.get(`${v}->${u}`)?.cost ?? 1);
      if (nd < (dist.get(v) ?? Infinity)) dist.set(v, nd);
    });
  }
  dist.delete(target);
  return dist;
}

export interface Reach {
  id: string;
  cost: number;
}

const sortReach = (m: Map<string, number>): Reach[] =>
  [...m.entries()].map(([id, cost]) => ({ id, cost })).sort((a, b) => a.cost - b.cost);

/** Everything reachable FROM a node (its outbound blast radius), cheapest first.
 * Derives field-based abuse edges (roast/delegation) from the source so they count. */
export function reachableFrom(nodes: GraphNode[], edges: GraphEdge[], sourceId: string, opts: PathOptions = {}): Reach[] {
  const allEdges = [...edges, ...inferAbuseEdges(nodes, edges, new Set([sourceId]))];
  const { g, info } = buildAttackGraph(nodes, allEdges, opts.avoid, opts.objective);
  if (!g.hasNode(sourceId)) return [];
  return sortReach(shortestFrom(g, info, sourceId));
}

/** Every node that can REACH a target (its inbound attack surface), cheapest first. */
export function reachersOf(nodes: GraphNode[], edges: GraphEdge[], targetId: string, opts: PathOptions = {}): Reach[] {
  const { g, info } = buildAttackGraph(nodes, edges, opts.avoid, opts.objective);
  if (!g.hasNode(targetId)) return [];
  return sortReach(shortestTo(g, info, targetId));
}

export interface BlastRadius {
  /** Reachable nodes, cheapest first. */
  reached: Reach[];
  /** Of those, the ones that are goals (Tier-0 / flagged). */
  goalsReached: string[];
  count: number;
}

/** "If I own this box, what opens up?" — the forward closure plus which goals fall. */
export function blastRadius(nodes: GraphNode[], edges: GraphEdge[], rootId: string, opts: PathOptions = {}): BlastRadius {
  const reached = reachableFrom(nodes, edges, rootId, opts);
  const goals = goalNodes(nodes, edges);
  return { reached, goalsReached: reached.map((r) => r.id).filter((id) => goals.has(id)), count: reached.length };
}

export interface Chokepoint {
  id: string;
  /** Number of distinct surfaced foothold→goal paths this node sits on (as a pivot). */
  pathsCovered: number;
}

/** Rank the intermediate nodes by how many surfaced goal-paths funnel through them
 * — the single pivots whose hardening (defender) or capture (attacker) matters most. */
export function chokepoints(nodes: GraphNode[], edges: GraphEdge[], opts: PathOptions = {}): Chokepoint[] {
  const paths = surfaceAttackPaths(nodes, edges, opts);
  const tally = new Map<string, number>();
  for (const p of paths) {
    // Intermediate hops only (exclude the foothold start and the goal end).
    for (let i = 1; i + 1 < p.hops.length; i++) {
      const id = p.hops[i]!;
      tally.set(id, (tally.get(id) ?? 0) + 1);
    }
  }
  return [...tally.entries()]
    .map(([id, pathsCovered]) => ({ id, pathsCovered }))
    .sort((a, b) => b.pathsCovered - a.pathsCovered || a.id.localeCompare(b.id));
}

export interface PathStep {
  from: string;
  to: string;
  kind: EdgeKind;
  mitre: string[];
  tool: string;
  note: string;
}

/** Turn a computed path into an ordered, ATT&CK-mapped playbook (one step per hop). */
export function explainPath(path: AttackPath): PathStep[] {
  const steps: PathStep[] = [];
  for (let i = 0; i + 1 < path.hops.length; i++) {
    const kind = path.edges[i] ?? "custom";
    const t = techniqueFor(kind);
    steps.push({
      from: path.hops[i]!,
      to: path.hops[i + 1]!,
      kind,
      mitre: t?.mitre ?? [],
      tool: t?.tool ?? "—",
      note: t?.note ?? "",
    });
  }
  return steps;
}

// ---------------------------------------------------------------------------
// Field → edge inference: the rich tradecraft fields the importers/operators
// capture (kerberoastable, unconstrained delegation, …) become DERIVED traversable
// edges so the path engine actually routes through them. Derived edges are
// synthetic (never persisted); they carry fields.derived so the UI can mark them.
// ---------------------------------------------------------------------------

/** Cumulative detection likelihood of a path: 1 − Π(1 − per-edge risk). The principled
 * companion to cost — additive cost answers "how hard", this answers "how loud", so the
 * UI/report can rank routes by noise and an operator can pick a quiet-but-longer path
 * under a detection budget (B11). Independent of the "quiet" objective, which folds the
 * same risk into edge weight; this exposes the joint probability directly. */
export function pathRisk(path: AttackPath): number {
  let survive = 1;
  for (const k of path.edges) survive *= 1 - edgeRisk(k);
  return 1 - survive;
}

const DERIVED_PROV: GraphNode["provenance"] = {
  author: "",
  source: { kind: "inference" },
  confidence: "suspected",
  first_seen: 0,
  last_verified: 0,
};
const derivedEdge = (
  kind: EdgeKind,
  source: string,
  target: string,
  extra: Record<string, unknown> = {},
): GraphEdge => ({
  id: `derived:${source}|${kind}|${target}`,
  kind,
  source,
  target,
  confidence: "suspected",
  fields: { derived: true, ...extra },
  provenance: DERIVED_PROV,
});

/** ESC1: a template that lets the enrollee supply the subject (SAN), is enrollable
 * by low-priv principals, needs no manager approval, and yields a client-auth cert
 * — any authenticated foothold can enroll a cert for an arbitrary (Tier-0) principal. */
const esc1Abusable = (n: GraphNode): boolean =>
  n.fields["enrollee_supplies_subject"] === true &&
  n.fields["low_priv_enroll"] === true &&
  n.fields["requires_manager_approval"] !== true &&
  (n.fields["client_auth_eku"] === true || n.fields["any_purpose_eku"] === true);

/** Derive abuse edges from node fields. Fixed-source abuses (unconstrained
 * delegation → the computer's domain) are always derived; roast abuses, which any
 * authenticated foothold can perform, are derived from each foothold to each
 * roastable target. */
export function inferAbuseEdges(
  nodes: GraphNode[],
  edges: GraphEdge[],
  footholdIds?: ReadonlySet<string>,
  credentials: Credential[] = [],
): GraphEdge[] {
  const derived: GraphEdge[] = [];
  const domainOf = new Map<string, string>();
  for (const e of edges) if (e.kind === "member_of_domain") domainOf.set(e.source, e.target);
  // A directory object's domain: an explicit member_of_domain edge, else (the common
  // single-forest case) the sole domain node in the graph — the target an ADCS abuse
  // "authenticates as a domain principal" lands on.
  const domainNodes = nodes.filter((n) => n.kind === "domain").map((n) => n.id);
  const soleDomain = domainNodes.length === 1 ? domainNodes[0]! : undefined;
  const domainFor = (id: string): string | undefined => domainOf.get(id) ?? soleDomain;
  const foot = footholdIds && footholdIds.size ? footholdIds : null;

  for (const n of nodes) {
    if (n.fields["unconstrained_delegation"] === true || n.fields["delegation"] === "unconstrained") {
      const d = domainOf.get(n.id);
      if (d) derived.push(derivedEdge("unconstrained_delegation", n.id, d));
    }

    // ESC1 — enrollable SAN-supplying client-auth template ⇒ enroll then authenticate
    // as any domain principal. enroll() needs a foothold; authenticates_as() is fixed.
    if (n.kind === "cert_template" && esc1Abusable(n)) {
      const d = domainFor(n.id);
      if (d) {
        if (foot) for (const f of foot) if (f !== n.id) derived.push(derivedEdge("enroll", f, n.id, { abuse: "esc1" }));
        derived.push(derivedEdge("authenticates_as", n.id, d, { abuse: "esc1" }));
      }
    }

    // ESC8 — a CA exposing HTTP web enrollment without EPA: a cert obtained from it
    // authenticates as a domain principal (structural fact). The way IN to the CA
    // (coerce + relay) is a compound prerequisite, emitted below.
    if (
      n.kind === "certificate_authority" &&
      n.fields["web_enrollment_http"] === true &&
      n.fields["epa_enforced"] !== true
    ) {
      const d = domainFor(n.id);
      if (d) derived.push(derivedEdge("authenticates_as", n.id, d, { abuse: "esc8" }));
    }

    // LAPS password already recovered ⇒ local admin on that computer for any foothold.
    if (n.fields["laps_pw_known"] === true && foot) {
      for (const f of foot) if (f !== n.id) derived.push(derivedEdge("has_local_admin", f, n.id, { abuse: "laps" }));
    }
  }

  // B7 — working credentials become credential_valid_for edges: a host you hold a
  // valid (tested-success) cred for is reachable by auth, with no structural edge.
  if (credentials.length) {
    const nodeIds = new Set(nodes.map((n) => n.id));
    for (const c of credentials) {
      for (const t of c.tested_against) {
        if (!t.succeeded || !nodeIds.has(t.host)) continue;
        if (c.belongs_to && nodeIds.has(c.belongs_to) && c.belongs_to !== t.host) {
          derived.push(derivedEdge("credential_valid_for", c.belongs_to, t.host, { credential: c.id }));
        } else if (foot) {
          for (const f of foot) if (f !== t.host) derived.push(derivedEdge("credential_valid_for", f, t.host, { credential: c.id }));
        }
      }
    }
  }

  // B9 — compound (AND-of-prerequisite) ESC8: a vulnerable CA is only abusable if a
  // coercible authentication source exists. Emit the full chain coerce(foothold→DC)
  // → relay_to(DC→CA) only when BOTH hold, so the path reflects the real prereqs.
  if (foot) {
    const vulnCAs = nodes.filter(
      (n) =>
        n.kind === "certificate_authority" &&
        n.fields["web_enrollment_http"] === true &&
        n.fields["epa_enforced"] !== true &&
        domainFor(n.id) !== undefined,
    );
    if (vulnCAs.length) {
      const dcSources = new Set(edges.filter((e) => e.kind === "dc_for").map((e) => e.source));
      const coercible = nodes.filter((n) => dcSources.has(n.id) || n.fields["unconstrained_delegation"] === true);
      for (const ca of vulnCAs) {
        for (const m of coercible) {
          for (const f of foot) if (f !== m.id) derived.push(derivedEdge("coerce", f, m.id, { abuse: "esc8" }));
          derived.push(derivedEdge("relay_to", m.id, ca.id, { abuse: "esc8" }));
        }
      }
    }
  }

  if (foot) {
    const roastable = nodes.filter((n) => n.fields["kerberoastable"] === true).map((n) => n.id);
    const asrep = nodes.filter((n) => n.fields["asrep_roastable"] === true).map((n) => n.id);
    for (const f of foot) {
      for (const t of roastable) if (t !== f) derived.push(derivedEdge("can_kerberoast", f, t));
      for (const t of asrep) if (t !== f) derived.push(derivedEdge("can_asrep_roast", f, t));
    }
  }
  return derived;
}

export interface AcquireResult {
  /** Goals that become reachable only after acquiring the hypothetical nodes. */
  newGoals: string[];
  /** Paths that originate from the newly-acquired nodes. */
  newPaths: AttackPath[];
}

/** What-if planning: "is it worth cracking this hash / popping this box?" — flip a
 * set of nodes to owned, recompute, and return the goals that newly fall. */
export function simulateAcquire(
  nodes: GraphNode[],
  edges: GraphEdge[],
  ownedIds: string[],
  opts: PathOptions = {},
): AcquireResult {
  const owned = new Set(ownedIds);
  const baseGoals = new Set(surfaceAttackPaths(nodes, edges, opts).map((p) => p.to));
  const hypothetical = nodes.map((n) =>
    owned.has(n.id) && !isCompromised(n) ? { ...n, compromise_level: "admin" as const } : n,
  );
  const after = surfaceAttackPaths(hypothetical, edges, opts);
  const newGoals = [...new Set(after.map((p) => p.to))].filter((g) => !baseGoals.has(g));
  return { newGoals, newPaths: after.filter((p) => owned.has(p.from)) };
}

/** Shortest source→target path over the prebuilt graph while masking a set of nodes
 * and `u->v` edges — without mutating the graph (so it is safe to call repeatedly
 * inside Yen's loop). Returns the hop list or null if disconnected under the mask. */
function dijkstraPath(
  g: Graph,
  info: Map<string, EdgeInfo>,
  source: string,
  target: string,
  blockNodes: ReadonlySet<string>,
  blockEdges: ReadonlySet<string>,
): string[] | null {
  if (blockNodes.has(source) || blockNodes.has(target)) return null;
  const dist = new Map<string, number>([[source, 0]]);
  const prev = new Map<string, string>();
  const done = new Set<string>();
  for (;;) {
    let u: string | null = null;
    let best = Infinity;
    for (const [node, d] of dist) if (!done.has(node) && d < best) { best = d; u = node; }
    if (u === null || u === target) break;
    done.add(u);
    g.forEachOutNeighbor(u, (v: string) => {
      if (blockNodes.has(v) || blockEdges.has(`${u}->${v}`)) return;
      const nd = best + (info.get(`${u}->${v}`)?.cost ?? 1);
      if (nd < (dist.get(v) ?? Infinity)) { dist.set(v, nd); prev.set(v, u); }
    });
  }
  return dist.has(target) ? reconstruct(prev, source, target) : null;
}

/** Up to `k` genuinely distinct, loopless routes from a foothold to a goal, by
 * Yen's algorithm — so when the primary route hits an EDR/MFA wall the operator sees
 * the true next-best alternatives (not just the best-path-minus-one-edge heuristic). */
export function alternativePaths(
  nodes: GraphNode[],
  edges: GraphEdge[],
  from: string,
  to: string,
  k = 3,
  opts: PathOptions = {},
  credentials: Credential[] = [],
): AttackPath[] {
  const footholdSet = new Set(nodes.filter(isCompromised).map((n) => n.id));
  const allEdges = [...edges, ...inferAbuseEdges(nodes, edges, footholdSet, credentials)];
  const { g, info } = buildAttackGraph(nodes, allEdges, opts.avoid, opts.objective);
  if (!g.hasNode(from) || !g.hasNode(to) || from === to) return [];

  const NONE: ReadonlySet<string> = new Set();
  const first = dijkstraPath(g, info, from, to, NONE, NONE);
  if (!first) return [];

  const accepted: string[][] = [first];
  const acceptedKeys = new Set<string>([first.join(">")]);
  const candidates: { hops: string[]; cost: number }[] = [];
  const candKeys = new Set<string>();

  while (accepted.length < k) {
    const prevPath = accepted[accepted.length - 1]!;
    for (let i = 0; i + 1 < prevPath.length; i++) {
      const spur = prevPath[i]!;
      const root = prevPath.slice(0, i + 1);
      const rootKey = root.join(">");
      // Block the edge every already-found path took out of this spur sharing the root.
      const blockEdges = new Set<string>();
      for (const p of accepted) {
        if (p.length > i + 1 && p.slice(0, i + 1).join(">") === rootKey) blockEdges.add(`${p[i]}->${p[i + 1]}`);
      }
      // Loopless: the spur path may not revisit a root node (except the spur itself).
      const blockNodes = new Set(root.slice(0, -1));
      const spurPath = dijkstraPath(g, info, spur, to, blockNodes, blockEdges);
      if (!spurPath) continue;
      const total = [...root.slice(0, -1), ...spurPath];
      const key = total.join(">");
      if (acceptedKeys.has(key) || candKeys.has(key)) continue;
      candKeys.add(key);
      candidates.push({ hops: total, cost: toAttackPath(from, to, total, info).cost });
    }
    if (!candidates.length) break;
    candidates.sort((a, b) => a.cost - b.cost || a.hops.length - b.hops.length);
    const next = candidates.shift()!;
    candKeys.delete(next.hops.join(">"));
    accepted.push(next.hops);
    acceptedKeys.add(next.hops.join(">"));
  }
  return accepted.map((hops) => toAttackPath(from, to, hops, info)).slice(0, k);
}

export interface OwnedClosure {
  /** Every node id owned at fixpoint: footholds + all that fall from them. */
  owned: Set<string>;
  /** Goals that lie inside the closure (the ones this team can actually take). */
  goalsOwned: string[];
  /** Rounds to convergence (a high count signals long capability chains). */
  rounds: number;
}

/** Owned-set capability fixpoint (saturation): repeatedly own everything reachable
 * from the current owned set, RE-deriving abuse edges as it grows — so owning one
 * user unlocks kerberoasting EVERY SPN, each crack expands reach, until nothing new
 * falls. This answers "what can this team ultimately take", not just "the shortest
 * path to one goal" — the question an operator actually plans the engagement around. */
export function computeOwnedClosure(
  nodes: GraphNode[],
  edges: GraphEdge[],
  seedIds?: Iterable<string>,
  credentials: Credential[] = [],
  opts: PathOptions = {},
): OwnedClosure {
  const owned = new Set<string>(seedIds ?? nodes.filter(isCompromised).map((n) => n.id));
  let rounds = 0;
  // Monotone growth over a finite node set ⇒ terminates; the bound is a safety net.
  for (let guard = 0; guard <= nodes.length + 1; guard++) {
    rounds++;
    const allEdges = [...edges, ...inferAbuseEdges(nodes, edges, owned, credentials)];
    const { g, info } = buildAttackGraph(nodes, allEdges, opts.avoid, opts.objective);
    let grew = false;
    for (const f of [...owned]) {
      if (!g.hasNode(f)) continue;
      for (const reached of dijkstraTree(g, info, f).dist.keys()) {
        if (!owned.has(reached)) { owned.add(reached); grew = true; }
      }
    }
    if (!grew) break;
  }
  const goals = goalNodes(nodes, edges);
  return { owned, goalsOwned: [...owned].filter((id) => goals.has(id)), rounds };
}
