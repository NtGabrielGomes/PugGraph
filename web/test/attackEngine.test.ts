// The deeper attack-path engine: Tier-0 / capability goals (owning a member of
// Domain Admins is the win), objective-weighted routing (quiet vs fast), forward/
// reverse reachability, blast radius, chokepoint ranking, and ATT&CK path explain.

import { describe, it, expect } from "vitest";
import {
  surfaceAttackPaths,
  goalNodes,
  reachableFrom,
  reachersOf,
  blastRadius,
  chokepoints,
  explainPath,
  inferAbuseEdges,
  simulateAcquire,
  alternativePaths,
  computeOwnedClosure,
  pathTo,
  pathRisk,
} from "@/graph/attackPaths";
import type { Credential, GraphEdge, GraphNode, IdentityKey } from "@/domain/types";

const prov = () => ({ author: "op", source: { kind: "manual" as const }, confidence: "confirmed" as const, first_seen: 0, last_verified: 0 });
const n = (id: string, kind: GraphNode["kind"], compromise: GraphNode["compromise_level"] = "unknown", over: Partial<GraphNode> = {}): GraphNode => ({
  id, kind, label: id, identity_keys: [], compromise_level: compromise, fields: {}, tags: [], provenance: prov(), ...over,
});
const e = (id: string, kind: GraphEdge["kind"], source: string, target: string): GraphEdge => ({
  id, kind, source, target, confidence: "confirmed", provenance: prov(),
});
const sid = (v: string): IdentityKey[] => [{ kind: "ad_sid", value: v, is_primary: true }];

describe("Tier-0 / capability goals", () => {
  it("treats a member of a Tier-0 group (RID 512) as a goal, transitively", () => {
    const nodes = [
      n("foothold", "host_windows", "user"),
      n("da", "group", "unknown", { identity_keys: sid("S-1-5-21-1-2-3-512") }), // Domain Admins
      n("alice", "user_account"),
    ];
    const edges = [e("m", "member_of", "alice", "da"), e("g", "generic_all", "foothold", "alice")];
    const goals = goalNodes(nodes, edges);
    expect(goals.has("da")).toBe(true);
    expect(goals.has("alice")).toBe(true); // transitively Tier-0
    const paths = surfaceAttackPaths(nodes, edges);
    expect(paths.find((p) => p.to === "alice")).toBeTruthy();
  });

  it("recognizes adminCount / tier_zero flags and krbtgt", () => {
    const nodes = [
      n("svc", "service_account", "unknown", { fields: { admin_count: true } }),
      n("krbtgt", "user_account"),
      n("plain", "user_account"),
    ];
    const goals = goalNodes(nodes, []);
    expect(goals.has("svc")).toBe(true);
    expect(goals.has("krbtgt")).toBe(true); // by label
    expect(goals.has("plain")).toBe(false);
  });
});

describe("objective-weighted routing", () => {
  it("prices a loud route higher under the quiet objective", () => {
    const nodes = [n("foothold", "domain_controller", "admin"), n("dom", "domain")];
    const edges = [e("d", "dc_sync", "foothold", "dom")];
    const fast = surfaceAttackPaths(nodes, edges, { objective: "fast" }).find((p) => p.to === "dom")!;
    const quiet = surfaceAttackPaths(nodes, edges, { objective: "quiet" }).find((p) => p.to === "dom")!;
    expect(quiet.cost).toBeGreaterThan(fast.cost); // dc_sync is loud → penalized when quiet
  });
});

describe("reachability + blast radius", () => {
  const nodes = [n("a", "host_windows", "admin"), n("b", "host_windows"), n("c", "domain_controller")];
  const edges = [e("e1", "admin_to", "a", "b"), e("e2", "can_ps_remote", "b", "c")];

  it("computes forward reachability (what a foothold can touch)", () => {
    const r = reachableFrom(nodes, edges, "a").map((x) => x.id);
    expect(r).toEqual(["b", "c"]);
  });
  it("computes reverse reachability (who can reach a crown jewel)", () => {
    const r = reachersOf(nodes, edges, "c").map((x) => x.id).sort();
    expect(r).toEqual(["a", "b"]);
  });
  it("reports blast radius with goals fallen", () => {
    const br = blastRadius(nodes, edges, "a");
    expect(br.count).toBe(2);
    expect(br.goalsReached).toContain("c"); // the DC is a goal
  });
});

describe("chokepoints", () => {
  it("ranks the pivot that the most goal-paths funnel through", () => {
    // Two footholds, both must pass through `pivot` to reach the DC goal.
    const nodes = [
      n("f1", "host_windows", "admin"),
      n("f2", "host_windows", "admin"),
      n("pivot", "host_windows"),
      n("dc", "domain_controller"),
    ];
    const edges = [
      e("a", "admin_to", "f1", "pivot"),
      e("b", "admin_to", "f2", "pivot"),
      e("c", "can_ps_remote", "pivot", "dc"),
    ];
    const cps = chokepoints(nodes, edges);
    expect(cps[0]!.id).toBe("pivot");
    expect(cps[0]!.pathsCovered).toBe(2);
  });
});

describe("field → edge inference", () => {
  it("derives a Kerberoast edge so a foothold can reach a roastable Tier-0 SPN", () => {
    const nodes = [
      n("foothold", "user_account", "user"),
      n("svc", "service_account", "unknown", { fields: { kerberoastable: true, admin_count: true } }),
    ];
    // No explicit edge — the path only exists via the derived can_kerberoast edge.
    const derived = inferAbuseEdges(nodes, [], new Set(["foothold"]));
    expect(derived.some((e) => e.kind === "can_kerberoast" && e.target === "svc")).toBe(true);
    const paths = surfaceAttackPaths(nodes, []);
    expect(paths.find((p) => p.to === "svc")?.edges).toEqual(["can_kerberoast"]);
  });

  it("derives unconstrained-delegation → domain from the computer field", () => {
    const nodes = [n("ws", "computer_account", "admin", { fields: { unconstrained_delegation: true } }), n("dom", "domain")];
    const edges = [e("md", "member_of_domain", "ws", "dom")];
    const paths = surfaceAttackPaths(nodes, edges);
    const p = paths.find((x) => x.to === "dom")!;
    expect(p.edges).toContain("unconstrained_delegation");
  });
});

describe("what-if acquisition", () => {
  it("reports goals that newly fall after owning a node", () => {
    const nodes = [n("pivot", "host_windows", "none"), n("dc", "domain_controller")];
    const edges = [e("a", "admin_to", "pivot", "dc")];
    expect(surfaceAttackPaths(nodes, edges)).toHaveLength(0); // nothing owned yet
    const sim = simulateAcquire(nodes, edges, ["pivot"]);
    expect(sim.newGoals).toContain("dc");
    expect(sim.newPaths.find((p) => p.from === "pivot" && p.to === "dc")).toBeTruthy();
  });
});

describe("alternative paths", () => {
  it("returns distinct routes when more than one exists", () => {
    const nodes = [n("f", "host_windows", "admin"), n("x", "host_windows"), n("y", "host_windows"), n("dc", "domain_controller")];
    const edges = [
      e("1", "admin_to", "f", "x"),
      e("2", "can_ps_remote", "x", "dc"),
      e("3", "admin_to", "f", "y"),
      e("4", "can_ps_remote", "y", "dc"),
    ];
    const alts = alternativePaths(nodes, edges, "f", "dc", 3);
    expect(alts.length).toBeGreaterThanOrEqual(2);
    expect(new Set(alts.map((p) => p.hops.join(">"))).size).toBe(alts.length); // all distinct
  });
});

describe("trust-aware weighting", () => {
  it("prices a SID-filtered trust higher than an open one", () => {
    const nodes = [n("d1", "domain", "admin"), n("d2", "domain")];
    const open: GraphEdge = { ...e("t", "trusts", "d1", "d2"), fields: {} };
    const filtered: GraphEdge = { ...e("t", "trusts", "d1", "d2"), fields: { sid_filtering: true } };
    const openCost = surfaceAttackPaths(nodes, [open]).find((p) => p.to === "d2")!.cost;
    const filteredCost = surfaceAttackPaths(nodes, [filtered]).find((p) => p.to === "d2")!.cost;
    expect(filteredCost).toBeGreaterThan(openCost);
  });
});

describe("ATT&CK path explanation", () => {
  it("maps each hop to its technique + tool", () => {
    const nodes = [n("dc01", "domain_controller", "admin"), n("dom", "domain")];
    const edges = [e("d", "dc_sync", "dc01", "dom")];
    const path = surfaceAttackPaths(nodes, edges).find((p) => p.to === "dom")!;
    const steps = explainPath(path);
    expect(steps).toHaveLength(1);
    expect(steps[0]!.mitre).toContain("T1003.006");
    expect(steps[0]!.tool).toMatch(/secretsdump/);
  });
});

describe("field-derived ADCS / LAPS abuse edges (B1: tradecraft fields → edges)", () => {
  it("derives ESC1 enroll + authenticates_as so a foothold routes to the domain through a template", () => {
    const nodes = [
      n("foothold", "user_account", "user"),
      n("tmpl", "cert_template", "unknown", {
        fields: { enrollee_supplies_subject: true, low_priv_enroll: true, client_auth_eku: true },
      }),
      n("corp", "domain", "unknown", { tags: ["goal"] }),
    ];
    const derived = inferAbuseEdges(nodes, [], new Set(["foothold"]));
    expect(derived.find((d) => d.kind === "enroll" && d.source === "foothold" && d.target === "tmpl")).toBeTruthy();
    expect(derived.find((d) => d.kind === "authenticates_as" && d.source === "tmpl" && d.target === "corp")).toBeTruthy();
    const path = surfaceAttackPaths(nodes, []).find((p) => p.from === "foothold" && p.to === "corp");
    expect(path).toBeTruthy();
    expect(path!.edges).toContain("enroll");
  });

  it("does NOT derive ESC1 when the template requires manager approval", () => {
    const nodes = [
      n("foothold", "user_account", "user"),
      n("tmpl", "cert_template", "unknown", {
        fields: { enrollee_supplies_subject: true, low_priv_enroll: true, client_auth_eku: true, requires_manager_approval: true },
      }),
      n("corp", "domain"),
    ];
    expect(inferAbuseEdges(nodes, [], new Set(["foothold"])).find((d) => d.kind === "enroll")).toBeFalsy();
  });

  it("derives ESC8 from a CA with HTTP web enrollment and no EPA", () => {
    const nodes = [
      n("foothold", "host_windows", "admin"),
      n("ca", "certificate_authority", "unknown", { fields: { web_enrollment_http: true } }),
      n("corp", "domain"),
    ];
    const derived = inferAbuseEdges(nodes, [], new Set(["foothold"]));
    expect(derived.find((d) => d.kind === "authenticates_as" && d.source === "ca" && d.target === "corp")).toBeTruthy();
  });

  it("derives local admin from a recovered LAPS password", () => {
    const nodes = [
      n("foothold", "user_account", "user"),
      n("ws01", "computer_account", "unknown", { fields: { laps_pw_known: true } }),
    ];
    const derived = inferAbuseEdges(nodes, [], new Set(["foothold"]));
    expect(derived.find((d) => d.kind === "has_local_admin" && d.source === "foothold" && d.target === "ws01")).toBeTruthy();
  });
});

describe("deeper attack-path engine (B7 cred-aware · B8 saturation · B9 compound · B10 Yen)", () => {
  const cred = (over: Partial<Credential> = {}): Credential => ({
    id: "c1", username: "svc", credential_type: "password_ntlm", source: "dump",
    validity: "valid", validity_as_of: 0, tested_against: [], provenance: prov(), ...over,
  });

  it("threads a working credential into pathfinding as a reachable edge (B7)", () => {
    const nodes = [
      n("foothold", "user_account", "user"),
      n("dc01", "host_windows", "unknown", { tags: ["goal"] }),
    ];
    expect(surfaceAttackPaths(nodes, []).find((p) => p.to === "dc01")).toBeFalsy(); // no edge
    const c = cred({ belongs_to: "foothold", tested_against: [{ host: "dc01", succeeded: true, at: 0 }] });
    const p = surfaceAttackPaths(nodes, [], {}, [c]).find((x) => x.to === "dc01");
    expect(p).toBeTruthy();
    expect(p!.edges).toContain("credential_valid_for");
  });

  it("ignores a credential whose test failed (B7)", () => {
    const nodes = [n("foothold", "user_account", "user"), n("dc01", "host_windows", "unknown", { tags: ["goal"] })];
    const c = cred({ belongs_to: "foothold", tested_against: [{ host: "dc01", succeeded: false, at: 0 }] });
    expect(surfaceAttackPaths(nodes, [], {}, [c]).find((x) => x.to === "dc01")).toBeFalsy();
  });

  it("computes the owned-set saturation fixpoint (B8)", () => {
    const nodes = [
      n("foothold", "host_windows", "admin"),
      n("svc", "service_account", "unknown", { fields: { kerberoastable: true } }),
      n("dc", "host_windows", "unknown", { tags: ["goal"] }),
    ];
    const edges = [e("a", "admin_to", "svc", "dc")];
    const closure = computeOwnedClosure(nodes, edges, ["foothold"]);
    expect(closure.owned.has("svc")).toBe(true); // kerberoasted
    expect(closure.owned.has("dc")).toBe(true); // then admin
    expect(closure.goalsOwned).toContain("dc");
  });

  it("models compound ESC8 (coerce + relay + CA), gated on a coercible DC (B9)", () => {
    const nodes = [
      n("foothold", "host_windows", "admin"),
      n("dc", "computer_account"),
      n("ca", "certificate_authority", "unknown", { fields: { web_enrollment_http: true } }),
      n("corp", "domain", "unknown", { tags: ["goal"] }),
    ];
    const edges = [e("d", "dc_for", "dc", "corp")]; // dc is a DC ⇒ coercible source
    const derived = inferAbuseEdges(nodes, edges, new Set(["foothold"]));
    expect(derived.find((x) => x.kind === "coerce" && x.source === "foothold" && x.target === "dc")).toBeTruthy();
    expect(derived.find((x) => x.kind === "relay_to" && x.source === "dc" && x.target === "ca")).toBeTruthy();
    expect(surfaceAttackPaths(nodes, edges).find((p) => p.to === "corp")).toBeTruthy();
    // No coercible source ⇒ no way INTO the CA ⇒ no esc8 relay chain.
    const noDc = inferAbuseEdges([nodes[0]!, nodes[2]!, nodes[3]!], [], new Set(["foothold"]));
    expect(noDc.find((x) => x.kind === "relay_to")).toBeFalsy();
  });

  it("returns true k-shortest loopless routes via Yen (B10)", () => {
    const nodes = [
      n("a", "host_windows", "admin"),
      n("b", "host_windows"),
      n("c", "host_windows"),
      n("goal", "host_windows", "unknown", { tags: ["goal"] }),
    ];
    const edges = [
      e("1", "admin_to", "a", "b"), e("2", "admin_to", "b", "goal"),
      e("3", "admin_to", "a", "c"), e("4", "admin_to", "c", "goal"),
    ];
    const alts = alternativePaths(nodes, edges, "a", "goal", 3);
    expect(alts.length).toBe(2);
    expect(alts.map((p) => p.hops.join(">")).sort()).toEqual(["a>b>goal", "a>c>goal"]);
  });

  it("routes to a chosen non-goal target (pathTo, B13)", () => {
    const nodes = [n("a", "host_windows", "admin"), n("mid", "host_windows"), n("target", "host_windows")];
    const edges = [e("1", "admin_to", "a", "mid"), e("2", "admin_to", "mid", "target")];
    const p = pathTo(nodes, edges, "target");
    expect(p?.hops).toEqual(["a", "mid", "target"]);
  });

  it("scores cumulative path detection likelihood (B11)", () => {
    const empty = pathRisk({ from: "a", to: "b", hops: ["a", "b"], cost: 1, edges: [] });
    expect(empty).toBe(0); // no edges ⇒ no noise
    const loud = pathRisk({ from: "a", to: "b", hops: ["a", "b", "c"], cost: 2, edges: ["dcsync" as never, "coerce"] });
    expect(loud).toBeGreaterThanOrEqual(0);
    expect(loud).toBeLessThanOrEqual(1); // a probability
  });
});
