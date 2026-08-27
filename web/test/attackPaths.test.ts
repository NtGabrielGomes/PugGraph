import { describe, it, expect } from "vitest";
import { surfaceAttackPaths } from "@/graph/attackPaths";
import type { GraphEdge, GraphNode } from "@/domain/types";

const prov = () => ({
  author: "op",
  source: { kind: "manual" as const },
  confidence: "confirmed" as const,
  first_seen: 0,
  last_verified: 0,
});

const n = (id: string, kind: GraphNode["kind"], compromise: GraphNode["compromise_level"]): GraphNode => ({
  id,
  kind,
  label: id,
  identity_keys: [],
  compromise_level: compromise,
  fields: {},
  tags: [],
  provenance: prov(),
});

const e = (id: string, kind: GraphEdge["kind"], source: string, target: string): GraphEdge => ({
  id,
  kind,
  source,
  target,
  confidence: "confirmed",
  provenance: prov(),
});

describe("attack-path surfacing", () => {
  it("finds the shortest traversable path from a foothold to a high-value target", () => {
    const nodes = [
      n("foothold", "host_windows", "user"),
      n("relay", "host_windows", "unknown"),
      n("dc", "domain_controller", "unknown"),
    ];
    const edges = [
      e("e1", "admin_to", "foothold", "relay"),
      e("e2", "can_ps_remote", "relay", "dc"),
    ];
    const paths = surfaceAttackPaths(nodes, edges);
    expect(paths.length).toBeGreaterThan(0);
    const toDc = paths.find((p) => p.to === "dc")!;
    expect(toDc.from).toBe("foothold");
    expect(toDc.hops).toEqual(["foothold", "relay", "dc"]);
  });

  it("does not traverse structural-only edges", () => {
    const nodes = [n("foothold", "host_windows", "admin"), n("dc", "domain_controller", "unknown")];
    // same_segment is not attacker-traversable, so no path should exist.
    const edges = [e("e1", "same_segment", "foothold", "dc")];
    expect(surfaceAttackPaths(nodes, edges)).toHaveLength(0);
  });

  it("ignores uncompromised footholds", () => {
    const nodes = [n("clean", "host_windows", "none"), n("dc", "domain_controller", "unknown")];
    const edges = [e("e1", "admin_to", "clean", "dc")];
    expect(surfaceAttackPaths(nodes, edges)).toHaveLength(0);
  });

  it("targets a node tagged #goal even when it is not a high-value kind", () => {
    const nodes = [n("foothold", "host_windows", "user"), { ...n("crown", "share", "unknown"), tags: ["goal"] }];
    const edges = [e("e1", "admin_to", "foothold", "crown")];
    const paths = surfaceAttackPaths(nodes, edges);
    expect(paths.find((p) => p.to === "crown")?.hops).toEqual(["foothold", "crown"]);
  });

  it("prefers the lower-cost route and reports its cost", () => {
    // Two routes foothold→dc: a 1-hop privilege edge vs a 2-hop network detour.
    const nodes = [
      n("foothold", "host_windows", "admin"),
      n("hop", "host_windows", "unknown"),
      n("dc", "domain_controller", "unknown"),
    ];
    const edges = [
      e("e1", "admin_to", "foothold", "dc"), // cheap, direct
      e("e2", "connects_to", "foothold", "hop"), // expensive detour
      e("e3", "connects_to", "hop", "dc"),
    ];
    const best = surfaceAttackPaths(nodes, edges).find((p) => p.to === "dc")!;
    expect(best.hops).toEqual(["foothold", "dc"]);
    expect(best.cost).toBeGreaterThan(0);
    expect(best.edges).toEqual(["admin_to"]);
  });
});
