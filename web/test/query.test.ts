import { describe, it, expect } from "vitest";
import { matchesQuery } from "@/graph/query";
import type { GraphNode } from "@/domain/types";

const prov = () => ({ author: "op", source: { kind: "manual" as const }, confidence: "confirmed" as const, first_seen: 0, last_verified: 0 });

const n = (over: Partial<GraphNode>): GraphNode => ({
  id: "x",
  kind: "host_windows",
  label: "DC01",
  identity_keys: [],
  compromise_level: "unknown",
  fields: {},
  tags: [],
  provenance: prov(),
  ...over,
});

describe("structured query", () => {
  it("matches everything on an empty query", () => {
    expect(matchesQuery(n({}), "")).toBe(true);
    expect(matchesQuery(n({}), "   ")).toBe(true);
  });

  it("filters by kind (comma list)", () => {
    expect(matchesQuery(n({ kind: "domain_controller" }), "kind:domain_controller")).toBe(true);
    expect(matchesQuery(n({ kind: "host_linux" }), "kind:domain_controller,host_linux")).toBe(true);
    expect(matchesQuery(n({ kind: "host_windows" }), "kind:domain_controller")).toBe(false);
  });

  it("compares compromise by severity rank", () => {
    expect(matchesQuery(n({ compromise_level: "admin" }), "compromise:>=user")).toBe(true);
    expect(matchesQuery(n({ compromise_level: "user" }), "compromise:>=admin")).toBe(false);
    expect(matchesQuery(n({ compromise_level: "system" }), "compromise:system")).toBe(true);
  });

  it("filters by tag, confidence, and has:", () => {
    expect(matchesQuery(n({ tags: ["crown-jewel"] }), "tag:crown-jewel")).toBe(true);
    expect(matchesQuery(n({ provenance: { ...prov(), confidence: "suspected" } }), "confidence:suspected")).toBe(true);
    expect(matchesQuery(n({ fields: { findings: [{ title: "x" }] } }), "has:finding")).toBe(true);
    expect(matchesQuery(n({ fields: {} }), "has:finding")).toBe(false);
    expect(matchesQuery(n({ fields: { spn: "HTTP/dc" } }), "has:spn")).toBe(true);
  });

  it("ANDs all terms and matches bare text against label/fields", () => {
    const node = n({ label: "FS01", kind: "host_windows", compromise_level: "admin", fields: { domain: "corp.local" } });
    expect(matchesQuery(node, "corp compromise:>=user")).toBe(true);
    expect(matchesQuery(node, "corp compromise:>=system")).toBe(false);
    expect(matchesQuery(node, "fs0")).toBe(true);
  });
});
