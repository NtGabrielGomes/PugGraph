import { describe, it, expect } from "vitest";
import { Campaign } from "@/campaign/document";
import type { GraphEdge } from "@/domain/types";

const prov = () => ({ author: "op", source: { kind: "manual" as const }, confidence: "confirmed" as const, first_seen: 0, last_verified: 0 });
const edge = (id: string, kind: GraphEdge["kind"], s: string, t: string, fields?: Record<string, unknown>): GraphEdge => ({
  id, kind, source: s, target: t, confidence: "confirmed", fields, provenance: prov(),
});

describe("edge fields", () => {
  it("persists and reads back typed edge fields", () => {
    const c = new Campaign("camp", 1n);
    c.addEdge(edge("e1", "trusts", "a", "b", { direction: "outbound", transitive: true }));
    c.setEdgeField("e1", "sid_filtering", false);
    const e = c.edges().find((x) => x.id === "e1")!;
    expect(e.fields).toMatchObject({ direction: "outbound", transitive: true, sid_filtering: false });
    c.removeEdgeField("e1", "transitive");
    expect(c.edges().find((x) => x.id === "e1")!.fields).not.toHaveProperty("transitive");
  });

  it("converges concurrent edge-field edits across two replicas (CRDT)", () => {
    const a = new Campaign("camp", 1n);
    const b = new Campaign("camp", 2n);
    a.addEdge(edge("e1", "can_rdp", "a", "b", {}));
    b.import(a.exportSnapshot());
    a.setEdgeField("e1", "port", 3389);
    b.setEdgeField("e1", "nla", true);
    const sa = a.exportSnapshot();
    const sb = b.exportSnapshot();
    a.import(sb);
    b.import(sa);
    const ea = a.edges().find((x) => x.id === "e1")!;
    const eb = b.edges().find((x) => x.id === "e1")!;
    expect(ea.fields).toEqual(eb.fields);
    expect(ea.fields).toMatchObject({ port: 3389, nla: true });
  });
});

describe("web-managed containers round-trip through a snapshot", () => {
  it("preserves saved filters, templates, and pathmarks", () => {
    const a = new Campaign("camp", 1n);
    a.addFilter({ id: "f1", name: "DA-reach", query: "compromise:>=admin", created_by: "op" });
    a.addTemplate({ id: "t1", name: "Win server", kind: "host_windows", fields: { os: "Windows Server 2019" }, tags: ["dmz"], created_by: "op" });
    a.addPathMark({ id: "p1", name: "foothold→dc", hops: ["a", "b", "c"], created_by: "op", created_at: 5 });

    const b = Campaign.fromSnapshot("camp", 2n, a.exportSnapshot());
    expect(b.filters()).toEqual(a.filters());
    expect(b.templates()).toEqual(a.templates());
    expect(b.pathmarks()).toEqual(a.pathmarks());

    a.removeFilter("f1");
    a.removePathMark("p1");
    const c = Campaign.fromSnapshot("camp", 3n, a.exportSnapshot());
    expect(c.filters()).toHaveLength(0);
    expect(c.pathmarks()).toHaveLength(0);
    expect(c.templates()).toHaveLength(1);
  });
});

describe("operator chat (messages container)", () => {
  it("persists messages and converges concurrent chat across two replicas", () => {
    const a = new Campaign("camp", 1n);
    const b = new Campaign("camp", 2n);
    a.addMessage({ id: "m1", author: "alice", at: 10, body: "pivoting via FS01", ref: "node_fs01" });
    b.import(a.exportSnapshot());
    // Two operators chat concurrently, then exchange updates in any order.
    a.addMessage({ id: "m2", author: "alice", at: 20, body: "DC reachable" });
    b.addMessage({ id: "m3", author: "bob", at: 15, body: "watch EDR on WS01" });
    a.import(b.exportSnapshot());
    b.import(a.exportSnapshot());
    expect(a.messages()).toEqual(b.messages());
    // Sorted by timestamp; the node reference round-trips.
    expect(a.messages().map((m) => m.id)).toEqual(["m1", "m3", "m2"]);
    expect(a.messages()[0]!.ref).toBe("node_fs01");
  });
});
