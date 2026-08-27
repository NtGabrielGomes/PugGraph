// The folded-collection data layer (the "dump problem"): large imports become one
// off-canvas node whose members materialize to real graph nodes only on demand,
// reconcile through a fold index, lift sealed secrets into the vault on promotion,
// and refold (guarded) on the way back. Web-managed, so it round-trips in snapshots.

import { describe, it, expect } from "vitest";
import { Campaign } from "@/campaign/document";
import type { CollectionMember, GraphEdge, Provenance } from "@/domain/types";

const prov = (): Provenance => ({ author: "op", source: { kind: "import", tool: "secretsdump" }, confidence: "confirmed", first_seen: 1000, last_verified: 1000 });

const member = (key: string, over: Partial<CollectionMember> = {}): CollectionMember => ({
  key,
  kind: "user_account",
  label: key,
  identity_keys: [{ kind: "ad_sid", value: `S-1-5-${key}`, is_primary: true }],
  fields: {},
  tags: [],
  ...over,
});

const coll = (c: Campaign, id = "coll:secretsdump:corp") =>
  c.addCollection({ id, tool: "secretsdump", object_type: "ntds", domain: "corp", label: "NTDS", created_by: "op", created_at: 1, last_collected_at: 1, stats: { kerberoastable: 1 }, count: 0 });

describe("folded collections", () => {
  it("stores members off-canvas — no graph nodes, tracked count + stats", () => {
    const c = new Campaign("camp", 1n);
    coll(c);
    c.addCollectionMember("coll:secretsdump:corp", member("alice"));
    c.addCollectionMember("coll:secretsdump:corp", member("bob"));
    expect(c.nodes()).toHaveLength(0); // nothing on the canvas
    const meta = c.collections()[0]!;
    expect(meta.count).toBe(2);
    expect(meta.stats.kerberoastable).toBe(1);
    expect(c.collectionMembers("coll:secretsdump:corp").map((m) => m.key).sort()).toEqual(["alice", "bob"]);
  });

  it("is idempotent on re-collection (same key does not double the count)", () => {
    const c = new Campaign("camp", 1n);
    coll(c);
    expect(c.addCollectionMember("coll:secretsdump:corp", member("alice"))).toBe(true);
    expect(c.addCollectionMember("coll:secretsdump:corp", member("alice", { label: "alice2" }))).toBe(false);
    expect(c.collections()[0]!.count).toBe(1);
  });

  it("materializes a member on demand, lifting sealed secrets into the vault", () => {
    const c = new Campaign("camp", 1n);
    coll(c);
    c.addCollectionMember("coll:secretsdump:corp", member("svc", {
      kind: "service_account",
      sealed_secrets: [{ type: "password_ntlm", username: "svc_sql", domain: "corp", sealed: '{"ct":"x"}' }],
    }));
    const id = c.promoteMember("coll:secretsdump:corp", "svc", prov())!;
    expect(id).toBeTruthy();
    expect(c.nodes().map((n) => n.id)).toEqual([id]); // now a real node
    expect(c.collections()[0]!.count).toBe(0); // removed from the fold
    const cred = c.credentials()[0]!;
    expect(cred.belongs_to).toBe(id);
    expect(cred.secret_sealed).toBe('{"ct":"x"}');
  });

  it("reconciles a later observation onto the folded member (fold index), promoting it once", () => {
    const c = new Campaign("camp", 1n);
    coll(c);
    c.addCollectionMember("coll:secretsdump:corp", member("dave"));
    // Nmap-style re-observation by the same identity should resolve-or-promote to one node.
    const id = c.promoteMember("coll:secretsdump:corp", "dave", prov())!;
    const again = c.resolveOrCreate([{ kind: "ad_sid", value: "S-1-5-dave", is_primary: true }], (nid) => ({
      id: nid, kind: "user_account", label: "dave", identity_keys: [{ kind: "ad_sid", value: "S-1-5-dave", is_primary: true }],
      compromise_level: "unknown", fields: {}, tags: [], provenance: prov(),
    }));
    expect(again).toBe(id); // collapsed onto the promoted node, not duplicated
    expect(c.nodes()).toHaveLength(1);
  });

  it("refolds a clean promoted node back into its collection (guarded)", () => {
    const c = new Campaign("camp", 1n);
    coll(c);
    c.addCollectionMember("coll:secretsdump:corp", member("erin"));
    const id = c.promoteMember("coll:secretsdump:corp", "erin", prov())!;
    expect(c.collections()[0]!.count).toBe(0);
    expect(c.refoldNode(id, [])).toBe(true);
    expect(c.nodes()).toHaveLength(0);
    expect(c.collections()[0]!.count).toBe(1); // back in the fold

    // Guard: a compromised or edge-bearing node must NOT refold (tradecraft state).
    const id2 = c.promoteMember("coll:secretsdump:corp", "erin", prov())!;
    c.setCompromise(id2, "admin");
    expect(c.refoldNode(id2, [])).toBe(false);
    c.setCompromise(id2, "unknown");
    const edge: GraphEdge = { id: "e1", kind: "admin_to", source: id2, target: "x", confidence: "confirmed", provenance: prov() };
    expect(c.refoldNode(id2, [edge])).toBe(false);
  });

  it("does not resurrect a promoted member on re-collection (no zombies, stable count)", () => {
    const c = new Campaign("camp", 1n);
    coll(c);
    c.addCollectionMember("coll:secretsdump:corp", member("frank"));
    const id = c.promoteMember("coll:secretsdump:corp", "frank", prov())!;
    expect(c.collections()[0]!.count).toBe(0);
    // Re-import the same dump: frank is now a real node → must be skipped, not re-folded.
    expect(c.addCollectionMember("coll:secretsdump:corp", member("frank", { label: "frank2" }))).toBe(false);
    expect(c.collections()[0]!.count).toBe(0);
    expect(c.collectionMembers("coll:secretsdump:corp")).toHaveLength(0);
    expect(c.nodes().map((n) => n.id)).toEqual([id]); // still exactly one node
  });

  it("round-trips folded collections through a snapshot", () => {
    const a = new Campaign("camp", 1n);
    coll(a);
    a.addCollectionMember("coll:secretsdump:corp", member("frank"));
    const b = Campaign.fromSnapshot("camp", 2n, a.exportSnapshot());
    expect(b.collections()[0]!.count).toBe(1);
    expect(b.collectionMember("coll:secretsdump:corp", "frank")?.label).toBe("frank");
  });
});
