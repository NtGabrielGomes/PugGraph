import { describe, it, expect } from "vitest";
import { Campaign } from "@/campaign/document";
import type { GraphNode, Provenance } from "@/domain/types";

const prov = (): Provenance => ({
  author: "op_test",
  source: { kind: "manual" },
  confidence: "confirmed",
  first_seen: 1000,
  last_verified: 1000,
});

const node = (id: string, over: Partial<GraphNode> = {}): GraphNode => ({
  id,
  kind: "host_windows",
  label: id,
  identity_keys: [],
  compromise_level: "unknown",
  fields: {},
  tags: [],
  provenance: prov(),
  ...over,
});

describe("Campaign document (Loro)", () => {
  it("round-trips a node through the document", () => {
    const c = new Campaign("c1", 1n);
    c.upsertNode(
      node("n1", {
        kind: "domain_controller",
        label: "DC01",
        compromise_level: "domain_admin",
        identity_keys: [
          { kind: "fqdn", value: "dc01.corp.local", is_primary: true },
          { kind: "ip_address", value: "10.0.0.1", is_primary: false },
        ],
        fields: { os_version: "Windows Server 2019" },
        tags: ["crown-jewel"],
      }),
    );
    const got = c.nodes()[0]!;
    expect(got.kind).toBe("domain_controller");
    expect(got.label).toBe("DC01");
    expect(got.compromise_level).toBe("domain_admin");
    expect(got.identity_keys).toHaveLength(2);
    expect(got.fields.os_version).toBe("Windows Server 2019");
    expect(got.tags).toContain("crown-jewel");
  });

  it("reconciles observations that share an identity key", () => {
    const c = new Campaign("c1", 1n);
    const id1 = c.resolveOrCreate(
      [{ kind: "ip_address", value: "10.0.0.5", is_primary: true }],
      (id) => node(id, { label: "10.0.0.5" }),
    );
    const id2 = c.resolveOrCreate(
      [
        { kind: "ip_address", value: "10.0.0.5", is_primary: false },
        { kind: "ad_sid", value: "S-1-5-21-x", is_primary: false },
      ],
      (id) => node(id, { label: "SRV05" }),
    );
    expect(id1).toBe(id2);
    const id3 = c.resolveOrCreate(
      [{ kind: "ip_address", value: "10.0.0.6", is_primary: true }],
      (id) => node(id, { kind: "host_linux", label: "10.0.0.6" }),
    );
    expect(id3).not.toBe(id1);
    expect(c.nodes()).toHaveLength(2);
  });

  it("converges two replicas after exchanging updates", () => {
    const a = new Campaign("c1", 1n);
    const b = new Campaign("c1", 2n);

    a.upsertNode(node("n1", { label: "alice-host" }));
    a.addEdge({
      id: "e1",
      kind: "admin_to",
      source: "n1",
      target: "n2",
      confidence: "confirmed",
      provenance: prov(),
    });
    b.upsertNode(node("n2", { kind: "domain_controller", label: "bob-dc" }));
    b.addTag("n2", "crown-jewel"); // edits its own node, no concurrent creation

    const va = a.version();
    const vb = b.version();
    const ua = a.exportUpdatesFrom(vb);
    const ub = b.exportUpdatesFrom(va);
    a.import(ub);
    b.import(ua);

    // Non-negotiable invariant: both replicas reach identical state.
    expect(a.toJSON()).toEqual(b.toJSON());
    expect(a.nodes().map((n) => n.id)).toEqual(["n1", "n2"]);
    expect(a.edges().map((e) => e.id)).toEqual(["e1"]);
  });

  it("converges concurrent edits to the same field (LWW agreement)", () => {
    // Shared base: Alice creates n1, Bob forks from her snapshot.
    const a = new Campaign("c1", 1n);
    a.upsertNode(node("n1", { label: "init" }));
    const b = Campaign.fromSnapshot("c1", 2n, a.exportSnapshot());

    // Concurrent edits to the same field.
    a.setLabel("n1", "from-alice");
    b.setLabel("n1", "from-bob");

    const va = a.version();
    const vb = b.version();
    const ua = a.exportUpdatesFrom(vb);
    const ub = b.exportUpdatesFrom(va);
    a.import(ub);
    b.import(ua);

    const la = a.nodes()[0]!.label;
    const lb = b.nodes()[0]!.label;
    expect(la).toBe(lb); // they AGREE (deterministic LWW winner)
    expect(["from-alice", "from-bob"]).toContain(la);
    expect(a.toJSON()).toEqual(b.toJSON());
  });

  it("survives a snapshot export/import cycle", () => {
    const a = new Campaign("c1", 1n);
    a.upsertNode(node("n1", { label: "persisted" }));
    const snap = a.exportSnapshot();
    const b = Campaign.fromSnapshot("c1", 2n, snap);
    expect(b.nodes()[0]!.label).toBe("persisted");
  });

  it("stores and reads back a credential", () => {
    const c = new Campaign("c1", 1n);
    c.addCredential({
      id: "cred1",
      username: "svc_sql",
      domain: "CORP",
      credential_type: "password_ntlm",
      secret_sealed: '{"nonce":"x","ct":"y"}',
      validity: "unknown",
      validity_as_of: 1000,
      source: "dump",
      tested_against: [],
      provenance: prov(),
    });
    c.setCredentialValidity("cred1", "valid", 2000);
    c.addCredentialTest("cred1", { host: "n1", succeeded: true, at: 2000 });
    const got = c.credentials()[0]!;
    expect(got.username).toBe("svc_sql");
    expect(got.validity).toBe("valid");
    expect(got.secret_sealed).toBe('{"nonce":"x","ct":"y"}');
    expect(got.tested_against).toHaveLength(1);
  });

  it("links a credential to the entities it belongs to / came from, and edits links", () => {
    const c = new Campaign("c1", 1n);
    c.addCredential({
      id: "cred1",
      username: "administrator",
      domain: "CORP",
      credential_type: "password_ntlm",
      belongs_to: "acct1",
      obtained_from: "host1",
      validity: "valid",
      validity_as_of: 1000,
      source: "dump",
      tested_against: [{ host: "host1", succeeded: true, at: 1000 }],
      provenance: prov(),
    });
    let got = c.credentials()[0]!;
    expect(got.belongs_to).toBe("acct1");
    expect(got.obtained_from).toBe("host1");
    expect(got.tested_against).toHaveLength(1);

    // Re-link is LWW; clearing removes the key.
    c.setCredentialLinks("cred1", "acct2", undefined);
    got = c.credentials()[0]!;
    expect(got.belongs_to).toBe("acct2");
    expect(got.obtained_from).toBeUndefined();
  });

  it("round-trips team-shared theme overrides in their own container", () => {
    const a = new Campaign("c1", 1n);
    a.setThemeColor("host_windows", "#123456");
    a.setThemeGlyph("service_account", "service");
    a.setThemeVariant("host_windows", "laptop");
    const b = Campaign.fromSnapshot("c1", 2n, a.exportSnapshot());
    const t = b.theme();
    expect(t.colors.host_windows).toBe("#123456");
    expect(t.glyphs.service_account).toBe("service");
    expect(t.variants.host_windows).toBe("laptop");
    // Clearing a color / variant removes it.
    a.setThemeColor("host_windows", undefined);
    expect(a.theme().colors.host_windows).toBeUndefined();
    a.setThemeVariant("host_windows", undefined);
    expect(a.theme().variants.host_windows).toBeUndefined();
  });

  it("round-trips the team roster and converges concurrent membership edits", () => {
    const a = new Campaign("c1", 1n);
    a.setRosterEntry({
      operator_id: "op_alice",
      display_name: "Alice",
      signing_pubkey: "SIGN_A",
      wrapping_pubkey: "WRAP_A",
      role: "lead",
      status: "active",
      added_by: "op_alice",
      added_at: 1000,
    });
    // Persists in its own container through a snapshot cycle.
    const b = Campaign.fromSnapshot("c1", 2n, a.exportSnapshot());
    const alice = b.roster().find((e) => e.operator_id === "op_alice")!;
    expect(alice.role).toBe("lead");
    expect(alice.signing_pubkey).toBe("SIGN_A");
    expect(alice.wrapping_pubkey).toBe("WRAP_A");

    // Two leads concurrently enroll DIFFERENT operators — both must survive.
    a.setRosterEntry({
      operator_id: "op_bob", display_name: "Bob", signing_pubkey: "SIGN_B",
      wrapping_pubkey: "WRAP_B", role: "operator", status: "active", added_by: "op_alice", added_at: 1100,
    });
    b.setRosterEntry({
      operator_id: "op_carol", display_name: "Carol", signing_pubkey: "SIGN_C",
      wrapping_pubkey: "WRAP_C", role: "observer", status: "active", added_by: "op_alice", added_at: 1200,
    });
    const va = a.version();
    const vb = b.version();
    a.import(b.exportUpdatesFrom(va));
    b.import(a.exportUpdatesFrom(vb));
    expect(a.toJSON()).toEqual(b.toJSON());
    expect(a.roster().map((e) => e.operator_id)).toEqual(["op_alice", "op_bob", "op_carol"]);
    expect(a.roster().find((e) => e.operator_id === "op_carol")!.role).toBe("observer");

    // Revoking flips status (kept for history) and is readable.
    a.setRosterStatus("op_bob", "revoked");
    expect(a.roster().find((e) => e.operator_id === "op_bob")!.status).toBe("revoked");
  });

  it("removing a node clears its identity index so a re-observation is fresh", () => {
    const c = new Campaign("c1", 1n);
    const key = [{ kind: "ad_sid", value: "S-1-5-21-z", is_primary: true }];
    const id1 = c.resolveOrCreate(key, (id) => node(id));
    expect(c.resolveOrCreate(key, (id) => node(id))).toBe(id1); // reconciles
    c.removeNode(id1);
    const id2 = c.resolveOrCreate(key, (id) => node(id)); // no stale index entry
    expect(id2).not.toBe(id1);
    expect(c.nodes().map((n) => n.id)).toEqual([id2]);
  });

  it("import is idempotent — applying the same op twice changes nothing", () => {
    const a = new Campaign("c1", 1n);
    a.upsertNode(node("n1", { label: "host" }));
    a.addEdge({ id: "e1", kind: "admin_to", source: "n1", target: "n2", confidence: "confirmed", provenance: prov() });
    const all = a.exportAll();
    const b = new Campaign("c1", 2n);
    b.import(all);
    const once = JSON.stringify(b.toJSON());
    b.import(all); // replay (e.g. snapshot + resync overlap)
    expect(JSON.stringify(b.toJSON())).toBe(once);
    expect(b.nodes().map((n) => n.id)).toEqual(["n1"]);
  });
});
