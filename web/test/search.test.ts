import { describe, it, expect } from "vitest";
import { SearchIndex, buildSearchDocs } from "@/graph/search";
import type { Credential, GraphNode, Provenance } from "@/domain/types";

const prov = (): Provenance => ({
  author: "op",
  source: { kind: "manual" },
  confidence: "confirmed",
  first_seen: 1,
  last_verified: 1,
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

const cred = (over: Partial<Credential>): Credential => ({
  id: "c",
  username: "u",
  credential_type: "password_ntlm",
  validity: "valid",
  validity_as_of: 1,
  source: "dump",
  tested_against: [],
  provenance: prov(),
  ...over,
});

describe("full-text search (MiniSearch over decrypted state)", () => {
  it("indexes labels, fields, tags, and findings", () => {
    const idx = new SearchIndex();
    idx.sync(
      buildSearchDocs(
        [
          node("n1", { label: "DC01", fields: { domain: "corp.local", os_version: "Windows Server 2019" }, tags: ["crown-jewel"] }),
          node("n2", { kind: "service", label: "tcp/445", fields: { findings: [{ title: "MS17-010", severity: "critical", status: "open" }] } }),
        ],
        [],
        [],
      ),
    );
    expect(idx.search("DC01").map((h) => h.id)).toContain("n1");
    expect(idx.search("corp.local").map((h) => h.id)).toContain("n1");
    expect(idx.search("crown-jewel").map((h) => h.id)).toContain("n1");
    expect(idx.search("MS17-010").map((h) => h.id)).toContain("n2");
    // Filter by kind.
    expect(idx.search("tcp", { kind: "service" }).map((h) => h.id)).toEqual(["n2"]);
  });

  it("finds a credential by username/domain but NEVER indexes the secret", () => {
    const docs = buildSearchDocs(
      [],
      [cred({ id: "cred1", username: "svc_sql", domain: "CORP", secret_sealed: '{"ct":"SUPERSECRETXYZ"}' })],
      [],
    );
    // The built document must not contain the sealed secret anywhere.
    expect(JSON.stringify(docs)).not.toContain("SUPERSECRETXYZ");

    const idx = new SearchIndex();
    idx.sync(docs);
    expect(idx.search("svc_sql").map((h) => h.id)).toContain("cred1");
    expect(idx.search("CORP", { type: "credential" }).map((h) => h.id)).toContain("cred1");
    // The secret is not searchable — it was never indexed.
    expect(idx.search("SUPERSECRETXYZ")).toHaveLength(0);
  });

  it("updates incrementally as state changes", () => {
    const idx = new SearchIndex();
    idx.sync(buildSearchDocs([node("n1", { label: "alpha" }), node("n2", { label: "beta" })], [], []));
    expect(idx.search("alpha").map((h) => h.id)).toEqual(["n1"]);

    // Remove n1, edit n2's label → reflected on the next sync.
    idx.sync(buildSearchDocs([node("n2", { label: "beta", fields: { os_version: "ubuntu" } })], [], []));
    expect(idx.search("alpha")).toHaveLength(0); // n1 gone
    expect(idx.search("ubuntu").map((h) => h.id)).toEqual(["n2"]); // n2 re-indexed with new term
  });
});
