import { describe, it, expect } from "vitest";
import { Campaign } from "@/campaign/document";
import { COMPROMISE_METHODS, HOST_KINDS, schemaFor, schemaKeys } from "@/domain/fieldSchema";
import { credsForNode } from "@/state/store";
import type { Credential, GraphNode, Provenance } from "@/domain/types";

const prov = (): Provenance => ({
  author: "op_test",
  source: { kind: "manual" },
  confidence: "confirmed",
  first_seen: 1000,
  last_verified: 1000,
});

const cred = (over: Partial<Credential>): Credential => ({
  id: "c",
  username: "u",
  credential_type: "password_ntlm",
  validity: "unknown",
  validity_as_of: 1,
  source: "dump",
  tested_against: [],
  provenance: prov(),
  ...over,
});

describe("M1 — compromise / access-vector dossier", () => {
  it("offers the access-vector fields on host kinds only, in a leading Compromise group", () => {
    for (const k of HOST_KINDS) {
      const keys = schemaKeys(k);
      expect(keys.has("compromise_method")).toBe(true);
      expect(keys.has("compromise_note")).toBe(true);
      expect(schemaFor(k).some((f) => f.key === "compromise_method" && f.group === "Compromise")).toBe(true);
    }
    // Non-host kinds never carry it — access is a property of a machine.
    for (const k of ["user_account", "domain", "group", "service", "cloud_identity"] as const) {
      expect(schemaKeys(k).has("compromise_method")).toBe(false);
    }
  });

  it("exposes a non-empty, deduplicated method vocabulary", () => {
    expect(COMPROMISE_METHODS.length).toBeGreaterThan(5);
    expect(COMPROMISE_METHODS).toContain("valid_credentials");
    expect(COMPROMISE_METHODS).toContain("vpn_pivot");
    expect(new Set(COMPROMISE_METHODS).size).toBe(COMPROMISE_METHODS.length);
  });

  it("round-trips the access vector through the campaign document (lives in the open fields bag)", () => {
    const c = new Campaign("c1", 1n);
    const n: GraphNode = {
      id: "host1",
      kind: "host_windows",
      label: "WS01",
      identity_keys: [],
      compromise_level: "admin",
      fields: { compromise_method: "phishing", compromise_note: "macro doc → beacon" },
      tags: [],
      provenance: prov(),
    };
    c.upsertNode(n);
    const got = c.nodes()[0]!;
    expect(got.fields.compromise_method).toBe("phishing");
    expect(got.fields.compromise_note).toBe("macro doc → beacon");
  });

  it("aggregates the dossier: loot/credentials link back to the specific machine they came from", () => {
    const creds = [
      cred({ id: "c1", username: "svc_sql", obtained_from: "host1" }),
      cred({ id: "c2", username: "admin", belongs_to: "acct1", tested_against: [{ host: "host1", succeeded: true, at: 1 }] }),
      cred({ id: "c3", username: "other", obtained_from: "host2" }),
    ];
    const d = credsForNode(creds, "host1");
    expect(d.obtainedHere.map((c) => c.id)).toEqual(["c1"]); // captured here
    expect(d.testedHere.map((c) => c.id)).toEqual(["c2"]); // opens this host
    expect(d.authenticatesAs).toHaveLength(0);
  });
});
