import { describe, it, expect } from "vitest";
import { buildReport, type ReportInput } from "@/io/report";
import type { Credential, GraphNode, Provenance } from "@/domain/types";

const prov = (): Provenance => ({ author: "op", source: { kind: "manual" }, confidence: "confirmed", first_seen: 1, last_verified: 1 });
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

const input = (): ReportInput => ({
  campaignId: "camp_demo",
  generatedAt: 1_700_000_000_000,
  operators: [{ operatorId: "op_alice", displayName: "Alice" }],
  nodes: [
    node("dc", { kind: "domain_controller", label: "DC01", compromise_level: "domain_admin", fields: { compromise_method: "kerberoast", compromise_note: "svc_sql SPN" } }),
    node("ws", { label: "WS01", compromise_level: "admin", fields: { compromise_method: "phishing", findings: [
      { title: "MS17-010", severity: "critical", status: "open" },
      { title: "SMB signing disabled", severity: "low", status: "open" },
    ] } }),
  ],
  credentials: [
    {
      id: "c1",
      username: "administrator",
      domain: "CORP",
      credential_type: "password_ntlm",
      secret_sealed: '{"ct":"TOPSECRET_NTLM_HASH"}',
      validity: "valid",
      validity_as_of: 1,
      source: "dump",
      tested_against: [{ host: "dc", succeeded: true, at: 1 }],
      provenance: prov(),
    } as Credential,
  ],
  events: [
    { author: "op_alice", at: 1_699_999_000_000, action: "node.upsert", summary: "added DC01" },
    { author: "op_alice", at: 1_699_999_500_000, action: "node.compromise", summary: "DC01 → domain_admin" },
  ],
  attackPaths: [{ hops: ["ws", "dc"], to: "dc" }],
});

describe("report export", () => {
  it("assembles the expected Markdown sections", () => {
    const { markdown } = buildReport(input());
    for (const h of ["# Campaign Report", "## Executive Summary", "## How Access Was Obtained", "## Attack Paths", "## Findings", "## Credentials", "## Asset Inventory", "## Timeline"]) {
      expect(markdown).toContain(h);
    }
    // Access vectors and the attack path are rendered with labels.
    expect(markdown).toContain("**DC01** — kerberoast");
    expect(markdown).toContain("WS01 → DC01");
  });

  it("sorts findings by severity (critical before low)", () => {
    const { markdown, data } = buildReport(input());
    expect(data.findings.map((f) => f.severity)).toEqual(["critical", "low"]);
    expect(markdown.indexOf("MS17-010")).toBeLessThan(markdown.indexOf("SMB signing disabled"));
  });

  it("NEVER includes a credential secret — only existence/validity", () => {
    const { markdown, data } = buildReport(input());
    expect(markdown).not.toContain("TOPSECRET_NTLM_HASH");
    expect(markdown).not.toContain("secret_sealed");
    expect(JSON.stringify(data)).not.toContain("TOPSECRET_NTLM_HASH");
    expect(JSON.stringify(data)).not.toContain("secret_sealed");
    // ...but the credential's existence + where-valid is reported.
    expect(markdown).toContain("administrator@CORP");
    expect(data.credentials[0]!.validOn).toEqual(["DC01"]);
  });

  it("produces JSON that round-trips", () => {
    const { data } = buildReport(input());
    expect(JSON.parse(JSON.stringify(data))).toEqual(data);
  });
});
