// Pughound importer: parses the per-table JSON files and the consolidated
// pughound-report.json, and maps AD enumeration onto the campaign graph so the
// path engine can reason over it (roastable/delegation fields derive edges).
// Fixtures are real Pughound output from a lab domain (garfield.htb).

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Campaign } from "@/campaign/document";
import { detectFormat, importFiles, parsePughound, type ImportCtx } from "@/io/import";

const fx = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`./fixtures/pughound/${name}`, import.meta.url)), "utf8");

const ctx: ImportCtx = { author: "op_test", now: 1000 };

const importReport = (): Campaign => {
  const c = new Campaign("ph", 1n);
  importFiles(c, [{ name: "pughound-report.json", content: fx("pughound-report.json") }], ctx);
  return c;
};

describe("pughound format detection", () => {
  it("detects the consolidated report and single-table files as pughound", () => {
    expect(detectFormat("pughound-report.json", fx("pughound-report.json"))).toBe("pughound");
    expect(detectFormat("Computers.json", fx("Computers.json"))).toBe("pughound");
  });

  it("still detects bloodhound JSON as bloodhound", () => {
    expect(detectFormat("users.json", '{"meta":{"type":"users"},"data":[]}')).toBe("bloodhound");
  });

  it("parses both shapes into the same table list", () => {
    const fromReport = parsePughound(fx("pughound-report.json"));
    expect(fromReport.length).toBeGreaterThan(30);
    const single = parsePughound(fx("Computers.json"));
    expect(single).toHaveLength(1);
    expect(single[0]!.name).toBe("Computers");
    expect(single[0]!.rows).toHaveLength(2);
  });
});

describe("pughound import over the real lab output", () => {
  it("builds the domain, DCs, computers, users and groups with reconciliation", () => {
    const c = importReport();
    const nodes = c.nodes();
    const byLabel = new Map(nodes.map((n) => [n.label, n]));

    // Domain node from DomainSID + DNs.
    const dom = nodes.find((n) => n.kind === "domain");
    expect(dom?.label).toBe("garfield.htb");
    expect(dom?.fields["functional_level"]).toContain("2019");
    expect(dom?.fields["lockout_threshold"]).toBe("0");

    // DC01 appears in both Computers and DomainControllers — ONE node, upgraded.
    const dc01 = byLabel.get("dc01.garfield.htb");
    expect(dc01).toBeDefined();
    expect(dc01!.fields["is_tier_zero"]).toBe(true);
    expect(dc01!.fields["network_role"]).toBe("domain_controller");
    const dc01s = nodes.filter((n) => n.label === "dc01.garfield.htb");
    expect(dc01s).toHaveLength(1);
    // IPs from DomainControllers + All_DNS reconciled onto the same node.
    const ips = dc01!.identity_keys.filter((k) => k.kind === "ip_address").map((k) => k.value);
    expect(ips).toContain("10.129.83.192");
    expect(ips).toContain("192.168.100.1");

    // Users with flags from the attribute tables.
    const admin = byLabel.get("Administrator");
    expect(admin?.kind).toBe("user_account");
    expect(admin?.fields["admin_count"]).toBe(true);
    expect(admin?.fields["password_never_expires"]).toBe(true);
    const guest = byLabel.get("Guest");
    expect(guest?.fields["enabled"]).toBe(false);

    // Kerberoast: krbtgt carries the flag + SPN (feeds derived can_kerberoast).
    const krbtgt = byLabel.get("krbtgt");
    expect(krbtgt?.fields["kerberoastable"]).toBe(true);

    // Groups exist and membership edges resolve (Administrator -> Domain Admins).
    const edges = c.edges();
    const da = byLabel.get("Domain Admins");
    expect(da?.kind).toBe("group");
    expect(
      edges.some((e) => e.kind === "member_of" && e.source === admin!.id && e.target === da!.id),
    ).toBe(true);

    // DCSync rights: well-known SID principals get readable stubs and dc_sync
    // edges onto the domain.
    const dcsync = edges.filter((e) => e.kind === "dc_sync");
    expect(dcsync.length).toBeGreaterThan(5);
    expect(dcsync.every((e) => e.target === dom!.id)).toBe(true);
    // S-1-5-32-544 reconciled onto the real Administrators group from DomainGroups.
    const admins = byLabel.get("Administrators");
    expect(admins?.kind).toBe("group");
    expect(dcsync.some((e) => e.source === admins!.id)).toBe(true);

    // Constrained delegation with protocol transition on RODC01$.
    const rodc = byLabel.get("rodc01.garfield.htb");
    expect(rodc?.fields["delegation"]).toBe("constrained");
    expect(rodc?.fields["protocol_transition"]).toBe(true);

    // GPO links: Default Domain Policy applies to the domain.
    const gpo = byLabel.get("Default Domain Policy");
    expect(gpo?.kind).toBe("gpo");
    expect(
      edges.some((e) => e.kind === "gpo_applies_to" && e.source === gpo!.id && e.target === dom!.id),
    ).toBe(true);
  });

  it("merges with a bloodhound import onto the same host node", () => {
    const c = importReport();
    const before = c.nodes().filter((n) => n.label === "dc01.garfield.htb");
    expect(before).toHaveLength(1);
    importFiles(
      c,
      [
        {
          name: "computers.json",
          content: JSON.stringify({
            meta: { type: "computers" },
            data: [
              {
                objectid: "S-1-5-21-2502726253-3859040611-225969357-1000",
                name: "DC01.GARFIELD.HTB",
                properties: { name: "DC01.GARFIELD.HTB", operatingsystem: "Windows Server 2019" },
              },
            ],
          }),
        },
      ],
      ctx,
    );
    // Same SID + fqdn → the bloodhound observation reconciles onto the node
    // pughound created instead of duplicating it.
    const after = c.nodes().filter((n) => n.label === "dc01.garfield.htb");
    expect(after).toHaveLength(1);
  });

  it("accepts a bare directory of table files (no consolidated report)", () => {
    const c = new Campaign("ph2", 1n);
    const summary = importFiles(
      c,
      [
        { name: "Computers.json", content: fx("Computers.json") },
        { name: "Users.json", content: fx("Users.json") },
        { name: "DCSync_Rights.json", content: fx("DCSync_Rights.json") },
      ],
      ctx,
    );
    expect(summary.hosts).toBe(2);
    expect(summary.nodes).toBeGreaterThan(5);
    expect(c.edges().filter((e) => e.kind === "dc_sync").length).toBeGreaterThan(5);
  });

  it("hostile input never panics: malformed JSON and wrong-shape JSON are skipped", () => {
    const c = new Campaign("ph3", 1n);
    expect(() =>
      importFiles(
        c,
        [
          { name: "a.json", content: "{not json" },
          { name: "b.json", content: '{"query":"X","columns":[],"rows":"nope"}' },
          { name: "c.json", content: '{"categories":[{"tables":[{"name":"Users","rows":[{"evil":"${7*7}"}]}]}]}' },
        ],
        ctx,
      ),
    ).not.toThrow();
  });
});
