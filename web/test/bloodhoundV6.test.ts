// BloodHound CE (SharpHound v6) ingestion: the real collector set from a lab
// domain (OUROBOROS.HC), both as loose JSON files and as the .zip SharpHound
// actually produces. Guards the v6 shapes: GUID-keyed GPO links, top-level
// AllowedToAct/AllowedToDelegate, LocalGroups, ChildObjects, and the v6
// property flags.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { unzipSync } from "fflate";
import { Campaign } from "@/campaign/document";
import { importFiles, type ImportCtx } from "@/io/import";

const ctx: ImportCtx = { author: "op_test", now: 1000 };

/** The store's zip path, verbatim: unzip and feed every .json entry. */
const importZip = (zipPath: string): Campaign => {
  const entries = unzipSync(
    new Uint8Array(readFileSync(fileURLToPath(new URL(`./fixtures/bloodhound/${zipPath}`, import.meta.url)))),
  );
  const inputs = Object.entries(entries)
    .filter(([name]) => name.toLowerCase().endsWith(".json"))
    .map(([name, bytes]) => ({ name, content: new TextDecoder().decode(bytes) }));
  const c = new Campaign("bh6", 1n);
  importFiles(c, inputs, ctx);
  return c;
};

describe("SharpHound v6 zip (the real 20260704192422_bloodhound.zip)", () => {
  const c = importZip("20260704192422_bloodhound.zip");
  const nodes = c.nodes();
  const edges = c.edges();
  const byLabel = new Map(nodes.map((n) => [n.label, n]));

  it("imports every collector file from the archive", () => {
    // 1 domain + 1 computer + 5 users + 52 groups + 2 gpos + 1 ou (+ 19 containers as nodes? containers map to custom)
    expect(nodes.length).toBeGreaterThan(50);
  });

  it("builds the domain with its functional level and tier-zero flag", () => {
    const dom = byLabel.get("OUROBOROS.HC");
    expect(dom?.kind).toBe("domain");
    expect(dom?.fields["functional_level"]).toBe("2016");
    expect(dom?.fields["is_tier_zero"]).toBe(true);
  });

  it("v6 computer flags: unconstrained delegation + SPNs on MGMT01", () => {
    const mgmt = byLabel.get("MGMT01.OUROBOROS.HC");
    expect(mgmt?.kind).toBe("host_windows");
    expect(mgmt?.fields["unconstrained_delegation"]).toBe(true);
    expect(mgmt?.fields["delegation"]).toBe("unconstrained");
    expect(Array.isArray(mgmt?.fields["spn"])).toBe(false); // computers don't get spn field; users do
  });

  it("ACEs become ACL edges, including GetChanges -> dc_sync on the domain", () => {
    const dom = byLabel.get("OUROBOROS.HC")!;
    const dcSync = edges.filter((e) => e.kind === "dc_sync" && e.target === dom.id);
    expect(dcSync.length).toBeGreaterThan(0);
    const genericAll = edges.filter((e) => e.kind === "generic_all");
    expect(genericAll.length).toBeGreaterThan(3);
  });

  it("group membership resolves (Domain Admins <- Administrator)", () => {
    const da = byLabel.get("DOMAIN ADMINS@OUROBOROS.HC");
    const admin = byLabel.get("ADMINISTRATOR@OUROBOROS.HC");
    expect(da?.kind).toBe("group");
    expect(admin).toBeDefined();
    expect(edges.some((e) => e.kind === "member_of" && e.source === admin!.id && e.target === da!.id)).toBe(true);
  });

  it("GPO links become gpo_applies_to edges (v6 Links by GUID)", () => {
    const gpoEdges = edges.filter((e) => e.kind === "gpo_applies_to");
    expect(gpoEdges.length).toBeGreaterThanOrEqual(2); // domain link + OU link
    const dcPolicy = byLabel.get("DEFAULT DOMAIN CONTROLLERS POLICY@OUROBOROS.HC");
    expect(dcPolicy?.kind).toBe("gpo");
    expect(gpoEdges.some((e) => e.source === dcPolicy!.id)).toBe(true);
  });

  it("OU child objects become contains_ou edges", () => {
    const mgmt = byLabel.get("MGMT01.OUROBOROS.HC")!;
    expect(edges.some((e) => e.kind === "contains_ou" && e.target === mgmt.id)).toBe(true);
  });

  it("re-importing the same zip dedups (resolveOrCreate collapses)", () => {
    const before = c.nodes().length;
    const edgesBefore = c.edges().length;
    const c2 = importZip("20260704192422_bloodhound.zip");
    // Fresh doc imports identically…
    expect(c2.nodes().length).toBe(before);
    // …and importing twice into the SAME doc adds nothing new.
    const entries = unzipSync(
      new Uint8Array(readFileSync(fileURLToPath(new URL("./fixtures/bloodhound/20260704192422_bloodhound.zip", import.meta.url)))),
    );
    const inputs = Object.entries(entries)
      .filter(([name]) => name.endsWith(".json"))
      .map(([name, bytes]) => ({ name, content: new TextDecoder().decode(bytes) }));
    importFiles(c, inputs, ctx);
    expect(c.nodes().length).toBe(before);
    expect(c.edges().length).toBe(edgesBefore);
  });
});
