// Pre-built queries: the catalog resolves over a real imported graph, counts
// are honest, and command templates get campaign variables filled.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Campaign } from "@/campaign/document";
import { importFiles, type ImportCtx } from "@/io/import";
import {
  PREBUILT_QUERIES,
  commandsFor,
  fillCommand,
  incidentScope,
  type PrebuiltQuery,
} from "@/graph/prebuiltQueries";
import type { GraphEdge, GraphNode, Provenance } from "@/domain/types";

const prov0 = (): Provenance => ({
  author: "op_test",
  source: { kind: "manual" },
  confidence: "confirmed",
  first_seen: 0,
  last_verified: 0,
});

const report = readFileSync(
  fileURLToPath(new URL("./fixtures/pughound/pughound-report.json", import.meta.url)),
  "utf8",
);

const ctx: ImportCtx = { author: "op_test", now: 1000 };

const loadGraph = (): { nodes: GraphNode[]; edges: GraphEdge[] } => {
  const c = new Campaign("pbq", 1n);
  importFiles(c, [{ name: "pughound-report.json", content: report }], ctx);
  return { nodes: c.nodes(), edges: c.edges() };
};

const byName = (name: string): PrebuiltQuery => {
  const q = PREBUILT_QUERIES.flatMap((g) => g.items).find((q) => q.name === name);
  if (!q) throw new Error(`query not registered: ${name}`);
  return q;
};

describe("pre-built queries over the garfield.htb import", () => {
  const { nodes, edges } = loadGraph();

  it("every catalog query resolves without throwing", () => {
    for (const g of PREBUILT_QUERIES)
      for (const q of g.items) {
        const s = q.match(nodes, edges);
        expect(s.nodeIds.length + s.edgeIds.length).toBeGreaterThanOrEqual(0);
      }
  });

  it("kerberoastable users scopes krbtgt", () => {
    const s = byName("Kerberoastable users").match(nodes, edges);
    const labels = s.nodeIds.map((id) => nodes.find((n) => n.id === id)?.label);
    expect(labels).toContain("krbtgt");
  });

  it("DCSync rights scopes the dc_sync edges onto the domain", () => {
    const s = byName("DCSync rights").match(nodes, edges);
    expect(s.edgeIds.length).toBeGreaterThan(5);
    const dom = nodes.find((n) => n.kind === "domain")!;
    for (const eid of s.edgeIds) {
      const e = edges.find((x) => x.id === eid)!;
      expect(e.kind).toBe("dc_sync");
      expect(e.target).toBe(dom.id);
    }
  });

  it("constrained delegation catches RODC01 with protocol transition", () => {
    const s = byName("Constrained delegation").match(nodes, edges);
    const rodc = nodes.find((n) => n.label === "rodc01.garfield.htb")!;
    expect(s.nodeIds).toContain(rodc.id);
  });

  it("infrastructure queries find the DC and the GPO links", () => {
    const dcs = byName("Domain controllers").match(nodes, edges);
    expect(dcs.nodeIds.length).toBe(1);
    const gpos = byName("GPOs and links").match(nodes, edges);
    expect(gpos.edgeIds.length).toBe(2);
    expect(gpos.nodeIds.length).toBeGreaterThanOrEqual(3); // 2 GPOs + domain
  });

  it("empty-result queries (RBCD, ADCS) resolve to an empty scope, not an error", () => {
    expect(byName("Resource-based constrained (RBCD)").match(nodes, edges).edgeIds).toHaveLength(0);
    expect(byName("Enrollment rights").match(nodes, edges).edgeIds).toHaveLength(0);
  });
});

describe("abuse command cards", () => {
  it("each query's command keys exist in the catalog", () => {
    for (const g of PREBUILT_QUERIES)
      for (const q of g.items) {
        const cmds = commandsFor(q);
        expect(cmds.length).toBeGreaterThanOrEqual(q.commandKeys.length === 0 ? 0 : 1);
        for (const c of cmds) expect(c.title).toBeTruthy();
      }
  });

  it("fills campaign variables and leaves operator placeholders literal", () => {
    const out = fillCommand(
      "impacket-secretsdump '{{domain}}/{{user}}:{{password}}@{{dc}}' # {{target}} {{targetDN}} {{source}}",
      { domain: "garfield.htb", dc: "10.129.83.192", target: "DC01$", targetDN: "CN=DC01,DC=garfield,DC=htb" },
    );
    expect(out).toContain("garfield.htb");
    expect(out).toContain("10.129.83.192");
    expect(out).toContain("DC01$");
    expect(out).toContain("CN=DC01,DC=garfield,DC=htb");
    expect(out).toContain("{{user}}"); // operator fills these
    expect(out).toContain("{{password}}");
    expect(out).toContain("<source>"); // unresolved falls back to a placeholder
  });
});

describe("incidentScope (navigator focus)", () => {
  const edges: GraphEdge[] = [
    { id: "e1", kind: "member_of", source: "a", target: "b", confidence: "confirmed", fields: {}, provenance: prov0() },
    { id: "e2", kind: "member_of", source: "b", target: "c", confidence: "confirmed", fields: {}, provenance: prov0() },
    { id: "e3", kind: "member_of", source: "d", target: "e", confidence: "confirmed", fields: {}, provenance: prov0() },
  ];

  it("focuses a node's neighborhood: incident edges pull in the other endpoint", () => {
    const s = incidentScope(["b"], edges);
    expect(s.nodeIds.sort()).toEqual(["a", "b", "c"]);
    expect(s.edgeIds.sort()).toEqual(["e1", "e2"]);
  });

  it("focuses a group: all members plus every edge touching them", () => {
    const s = incidentScope(["a", "d"], edges);
    expect(s.nodeIds.sort()).toEqual(["a", "b", "d", "e"]);
    expect(s.edgeIds.sort()).toEqual(["e1", "e3"]);
  });

  it("an isolated node scopes itself with no edges", () => {
    const s = incidentScope(["zzz"], edges);
    expect(s.nodeIds).toEqual(["zzz"]);
    expect(s.edgeIds).toEqual([]);
  });
});
