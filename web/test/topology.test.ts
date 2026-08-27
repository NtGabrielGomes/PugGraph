import { describe, it, expect } from "vitest";
import { compoundParentIds, computeCompoundParents } from "@/graph/topology";
import type { GraphEdge, GraphNode, NodeKind } from "@/domain/types";

const prov = () => ({ author: "op", source: { kind: "manual" as const }, confidence: "confirmed" as const, first_seen: 1, last_verified: 1 });
const n = (id: string, kind: NodeKind): GraphNode => ({ id, kind, label: id, identity_keys: [], compromise_level: "unknown", fields: {}, tags: [], provenance: prov() });
const e = (kind: GraphEdge["kind"], source: string, target: string): GraphEdge => ({ id: `${source}|${kind}|${target}`, kind, source, target, confidence: "confirmed", provenance: prov() });

describe("topology orchestration (compound grouping)", () => {
  it("nests VMs in hypervisors, containers in hosts, members in domains", () => {
    const nodes = [
      n("hv", "hypervisor"),
      n("vm", "virtual_machine"),
      n("ch", "container_host"),
      n("ct", "container"),
      n("dom", "domain"),
      n("u", "user_account"),
    ];
    const edges = [e("hosts_vm", "hv", "vm"), e("runs_container", "ch", "ct"), e("member_of_domain", "u", "dom")];
    const p = computeCompoundParents(nodes, edges);
    expect(p["vm"]).toBe("hv");
    expect(p["ct"]).toBe("ch");
    expect(p["u"]).toBe("dom");
    // hv/ch/dom are the compound parents.
    expect(compoundParentIds(p)).toEqual(new Set(["hv", "ch", "dom"]));
  });

  it("supports the reverse vm_hosted_on direction and nested compounds", () => {
    const nodes = [n("hv", "hypervisor"), n("vm", "virtual_machine"), n("dom", "domain")];
    // vm_hosted_on: vm -> hypervisor; hypervisor is itself a domain member.
    const edges = [e("vm_hosted_on", "vm", "hv"), e("member_of_domain", "hv", "dom")];
    const p = computeCompoundParents(nodes, edges);
    expect(p["vm"]).toBe("hv"); // nested: dom ⊃ hv ⊃ vm
    expect(p["hv"]).toBe("dom");
  });

  it("prefers virtualization over domain membership and breaks cycles", () => {
    const nodes = [n("hv", "hypervisor"), n("vm", "virtual_machine"), n("dom", "domain")];
    // The VM is both hosted by hv AND (spuriously) a domain member → host wins.
    const edges = [e("hosts_vm", "hv", "vm"), e("member_of_domain", "vm", "dom")];
    expect(computeCompoundParents(nodes, edges)["vm"]).toBe("hv");

    // A 2-cycle is rejected rather than producing an invalid compound tree.
    const cyc = computeCompoundParents([n("a", "domain"), n("b", "domain")], [e("member_of_domain", "a", "b"), e("member_of_domain", "b", "a")]);
    const chainsToSelf = Object.keys(cyc).some((k) => {
      let cur: string | undefined = k;
      const seen = new Set<string>();
      while (cur && cyc[cur]) {
        if (seen.has(cur)) return true;
        seen.add(cur);
        cur = cyc[cur];
      }
      return false;
    });
    expect(chainsToSelf).toBe(false);
  });
});

describe("edge-kind filtering (map declutter)", () => {
  it("hidden kinds leave the model; nodes stay", async () => {
    const { buildGraphModel } = await import("@/graph/model");
    const nodes = [n("u", "user_account"), n("g", "group"), n("ou", "organizational_unit")];
    const edges = [e("member_of", "u", "g"), e("contains_ou", "ou", "u")];
    const all = buildGraphModel(nodes, edges, "all", null);
    expect(all.visibleEdges).toHaveLength(2);
    const filtered = buildGraphModel(nodes, edges, "all", null, "", new Set(["contains_ou"]));
    expect(filtered.visibleEdges.map((x) => x.kind)).toEqual(["member_of"]);
    expect(filtered.visibleNodes).toHaveLength(3); // nodes never disappear
  });
});

describe("scoped visibility (BloodHound-style explore)", () => {
  it("with a scope, only scope nodes and edges render", async () => {
    const { buildGraphModel } = await import("@/graph/model");
    const nodes = [n("u", "user_account"), n("g", "group"), n("x", "host_windows")];
    const edges = [e("member_of", "u", "g"), e("admin_to", "u", "x")];
    const scoped = buildGraphModel(nodes, edges, "all", null, "", undefined, {
      nodeIds: new Set(["u", "g"]),
      edgeIds: new Set(["u|member_of|g"]),
    });
    expect(scoped.visibleNodes.map((x) => x.id).sort()).toEqual(["g", "u"]);
    expect(scoped.visibleEdges.map((x) => x.id)).toEqual(["u|member_of|g"]);
  });

  it("an empty scope renders nothing (hide-all with no reveal yet)", async () => {
    const { buildGraphModel } = await import("@/graph/model");
    const nodes = [n("u", "user_account"), n("g", "group")];
    const edges = [e("member_of", "u", "g")];
    const scoped = buildGraphModel(nodes, edges, "all", null, "", undefined, {
      nodeIds: new Set(),
      edgeIds: new Set(),
    });
    expect(scoped.visibleNodes).toHaveLength(0);
    expect(scoped.visibleEdges).toHaveLength(0);
  });

  it("no scope keeps the full map", async () => {
    const { buildGraphModel } = await import("@/graph/model");
    const nodes = [n("u", "user_account"), n("g", "group")];
    const edges = [e("member_of", "u", "g")];
    expect(buildGraphModel(nodes, edges, "all", null).visibleNodes).toHaveLength(2);
  });
});
