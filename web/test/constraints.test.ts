// Cross-language parity gate for the edge-validity constraints. The web mirror
// (`catalog.ts`) and the authoritative Rust table (`domain`) are both
// checked against the SAME committed fixture, so neither side can change the
// rules without the other's test going red. See `constraints.rs` for the source
// of truth and the regeneration command.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  NODE_CLASS,
  EDGE_RULES,
  ALL_NODE_KINDS,
  ALL_EDGE_KINDS,
  edgePermits,
  edgeKindsFor,
} from "@/domain/catalog";

const sortStr = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function buildContract() {
  const node_classes: Record<string, string> = {};
  for (const k of ALL_NODE_KINDS) node_classes[k] = NODE_CLASS[k];
  const edge_rules: Record<string, unknown> = {};
  for (const k of ALL_EDGE_KINDS) {
    const r = EDGE_RULES[k];
    edge_rules[k] = {
      src_classes: [...r.src_classes].sort(sortStr),
      dst_classes: [...r.dst_classes].sort(sortStr),
      src_kinds: [...r.src_kinds].sort(sortStr),
      dst_kinds: [...r.dst_kinds].sort(sortStr),
    };
  }
  return { node_classes, edge_rules };
}

const fixturePath = fileURLToPath(
  new URL("../../crates/domain/tests/fixtures/edge_matrix.json", import.meta.url),
);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

describe("edge constraint parity with domain", () => {
  it("reproduces the committed Rust fixture exactly", () => {
    expect(buildContract()).toEqual(fixture);
  });

  it("covers every NodeKind and EdgeKind", () => {
    expect(ALL_NODE_KINDS.length).toBe(30);
    expect(ALL_EDGE_KINDS.length).toBe(64);
    for (const k of ALL_NODE_KINDS) expect(NODE_CLASS[k]).toBeTruthy();
    for (const k of ALL_EDGE_KINDS) expect(EDGE_RULES[k]).toBeTruthy();
  });

  it("matches the Rust anchor semantics", () => {
    expect(edgePermits("hosts_vm", "hypervisor", "virtual_machine")).toBe(true);
    expect(edgePermits("hosts_vm", "host_linux", "virtual_machine")).toBe(false);
    expect(edgePermits("hosts_vm", "hypervisor", "host_windows")).toBe(false);
    expect(edgePermits("trusts", "domain", "domain")).toBe(true);
    expect(edgePermits("trusts", "host_windows", "domain")).toBe(false);
    expect(edgePermits("listens_on", "service", "host_windows")).toBe(true);
    expect(edgePermits("listens_on", "host_windows", "service")).toBe(false);
    expect(edgePermits("dc_for", "domain_controller", "domain")).toBe(true);
    expect(edgePermits("admin_to", "user_account", "host_windows")).toBe(true);
    expect(edgePermits("admin_to", "host_windows", "user_account")).toBe(false);
    expect(edgePermits("custom", "service", "domain")).toBe(true);
  });

  it("filters the connect menu to sensible kinds", () => {
    const hvVm = edgeKindsFor("hypervisor", "virtual_machine");
    expect(hvVm).toContain("hosts_vm");
    expect(hvVm).not.toContain("listens_on");
    expect(hvVm).toContain("custom"); // escape hatch always offered
  });
});
