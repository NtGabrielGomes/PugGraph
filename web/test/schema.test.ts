// Cross-language schema-vocabulary gate. The Rust domain is the source of truth;
// it emits crates/domain/tests/fixtures/schema.json, and this test asserts the web
// mirror (catalog.ts) reproduces the same node/edge/identity-key vocabularies — so
// adding a kind in Rust without mirroring it in the web (or vice-versa) goes red.
// See crates/domain/src/schema.rs for the source and the regeneration command.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ALL_NODE_KINDS, ALL_EDGE_KINDS, IDENTITY_KINDS } from "@/domain/catalog";

const fixture = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../crates/domain/tests/fixtures/schema.json", import.meta.url)), "utf8"),
) as { node_kinds: string[]; edge_kinds: string[]; identity_keys: string[] };

const sorted = (xs: readonly string[]) => [...xs].sort();

describe("schema vocabulary parity with the Rust core", () => {
  it("mirrors the node-kind vocabulary", () => {
    expect(sorted(ALL_NODE_KINDS)).toEqual(sorted(fixture.node_kinds));
  });
  it("mirrors the edge-kind vocabulary", () => {
    expect(sorted(ALL_EDGE_KINDS)).toEqual(sorted(fixture.edge_kinds));
  });
  it("mirrors the identity-key vocabulary", () => {
    expect(sorted(IDENTITY_KINDS.map((k) => k.kind))).toEqual(sorted(fixture.identity_keys));
  });
});
