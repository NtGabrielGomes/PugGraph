import { describe, it, expect } from "vitest";
import { asOf, timeBounds } from "@/graph/timeline";

const item = (id: string, first_seen: number) => ({ id, provenance: { first_seen } });

describe("timeline scrubbing (as-of-T view)", () => {
  it("filters entities to those that existed at or before T", () => {
    const items = [item("a", 100), item("b", 200), item("c", 300)];
    expect(asOf(items, 250).map((i) => i.id)).toEqual(["a", "b"]);
    expect(asOf(items, 99).map((i) => i.id)).toEqual([]);
    expect(asOf(items, null)).toHaveLength(3); // null = now
  });

  it("computes the timestamp span of the event list", () => {
    expect(timeBounds([{ at: 5 }, { at: 9 }, { at: 2 }])).toEqual({ min: 2, max: 9 });
    expect(timeBounds([])).toBeNull();
  });
});
