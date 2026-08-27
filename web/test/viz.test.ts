// Guards that every node kind has a real icon + color (no gray fallbacks) and
// every edge kind has a semantic style group, so the map is legible with zero
// tuning. Also checks the field schema and findings round-trip helpers.

import { describe, it, expect } from "vitest";
import { ALL_EDGE_KINDS, ALL_NODE_KINDS } from "@/domain/catalog";
import { ICONS, ICON_VARIANTS, iconDataUri, iconVariants } from "@/viz/icons";
import { EDGE_STYLE_GROUP, KIND_COLOR, kindColor } from "@/viz/viz";
import { readFindings, schemaFor, schemaKeys } from "@/domain/fieldSchema";

describe("visual encoding completeness", () => {
  it("has a distinct icon and an explicit color for every node kind", () => {
    expect(Object.keys(ICONS).length).toBe(30);
    for (const k of ALL_NODE_KINDS) {
      expect(ICONS[k], `icon for ${k}`).toBeTruthy();
      expect(KIND_COLOR[k], `color for ${k}`).toBeTruthy();
    }
  });

  it("maps every edge kind to a style group", () => {
    for (const k of ALL_EDGE_KINDS) {
      expect(EDGE_STYLE_GROUP[k], `style group for ${k}`).toBeTruthy();
    }
  });

  it("emits a usable data URI; operator color override wins over the default", () => {
    const uri = iconDataUri("domain_controller");
    expect(uri.startsWith("data:image/svg+xml,")).toBe(true);
    expect(decodeURIComponent(uri)).toContain("<svg"); // a real, parseable scene
    expect(kindColor("host_windows", "#abcdef")).toBe("#abcdef");
  });

  it("ships alternate form-factor variants for every kind, default = ICONS[kind]", () => {
    expect(Object.keys(ICON_VARIANTS).length).toBe(30);
    for (const k of ALL_NODE_KINDS) {
      const vs = ICON_VARIANTS[k];
      expect(vs.length, `variants for ${k}`).toBeGreaterThanOrEqual(1);
      for (const v of vs) {
        expect(v.variant, `variant label for ${k}`).toBeTruthy();
        expect(v.svg, `variant svg for ${k}`).toBeTruthy();
      }
      // The recommended default mirrors the first variant.
      expect(ICONS[k]).toBe(vs[0]!.svg);
      expect(iconVariants(k)).toEqual(vs.map((v) => v.variant));
    }
    // Hero hosts offer multiple form factors (monitor / laptop / all-in-one ...).
    expect(ICON_VARIANTS.host_windows.length).toBeGreaterThanOrEqual(2);
  });

  it("renders a chosen variant, falling back to the default for unknown variants", () => {
    const def = iconDataUri("host_windows");
    const alt = ICON_VARIANTS.host_windows[1]!.variant;
    expect(iconDataUri("host_windows", undefined, alt)).not.toBe(def); // alternate differs
    expect(iconDataUri("host_windows", undefined, "nope")).toBe(def); // unknown → default
    expect(iconDataUri("host_windows", undefined, undefined)).toBe(def); // none → default
  });
});

describe("field schema + findings", () => {
  it("gives every kind typed fields ending in notes, and owns 'findings'", () => {
    for (const k of ALL_NODE_KINDS) {
      const s = schemaFor(k);
      expect(s.at(-1)?.key).toBe("notes");
      expect(schemaKeys(k).has("findings")).toBe(true);
    }
    const svc = schemaFor("service").map((f) => f.key);
    expect(svc).toContain("port");
    expect(svc).toContain("cve");
  });

  it("reads findings tolerantly", () => {
    expect(readFindings({})).toEqual([]);
    expect(readFindings({ findings: "garbage" })).toEqual([]);
    const good = [{ title: "X", severity: "high", status: "open" }];
    expect(readFindings({ findings: good })).toHaveLength(1);
    expect(readFindings({ findings: [{ nope: 1 }] })).toHaveLength(0);
  });
});
