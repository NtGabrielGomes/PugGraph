// Shared appearance settings. Color and glyph per node kind are team-wide
// (persisted in the campaign doc's `theme` container), so the whole crew reads
// the same visual language. Defaults are already correct; this only captures
// deliberate overrides. Reset returns a kind to its baked-in default.

import { ALL_NODE_KINDS, nodeKindLabel } from "@/domain/catalog";
import { useStore } from "@/state/store";
import { KIND_COLOR, kindColor } from "@/viz/viz";
import { iconDataUri, iconVariants } from "@/viz/icons";
import type { NodeKind } from "@/domain/types";
import { Dialog, Select } from "@/ui";

export function VizSettings({ onClose }: { onClose: () => void }) {
  const theme = useStore((s) => s.theme);
  const setThemeColor = useStore((s) => s.setThemeColor);
  const setThemeGlyph = useStore((s) => s.setThemeGlyph);
  const setThemeVariant = useStore((s) => s.setThemeVariant);

  return (
    <Dialog
      className="viz"
      title="Appearance * shared with the team"
      subtitle="Overrides are optional and sync to everyone."
      onClose={onClose}
    >
      <div className="vizgrid">
          {ALL_NODE_KINDS.map((k) => {
            const color = kindColor(k, theme.colors[k]);
            const glyph = (theme.glyphs[k] ?? k) as NodeKind;
            const variant = theme.variants[k];
            const variantOpts = iconVariants(glyph); // form factors of the shown glyph
            const overridden =
              theme.colors[k] !== undefined || theme.glyphs[k] !== undefined || theme.variants[k] !== undefined;
            return (
              <div className="vizrow" key={k}>
                <span className="vizicon" style={{ background: "var(--surface-2)" }}>
                  <img alt="" src={iconDataUri(k, glyph, variant)} />
                </span>
                <span className="vizname" title={k}>{nodeKindLabel(k)}</span>
                <input
                  type="color"
                  value={color}
                  onChange={(e) => setThemeColor(k, e.target.value === KIND_COLOR[k] ? undefined : e.target.value)}
                  title="Color"
                />
                <Select
                  size="sm"
                  ariaLabel={`${nodeKindLabel(k)} glyph — which kind's icon to draw`}
                  value={glyph}
                  onChange={(v) => setThemeGlyph(k, (v as NodeKind) === k ? undefined : (v as NodeKind))}
                  options={ALL_NODE_KINDS.map((g) => ({ value: g, label: nodeKindLabel(g) }))}
                />
                <Select
                  size="sm"
                  ariaLabel={`${nodeKindLabel(k)} variant — icon form factor`}
                  value={variant ?? ""}
                  disabled={variantOpts.length < 2}
                  onChange={(v) => setThemeVariant(k, v || undefined)}
                  options={[{ value: "", label: "default" }, ...variantOpts.map((v) => ({ value: v, label: v }))]}
                />
                <button
                  type="button"
                  className="vizreset"
                  disabled={!overridden}
                  onClick={() => { setThemeColor(k, undefined); setThemeGlyph(k, undefined); setThemeVariant(k, undefined); }}
                  title="Reset to default"
                >↺</button>
              </div>
            );
          })}
        </div>
      <div className="modalactions">
        <button type="button" onClick={onClose}>Done</button>
      </div>
    </Dialog>
  );
}
