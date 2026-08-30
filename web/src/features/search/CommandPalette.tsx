import { useMemo, useState } from "react";
import { useStore } from "@/state/store";
import { mapApi } from "@/features/map/mapApi";

interface Cmd {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

const focusSel = (sel: string) => document.querySelector<HTMLElement>(sel)?.focus();

export function CommandPalette({ onReport, onClose }: { onReport: () => void; onClose: () => void }) {
  const setLens = useStore((s) => s.setLens);
  const setFilterQuery = useStore((s) => s.setFilterQuery);
  const setHighlightPath = useStore((s) => s.setHighlightPath);
  const savedFilters = useStore((s) => s.savedFilters);
  const pathmarks = useStore((s) => s.pathmarks);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);

  const commands = useMemo<Cmd[]>(
    () => [
      { id: "fit", label: "Fit graph to view", hint: "f", run: () => mapApi.fit?.() },
      { id: "arrange", label: "Rearrange map layout (spread nodes)", run: () => mapApi.autoArrange?.() },
      { id: "search", label: "Search assets", hint: "/", run: () => focusSel(".searchinput input") },
      { id: "nav", label: "Focus network navigator", hint: "g", run: () => focusSel('.ovlist[role="tree"]') },
      { id: "report", label: "Generate report", run: onReport },
      { id: "mapimg", label: "Export map image", run: () => mapApi.exportImage?.() },
      { id: "clear", label: "Clear map filter", run: () => setFilterQuery("") },
      { id: "l-all", label: "Lens: All", run: () => setLens("all") },
      { id: "l-comp", label: "Lens: Compromised", run: () => setLens("compromised") },
      { id: "l-entry", label: "Lens: Entry vectors", run: () => setLens("entry") },
      { id: "l-ad", label: "Lens: Active Directory", run: () => setLens("ad") },
      { id: "l-unc", label: "Lens: Unconfirmed", run: () => setLens("unconfirmed") },

      ...savedFilters.map((f) => ({ id: `f-${f.id}`, label: `Filter: ${f.name}`, hint: "view", run: () => setFilterQuery(f.query) })),
      ...pathmarks.map((p) => ({ id: `p-${p.id}`, label: `Path: ${p.name}`, hint: "view", run: () => setHighlightPath(p.hops) })),
    ],
    [setLens, setFilterQuery, setHighlightPath, savedFilters, pathmarks, onReport],
  );

  const filtered = commands.filter((c) => c.label.toLowerCase().includes(q.toLowerCase()));
  const run = (c?: Cmd) => { if (c) { c.run(); onClose(); } };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(filtered.length - 1, a + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
    else if (e.key === "Enter") { e.preventDefault(); run(filtered[active]); }
    else if (e.key === "Escape") { e.preventDefault(); onClose(); }
  };

  return (
    <div className="palette-backdrop" onMouseDown={onClose}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Command palette" onMouseDown={(e) => e.stopPropagation()}>
        <input
          autoFocus
          value={q}
          onChange={(e) => { setQ(e.target.value); setActive(0); }}
          onKeyDown={onKey}
          placeholder="Type a command..."
          role="combobox"
          aria-expanded
          aria-controls="palette-list"
          aria-activedescendant={filtered[active] ? `pal-${filtered[active].id}` : undefined}
        />
        <ul className="menu" id="palette-list" role="listbox" aria-label="Commands">
          {filtered.length === 0 && <li className="mhead">No matching command</li>}
          {filtered.map((c, i) => (
            <li key={c.id}>
              <button
                id={`pal-${c.id}`}
                role="option"
                aria-selected={i === active}
                className={"mitem" + (i === active ? " active" : "")}
                onMouseEnter={() => setActive(i)}
                onClick={() => run(c)}
              >
                {c.label}
                {c.hint && <span className="mkey">{c.hint}</span>}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
