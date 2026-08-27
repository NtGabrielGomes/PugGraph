import { useState } from "react";
import { useStore, type Lens } from "@/state/store";
import { Popover, Icon } from "@/ui";

const LENSES: { id: Lens; label: string; title: string }[] = [
  { id: "all", label: "All", title: "Everything" },
  { id: "compromised", label: "Compromised", title: "Only hosts with a foothold" },
  { id: "entry", label: "Entry", title: "How we got in" },
  { id: "ad", label: "AD", title: "Active Directory objects" },
  { id: "unconfirmed", label: "Unconfirmed", title: "What still needs verification" },
];

export function Lenses() {
  const lens = useStore((s) => s.lens);
  const setLens = useStore((s) => s.setLens);
  const filterQuery = useStore((s) => s.filterQuery);
  const setFilterQuery = useStore((s) => s.setFilterQuery);
  const savedFilters = useStore((s) => s.savedFilters);
  const saveFilter = useStore((s) => s.saveFilter);
  const removeFilter = useStore((s) => s.removeFilter);

  const [at, setAt] = useState<{ x: number; y: number } | null>(null);
  const [draft, setDraft] = useState(filterQuery);
  const [name, setName] = useState("");

  const open = (e: React.MouseEvent) => {
    setDraft(filterQuery);
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    setAt({ x: r.right - 280, y: r.bottom + 6 });
  };

  return (
    <div className="lenses">
      {LENSES.map((l) => (
        <button key={l.id} title={l.title} className={lens === l.id ? "active" : ""} onClick={() => setLens(l.id)}>
          {l.label}
        </button>
      ))}
      <button
        className={"filterbtn" + (filterQuery ? " active" : "")}
        title="Structured filter (kind:, compromise:, tag:, has:, text)"
        aria-label="Structured filter"
        onClick={open}
      >
        <Icon name="filter" size={14} />{filterQuery ? " •" : ""}
      </button>
      {at && (
        <Popover x={at.x} y={at.y} onClose={() => setAt(null)} label="Filter" className="filterpop">
          <div className="filterbody">
            <input
              className="filterinput"
              autoFocus
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") setFilterQuery(draft.trim()); }}
              placeholder="compromise:>=admin tag:dmz has:finding"
              aria-label="Filter query"
            />
            <div className="filterhint">
              <code>kind:</code> <code>compromise:&gt;=admin</code> <code>tag:</code> <code>confidence:</code> <code>has:finding</code> * text
            </div>
            <div className="filteractions">
              <button onClick={() => setFilterQuery(draft.trim())}>Apply</button>
              <button className="ghost" onClick={() => { setDraft(""); setFilterQuery(""); }}>Clear</button>
            </div>
            {savedFilters.length > 0 && (
              <div className="savedfilters">
                {savedFilters.map((f) => (
                  <div key={f.id} className="savedrow">
                    <button className="savedapply" title={f.query} onClick={() => { setDraft(f.query); setFilterQuery(f.query); }}>{f.name}</button>
                    <button className="x" title="Remove" onClick={() => removeFilter(f.id)}>x</button>
                  </div>
                ))}
              </div>
            )}
            <form
              className="savecur"
              onSubmit={(e) => { e.preventDefault(); if (name.trim() && draft.trim()) { saveFilter(name.trim(), draft.trim()); setName(""); } }}
            >
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="name to save this filter" aria-label="Filter name" />
              <button type="submit" disabled={!name.trim() || !draft.trim()}>Save</button>
            </form>
          </div>
        </Popover>
      )}
    </div>
  );
}
