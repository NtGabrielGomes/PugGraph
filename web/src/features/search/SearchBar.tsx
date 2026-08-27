import { useMemo, useState } from "react";
import { useStore } from "@/state/store";
import { Icon } from "@/ui/Icon";
import { incidentScope } from "@/graph/prebuiltQueries";
import type { SearchType } from "@/graph/search";

const TYPES: { id: "" | SearchType; label: string }[] = [
  { id: "", label: "All" },
  { id: "node", label: "Assets" },
  { id: "credential", label: "Creds" },
  { id: "event", label: "Events" },
];

export function SearchBar() {
  const [q, setQ] = useState("");
  const [type, setType] = useState<"" | SearchType>("");
  const searchEntities = useStore((s) => s.searchEntities);
  const select = useStore((s) => s.select);
  const hideAll = useStore((s) => s.hideAll);
  const edges = useStore((s) => s.edges);
  const setQueryScope = useStore((s) => s.setQueryScope);
  const rev = useStore((s) => s.rev);

  const hits = useMemo(
    () => (q.trim() ? searchEntities(q, type ? { type } : undefined).slice(0, 12) : []),
    [q, type, rev, searchEntities],
  );

  return (
    <div className="searchbar">
      <div className="searchinput">
        <Icon name="search" size={13} />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search assets, credentials, events..."
          spellCheck={false}
        />
        { }
        <div className="searchfilters">
          {TYPES.map((t) => (
            <button key={t.id} className={type === t.id ? "active" : ""} onClick={() => setType(t.id)} type="button" title={`Search ${t.label.toLowerCase()}`}>
              {t.label}
            </button>
          ))}
        </div>
      </div>
      {hits.length > 0 && (
        <ul className="searchresults">
          {hits.map((h) => (
            <li
              key={h.id}
              onClick={() => {
                const target = h.type === "node" ? h.id : h.nodeId;
                if (target) {
                  // With the map hidden (BloodHound-style explore), a search hit
                  // IS the reveal: scope the map to the hit's neighborhood.
                  if (hideAll) {
                    const s = incidentScope([target], edges);
                    setQueryScope({ label: `search:${target}`, nodeIds: s.nodeIds, edgeIds: s.edgeIds });
                  }
                  select(target);
                }
                setQ("");
              }}
            >
              <span className={`badge b-${h.type}`}>{h.type}</span>
              <span className="lbl">{h.label || h.id}</span>
              <small className="muted">{h.kind}</small>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
