import { useState } from "react";
import { useStore } from "@/state/store";
import { COMPROMISE_LEVELS, compromiseColor } from "@/viz/viz";
import { mapApi } from "@/features/map/mapApi";
import { Select } from "@/ui";
import type { CompromiseLevel } from "@/domain/types";

export function BulkBar() {
  const ids = useStore((s) => s.bulkIds);
  const bulkSetCompromise = useStore((s) => s.bulkSetCompromise);
  const bulkAddTag = useStore((s) => s.bulkAddTag);
  const bulkRemove = useStore((s) => s.bulkRemove);
  const [tag, setTag] = useState("");

  if (ids.length < 2)
      return null;

  const clear = () => mapApi.clearSelection?.();

  return (
    <div className="bulkbar" role="region" aria-label={`${ids.length} nodes selected`}>
      <span className="bulkcount">{ids.length} selected</span>
      <Select
        ariaLabel="Set compromise for selection"
        value=""
        placeholder="Set compromise..."
        onChange={(v) => bulkSetCompromise(ids, v as CompromiseLevel)}
        options={COMPROMISE_LEVELS.map((l) => ({ value: l, label: l, color: compromiseColor(l) }))}
      />
      <form
        className="bulkfield"
        onSubmit={(e) => {
          e.preventDefault();
          if (tag.trim()) { bulkAddTag(ids, tag.trim()); setTag(""); }
        }}
      >
        <input value={tag} onChange={(e) => setTag(e.target.value)} placeholder="add tag..." aria-label="Add a tag to the selection" />
        <button type="submit">Tag</button>
      </form>
      <button type="button" className="danger" onClick={() => { bulkRemove(ids); clear(); }}>Delete</button>
      <button type="button" className="ghost" onClick={clear}>Clear</button>
    </div>
  );
}
