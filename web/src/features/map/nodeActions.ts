// The actions offered for a single node, shared by every node context menu in
// the app — the network navigator list and the topology map — so a right-click
// means the same thing everywhere. State is read and mutated through the store
// and map directly, so callers only need to supply the node id.

import { useStore } from "@/state/store";
import { mapApi } from "@/features/map/mapApi";
import { compromiseColor } from "@/viz/viz";
import type { MenuAction } from "@/ui";
import type { CompromiseLevel } from "@/domain/types";

// Access levels worth assigning straight from the menu. "unknown" (the default)
// and "none" (explicit clear) are reached by cycling the row dot, not here.
const ASSIGNABLE_LEVELS: CompromiseLevel[] = ["user", "admin", "system", "domain_admin"];

export function buildNodeActions(id: string): MenuAction[] {
  const store = useStore.getState();
  const node = store.nodes.find((n) => n.id === id);
  const owned = !!node && node.compromise_level !== "unknown" && node.compromise_level !== "none";
  const setLevel = (level: CompromiseLevel): MenuAction => ({
    label: `Set ${level}`,
    dot: compromiseColor(level),
    run: () => store.setCompromise(id, level),
  });

  return [
    { label: "Inspect", icon: "focus", run: () => store.select(id) },
    { label: "Center on map", icon: "fit", run: () => mapApi.centerOn?.(id) },
    { label: "Clone", icon: "clone", run: () => store.cloneNode(id) },
    {
      label: "Add tag...",
      icon: "tag",
      run: () => {
        const tag = window.prompt("Tag");
        if (tag?.trim()) store.addTag(id, tag.trim());
      },
    },
    { separator: true },
    owned
      ? { label: "Mark as clean", dot: compromiseColor("none"), run: () => store.setCompromise(id, "none") }
      : { label: "\u2620 Mark as compromised", run: () => store.setCompromise(id, "user") },
    ...ASSIGNABLE_LEVELS.map(setLevel),
    { separator: true },
    { label: "Delete", icon: "trash", danger: true, run: () => store.removeNode(id) },
  ];
}
