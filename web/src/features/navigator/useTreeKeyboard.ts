// Keyboard navigation for the navigator tree (ARIA `tree` pattern). Owns the
// "active" (focused) row, exposes an `activate` that the view also calls on
// click so mouse and keyboard stay in sync, and keeps the active row scrolled
// into view. The caller supplies `onActivate` for the domain effect of choosing
// a row (toggle a group, select a node); this hook only moves focus.

import { useEffect, useRef, useState } from "react";
import type { Row } from "@/features/navigator/grouping";

export function useTreeKeyboard(rows: Row[], onActivate: (row: Row) => void) {
  const [activeKey, setActiveKey] = useState<string | null>(null);
  const treeRef = useRef<HTMLDivElement | null>(null);

  const move = (delta: number) => {
    if (rows.length === 0) return;
    const current = Math.max(0, rows.findIndex((r) => r.key === activeKey));
    const next = Math.min(rows.length - 1, Math.max(0, current + delta));
    setActiveKey(rows[next]!.key);
  };

  const activate = (row: Row) => {
    setActiveKey(row.key);
    onActivate(row);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    const row = rows.find((r) => r.key === activeKey);
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        move(1);
        break;
      case "ArrowUp":
        e.preventDefault();
        move(-1);
        break;
      case "Home":
        e.preventDefault();
        if (rows[0]) setActiveKey(rows[0].key);
        break;
      case "End":
        e.preventDefault();
        if (rows.length) setActiveKey(rows[rows.length - 1]!.key);
        break;
      case "ArrowRight":
        e.preventDefault();
        if (row?.type === "group" && !row.expanded) activate(row);
        else if (row?.type === "group" && row.expanded) move(1);
        break;
      case "ArrowLeft":
        e.preventDefault();
        if (row?.type === "group" && row.expanded) activate(row);
        else if (row?.type === "node") setActiveKey(`grp:${row.group}`);
        break;
      case "Enter":
      case " ":
        e.preventDefault();
        if (row) activate(row);
        break;
    }
  };

  useEffect(() => {
    if (!activeKey || !treeRef.current) return;
    treeRef.current
      .querySelector(`[data-key="${CSS.escape(activeKey)}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [activeKey]);

  return { activeKey, setActiveKey, treeRef, onKeyDown, activate };
}
