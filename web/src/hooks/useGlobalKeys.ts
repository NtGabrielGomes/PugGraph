// The workspace's global keyboard map. Mounted once in the live workspace, it
// gives the whole tool keyboard parity with the mouse: jump to search, open the
// command palette, fit the map, and cancel/clear with Escape. Keystrokes are ignored while typing in a field so capture is
// never stolen from the quick-add bar, inspector, or any form.

import { useEffect } from "react";
import { mapApi } from "@/features/map/mapApi";
import { useStore } from "@/state/store";

export interface MapTools {
  /** Wired once the command palette exists (M5); absent before then. */
  openPalette?: () => void;
}

const isTyping = (): boolean => {
  const el = document.activeElement as HTMLElement | null;
  if (!el) return false;
  const tag = el.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
};

export function useGlobalKeys(tools: MapTools) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // The command palette is reachable even while typing (⌘K / Ctrl-K).
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K") && tools.openPalette) {
        e.preventDefault();
        tools.openPalette();
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      if (e.key === "Escape") {
        useStore.getState().select(null);
        return;
      }
      if (isTyping()) return;

      switch (e.key) {
        case "/":
          e.preventDefault();
          document.querySelector<HTMLInputElement>(".searchinput input")?.focus();
          break;
        case "f": e.preventDefault(); mapApi.fit?.(); break;
        case "g":
          e.preventDefault();
          document.querySelector<HTMLElement>('.ovlist[role="tree"]')?.focus();
          break;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [tools]);
}
