// Desktop-shell bridges. In the browser these are inert; inside Tauri they wire
// native launch/file opens into the store, where the Dashboard consumes them
// once an identity is unlocked.

import { useEffect } from "react";
import { platform } from "@/io/platform";
import { useStore, type PendingOpenTarget } from "@/state/store";

async function resolveTarget(target: string): Promise<PendingOpenTarget | null> {
  const file = await platform.readCampaignPath(target);
  return file ? { kind: "file", file } : null;
}

/** Mounts the native open bridges once (no-op in a plain browser). */
export function useDesktopOpen(): void {
  const setPendingOpen = useStore((s) => s.setPendingOpen);
  useEffect(() => {
    if (!platform.isTauri()) return;
    let cancelled = false;
    const set = (t: PendingOpenTarget | null) => {
      if (t && !cancelled) setPendingOpen(t);
    };
    // A campaign handed to us at launch (double-clicked `.camp` / deep link)
    // before the live listeners below were attached.
    void platform.takePendingOpen().then((t) => {
      if (t) void resolveTarget(t).then(set);
    });
    const unFile = platform.onOpenFile((p) => void resolveTarget(p).then(set));
    return () => {
      cancelled = true;
      void unFile?.then((fn) => fn());
    };
  }, [setPendingOpen]);
}
