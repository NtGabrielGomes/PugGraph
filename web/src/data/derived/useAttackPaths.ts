// The surfaced attack paths as a hook. Pathfinding is expensive (Dijkstra per
// foothold×goal), so it is computed off the edit hot path — the store recomputes
// it debounced after mutations settle and after remote ops, never synchronously
// on a keystroke. Consumers read the latest result through this hook.

import { useStore } from "@/state/store";
import type { AttackPath } from "@/graph/attackPaths";

export function useAttackPaths(): AttackPath[] {
  return useStore((s) => s.attackPaths);
}
