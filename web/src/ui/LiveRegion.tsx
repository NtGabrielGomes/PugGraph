import { useSyncExternalStore } from "react";
import { getAnnouncement, subscribeAnnounce } from "@/ui/announce";

export function LiveRegion() {
  const msg = useSyncExternalStore(subscribeAnnounce, getAnnouncement, () => "");
  return (
    <div className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
      {msg}
    </div>
  );
}
