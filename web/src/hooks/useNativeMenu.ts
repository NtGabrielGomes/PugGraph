import { useEffect, useRef } from "react";
import { platform } from "@/io/platform";

/** The in-session actions the desktop shell's native menu can trigger. */
export interface NativeMenuActions {
  exportCampaign: () => void;
  exportReport: () => void;
  exportMap: () => void;
  fit: () => void;
  commandPalette: () => void;
  appearance: () => void;
  reload: () => void;
  openCampaign: () => void;
  newCampaign: () => void;
}

const MENU_ACTIONS: Record<string, keyof NativeMenuActions> = {
  export_campaign: "exportCampaign",
  export_report: "exportReport",
  export_map: "exportMap",
  fit: "fit",
  command_palette: "commandPalette",
  appearance: "appearance",
  reload: "reload",
  open_campaign: "openCampaign",
  new_campaign: "newCampaign",
};

/** Bridge native menu events to the current session's actions. A ref keeps the
 * subscription stable while always dispatching to the latest callbacks. */
export function useNativeMenu(actions: NativeMenuActions): void {
  const ref = useRef(actions);
  ref.current = actions;
  useEffect(() => {
    const un = platform.onMenu((id) => {
      const key = MENU_ACTIONS[id];
      if (key) ref.current[key]();
    });
    return () => void un?.then((fn) => fn());
  }, []);
}
