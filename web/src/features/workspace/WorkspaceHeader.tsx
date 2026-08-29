import { useRef } from "react";
import { Lenses } from "@/features/search/Lenses";
import { SearchBar } from "@/features/search/SearchBar";
import { Icon } from "@/ui";
import { useStore } from "@/state/store";
import { platform } from "@/io/platform";

const STATUS_LABEL: Record<string, string> = {
  disconnected: "no campaign open",
  local: "local campaign — saved to your folder",
};

export function WorkspaceHeader({
  leftOpen,
  rightOpen,
  onToggleLeft,
  onToggleRight,
  onExport,
  onReport,
}: {
  leftOpen: boolean;
  rightOpen: boolean;
  onToggleLeft: () => void;
  onToggleRight: () => void;
  onExport: () => void;
  onReport: () => void;
}) {
  const status = useStore((s) => s.status);
  const campaignId = useStore((s) => s.campaign?.campaignId ?? "");
  const nodes = useStore((s) => s.nodes.length);
  const edges = useStore((s) => s.edges.length);
  const paths = useStore((s) => s.attackPaths.length);
  const leave = useStore((s) => s.leave);
  const importScans = useStore((s) => s.importScans);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const statusLabel = STATUS_LABEL[status] ?? status;

  return (
    <header>
      <div className="hgroup hbrand">
        <button
          className="paneltoggle"
          aria-pressed={leftOpen}
          aria-label={leftOpen ? "Hide network panel" : "Show network panel"}
          title="Toggle the left network panel"
          onClick={onToggleLeft}
        ><Icon name="chevron-left" size={14} className={leftOpen ? "" : "flip"} /></button>
        <span className={`livedot ${status}`} role="status" title={statusLabel}>
          <span className="visually-hidden">{statusLabel}</span>
        </span>
        <span className="campid">{campaignId}</span>
        <span className="stats" title="Live campaign size">
          {nodes} nodes * {edges} edges * {paths} paths
        </span>
      </div>

      <div className="hgroup hsearch">
        <SearchBar />
      </div>

      <div className="hgroup hview">
        <Lenses />
        <div className="hactions">
          <button
            onClick={() => {
              if (platform.isTauri())
                  void platform.openScanFiles().then((f) => f.length && importScans(f));
              else
                  fileRef.current?.click();
            }}
            title="Import Nmap / BloodHound / Pughound / NetExec / Nessus output (SharpHound .zip accepted)"
          ><Icon name="import" size={14} /> Import</button>
          <button onClick={onExport} title="Download the sovereign encrypted campaign file"><Icon name="export" size={14} /> Export</button>
          <button onClick={onReport} title="Generate the engagement report"><Icon name="report" size={14} /> Report</button>
          <button className="leave" onClick={leave} title="Disconnect and lock"><Icon name="power" size={14} /> Leave</button>
          <button
            className="paneltoggle"
            aria-pressed={rightOpen}
            aria-label={rightOpen ? "Hide inspector panel" : "Show inspector panel"}
            title="Toggle the right inspector panel"
            onClick={onToggleRight}
          ><Icon name="chevron-right" size={14} className={rightOpen ? "" : "flip"} /></button>
        </div>
      </div>
      <input
        ref={fileRef}
        type="file"
        multiple
        accept=".xml,.json,.nessus,.txt,.log,.zip"
        style={{ display: "none" }}
        onChange={(e) => {
          const files = e.target.files ? Array.from(e.target.files) : [];
          if (files.length)
              importScans(files);
          e.target.value = "";
        }}
      />
    </header>
  );
}
