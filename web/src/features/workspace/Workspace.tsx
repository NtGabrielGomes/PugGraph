import { useEffect, useState } from "react";
import { ActivityStream } from "@/features/activity/ActivityStream";
import { BulkBar } from "@/features/map/BulkBar";
import { CommandPalette } from "@/features/search/CommandPalette";
import { GraphNav } from "@/features/navigator/GraphNav";
import { PrebuiltQueries } from "@/features/search/PrebuiltQueries";
import { InspectorTabs } from "@/features/inspector/InspectorTabs";
import { NetworkMap } from "@/features/map/NetworkMap";
import { ReportPanel } from "@/features/report/ReportPanel";
import { Toolbar } from "@/features/map/Toolbar";
import { WorkspaceHeader } from "@/features/workspace/WorkspaceHeader";
import { mapApi } from "@/features/map/mapApi";
import { ErrorBoundary, LiveRegion } from "@/ui";
import { useStore } from "@/state/store";
import { useGlobalKeys } from "@/hooks/useGlobalKeys";
import { useNativeMenu } from "@/hooks/useNativeMenu";
import { platform } from "@/io/platform";

export function Workspace() {
  const leave = useStore((s) => s.leave);
  
  const exportCampaignFile = useStore((s) => s.exportCampaignFile);
  
  const campaignId = useStore((s) => s.campaign?.campaignId ?? "");
  const setCreator = useStore((s) => s.setCreator);
  const selectedId = useStore((s) => s.selectedId);

  const [report, setReport] = useState(false);
  const [palette, setPalette] = useState(false);
  const [leftOpen, setLeftOpen] = useState(true);
  const [rightOpen, setRightOpen] = useState(true);
  const [streamOpen, setStreamOpen] = useState(true);
  const tab = useStore((s) => s.inspectorTab);
  const setTab = useStore((s) => s.setInspectorTab);

  useGlobalKeys({ openAdd: (m) => setCreator(m), openPalette: () => setPalette(true) });

  useEffect(() => {
    if (selectedId) { setTab("inspect"); setRightOpen(true); }
  }, [selectedId]);

  const exportFile = () => {
    const bytes = exportCampaignFile();
    if (bytes)
        void platform.saveCampaignFile(`${campaignId || "campaign"}.camp`, bytes);
  };

  useNativeMenu({
    exportCampaign: exportFile,
    exportReport: () => setReport(true),
    exportMap: () => mapApi.exportImage?.(),
    fit: () => mapApi.fit?.(),
    commandPalette: () => setPalette(true),
    appearance: () => useStore.getState().setAppearanceOpen(true),
    reload: () => window.location.reload(),
    openCampaign: () =>
      void platform.openCampaignFile().then((f) => {
        if (f) { useStore.getState().setPendingOpen({ kind: "file", file: f }); leave(); }
      }),
    newCampaign: leave,
  });

  const appClass =
    "app" + (leftOpen ? "" : " noleft") + (rightOpen ? "" : " noright") + (streamOpen ? "" : " streamclosed");

  return (
    <div className={appClass}>
      <LiveRegion />
      <WorkspaceHeader
        leftOpen={leftOpen}
        rightOpen={rightOpen}
        onToggleLeft={() => setLeftOpen((v) => !v)}
        onToggleRight={() => setRightOpen((v) => !v)}
        onExport={exportFile}
        onReport={() => setReport(true)}
      />
      {report && <ReportPanel onClose={() => setReport(false)} />}
      {palette && <CommandPalette onReport={() => setReport(true)} onClose={() => setPalette(false)} />}

      <div className="leftcol">
        <ErrorBoundary label="Queries">
          <PrebuiltQueries />
        </ErrorBoundary>
        <ErrorBoundary label="Navigator">
          <GraphNav />
        </ErrorBoundary>
      </div>
      <div className="mapcell">
        <ErrorBoundary label="Map">
          <NetworkMap />
        </ErrorBoundary>
        <Toolbar />
      </div>
      <div className="rightcol">
        <ErrorBoundary label="Inspector">
          <InspectorTabs tab={tab} setTab={setTab} />
        </ErrorBoundary>
      </div>

      <BulkBar />
      <ActivityStream open={streamOpen} onToggle={() => setStreamOpen((v) => !v)} />
    </div>
  );
}
