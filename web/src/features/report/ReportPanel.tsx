import { useMemo } from "react";
import { buildReport } from "@/io/report";
import { useStore } from "@/state/store";
import { platform } from "@/io/platform";
import { Dialog } from "@/ui";

export function ReportPanel({ onClose }: { onClose: () => void }) {
  const nodes = useStore((s) => s.nodes);
  const credentials = useStore((s) => s.credentials);
  const events = useStore((s) => s.events);
  const attackPaths = useStore((s) => s.attackPaths);
  const roster = useStore((s) => s.roster);
  const campaignId = useStore((s) => s.campaign?.campaignId ?? "");

  const { markdown, data } = useMemo(
    () =>
      buildReport({
        campaignId,
        generatedAt: Date.now(),
        nodes,
        credentials,
        events,
        attackPaths,
        operators: roster
          .filter((e) => e.status === "active")
          .map((e) => ({ operatorId: e.operator_id, displayName: e.display_name })),
      }),
    [campaignId, nodes, credentials, events, attackPaths, roster],
  );

  const print = (): void => {
    const w = window.open("", "_blank");
    if (!w)
        return;

    const doc = w.document;
    const pre = doc.createElement("pre");
    pre.style.font = "13px/1.55 ui-monospace,monospace";
    pre.style.whiteSpace = "pre-wrap";
    pre.style.padding = "28px";
    pre.style.maxWidth = "80ch";
    pre.style.margin = "auto";
    pre.textContent = markdown;

    doc.title = `${campaignId} report`;
    if (doc.body) {
      doc.body.style.margin = "0";
      doc.body.appendChild(pre);
    }

    w.focus();
    w.print();
  };

  return (
    <Dialog className="report" title="Campaign report" onClose={onClose}>
      <div className="modalactions">
        <span className="spacer" />
        <button type="button" onClick={() => void platform.saveTextFile(`report-${campaignId}.md`, markdown)}>⤓ Markdown</button>
        <button type="button" onClick={() => void platform.saveTextFile(`report-${campaignId}.json`, JSON.stringify(data, null, 2))}>⤓ JSON</button>
        <button type="button" onClick={print}>Print</button>
        <button type="button" onClick={onClose}>Close</button>
      </div>
      <pre className="reportpreview" tabIndex={0}>{markdown}</pre>
    </Dialog>
  );
}
