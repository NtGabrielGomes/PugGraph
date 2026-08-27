// The abuse card of the active pre-built query: what the finding means and how
// to exploit it (description + ready-to-fill commands from the abuse catalog).
// Lives in the inspector's "abuse" tab — the query list stays in the left
// column; the reading material stays here.

import { useMemo } from "react";
import { PREBUILT_QUERIES, commandsFor, fillCommand } from "@/graph/prebuiltQueries";
import { useStore } from "@/state/store";

export function AbusePanel() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const queryScope = useStore((s) => s.queryScope);

  const active = useMemo(
    () => PREBUILT_QUERIES.flatMap((g) => g.items).find((q) => q.name === queryScope?.label) ?? null,
    [queryScope],
  );

  // Template variables resolved from the campaign: the domain node, a DC, and
  // the first matched node/edge as the concrete target/source.
  const vars = useMemo(() => {
    const dom = nodes.find((n) => n.kind === "domain");
    const dc = nodes.find((n) => n.kind === "domain_controller");
    const dcIp = dc?.identity_keys.find((k) => k.kind === "ip_address")?.value;
    const firstNode = queryScope?.nodeIds[0];
    const target = nodes.find((n) => n.id === firstNode);
    const firstEdge = queryScope?.edgeIds[0];
    const edge = edges.find((e) => e.id === firstEdge);
    const edgeTarget = edge && nodes.find((n) => n.id === edge.target);
    const edgeSource = edge && nodes.find((n) => n.id === edge.source);
    return {
      domain: dom?.label,
      dc: dcIp ?? dc?.label,
      target: (edgeTarget ?? target)?.label || undefined,
      source: edgeSource?.label || undefined,
      targetDN: (edgeTarget ?? target)?.identity_keys.find((k) => k.kind === "ad_dn")?.value,
    };
  }, [nodes, edges, queryScope]);

  if (!queryScope) {
    return <p className="muted">Select a pre-built query on the left to see what it means and how to exploit it.</p>;
  }
  if (!active) {
    return (
      <p className="muted">
        Focus scope active ({queryScope.nodeIds.length} nodes) — focus scopes carry no abuse info. Pick a pre-built
        query for exploitation guidance.
      </p>
    );
  }

  return (
    <div className="abuse">
      <div className="abusetitle">{active.name}</div>
      <p className="abusedesc">{active.description}</p>
      {commandsFor(active).length === 0 && (
        <p className="muted">No canned commands for this one — investigate manually.</p>
      )}
      {commandsFor(active).map((c, i) => (
        <div key={i} className="abusecmd">
          <div className="abusecmdhead">
            <span>{c.title}</span>
            {c.tool && <span className="abusetool">{c.tool}</span>}
          </div>
          {c.description && <p className="abusecmddesc">{c.description}</p>}
          {c.command && (
            <code
              className="abusecode"
              title="Click to copy"
              onClick={() => void navigator.clipboard?.writeText(fillCommand(c.command!, vars))}
            >
              {fillCommand(c.command, vars)}
            </code>
          )}
        </div>
      ))}
    </div>
  );
}
