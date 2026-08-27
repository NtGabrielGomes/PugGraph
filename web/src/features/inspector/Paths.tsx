// The attack-paths tab: cheapest routes from a foothold to a goal, computed from
// the live graph. Interaction is simple — click a path to highlight its whole
// chain on the map and frame it; star it to save a named route the team shares.
// Capable underneath — pin a foothold, pin a goal, and exclude chokepoints
// ("assume EDR / 2FA here") to ask what the path becomes when a node is blocked.
// A goal is any high-value asset OR anything tagged #goal / #crown-jewel.

import { useMemo, useState } from "react";
import { useStore } from "@/state/store";
import { surfaceAttackPaths } from "@/graph/attackPaths";
import { isHighValue, type GraphNode } from "@/domain/types";
import { Icon, Select } from "@/ui";

const sameHops = (a: string[], b: string[] | null): boolean =>
  !!b && a.length === b.length && a.every((x, i) => x === b[i]);
const GOAL_TAGS = new Set(["goal", "crown-jewel"]);
const isGoalNode = (n: GraphNode): boolean => isHighValue(n.kind) || n.tags.some((t) => GOAL_TAGS.has(t));

export function Paths() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const auto = useStore((s) => s.attackPaths);
  const pathmarks = useStore((s) => s.pathmarks);
  const highlightPath = useStore((s) => s.highlightPath);
  const setHighlightPath = useStore((s) => s.setHighlightPath);
  const savePath = useStore((s) => s.savePath);
  const removePath = useStore((s) => s.removePath);
  const [foothold, setFoothold] = useState("");
  const [goal, setGoal] = useState("");
  const [avoid, setAvoid] = useState<string[]>([]);
  const [avoidPick, setAvoidPick] = useState("");

  const label = (id: string) => nodes.find((n) => n.id === id)?.label ?? id;
  const compromised = useMemo(
    () => nodes.filter((n) => n.compromise_level !== "unknown" && n.compromise_level !== "none"),
    [nodes],
  );
  const goals = useMemo(() => nodes.filter(isGoalNode), [nodes]);
  const sorted = useMemo(() => [...nodes].sort((a, b) => (a.label || a.id).localeCompare(b.label || b.id)), [nodes]);

  // The store already computes the all-footholds set with no constraints; only
  // recompute when the operator pins a foothold or excludes a chokepoint.
  const custom = !!foothold || avoid.length > 0;
  const computed = useMemo(
    () => (custom ? surfaceAttackPaths(nodes, edges, { footholdId: foothold || null, avoid: new Set(avoid) }) : auto),
    [custom, foothold, avoid, nodes, edges, auto],
  );
  const paths = useMemo(() => (goal ? computed.filter((p) => p.to === goal) : computed), [computed, goal]);

  const toggle = (hops: string[]) => setHighlightPath(sameHops(hops, highlightPath) ? null : hops);
  const addAvoid = (id: string) => { if (id && !avoid.includes(id)) setAvoid((a) => [...a, id]); setAvoidPick(""); };

  return (
    <section className="pathspanel">
      <div className="pathshead">
        <h2>Attack paths</h2>
      </div>

      <div className="pathopts">
        <label className="popt">
          <span>From</span>
          <Select
            value={foothold}
            ariaLabel="Foothold"
            onChange={setFoothold}
            options={[{ value: "", label: "any foothold" }, ...compromised.map((n) => ({ value: n.id, label: n.label || n.id }))]}
          />
        </label>
        <label className="popt">
          <span>To</span>
          <Select
            value={goal}
            ariaLabel="Goal"
            onChange={setGoal}
            options={[{ value: "", label: "any goal" }, ...goals.map((n) => ({ value: n.id, label: n.label || n.id }))]}
          />
        </label>
      </div>

      <div className="pathavoid">
        <label className="popt">
          <span>Avoid</span>
          <Select
            value={avoidPick}
            placeholder="+ exclude a chokepoint..."
            ariaLabel="Exclude a node (assume blocked)"
            onChange={addAvoid}
            options={sorted.filter((n) => !avoid.includes(n.id)).map((n) => ({ value: n.id, label: n.label || n.id }))}
          />
        </label>
        {avoid.length > 0 && (
          <div className="chips">
            {avoid.map((id) => (
              <span key={id} className="chip tag">{label(id)}<button type="button" className="x" onClick={() => setAvoid((a) => a.filter((x) => x !== id))} aria-label="Stop avoiding">×</button></span>
            ))}
          </div>
        )}
      </div>

      {paths.length === 0 && (
        <p className="muted">No path to a goal yet. Compromise a foothold and tag a target <code>#goal</code> or <code>#crown-jewel</code>{avoid.length ? " (or relax the avoid set)" : ""}.</p>
      )}
      <ul className="paths">
        {paths.slice(0, 12).map((p, i) => (
          <li key={i} className={sameHops(p.hops, highlightPath) ? "hi" : ""} onClick={() => toggle(p.hops)}>
            <div className="pathchain">{p.hops.map(label).join(" → ")}</div>
            <div className="pathmeta">
              <span className="len">{p.hops.length - 1} hop{p.hops.length - 1 === 1 ? "" : "s"}</span>
              <span className="cost">cost {p.cost.toFixed(1)}</span>
              <button
                type="button"
                className="star"
                title="Save this path for the team"
                aria-label="Save path"
                onClick={(e) => { e.stopPropagation(); savePath(`${label(p.from)} → ${label(p.to)}`, p.hops); }}
              ><Icon name="star" size={13} /></button>
            </div>
          </li>
        ))}
      </ul>
      {pathmarks.length > 0 && (
        <>
          <h3 className="lbl pathsub">Saved paths</h3>
          <ul className="paths saved">
            {pathmarks.map((pm) => (
              <li key={pm.id} className={sameHops(pm.hops, highlightPath) ? "hi" : ""} onClick={() => toggle(pm.hops)}>
                <div className="pathchain">{pm.name}</div>
                <div className="pathmeta">
                  <span className="len">{pm.hops.length - 1} hops</span>
                  <button
                    type="button"
                    className="x"
                    title="Remove saved path"
                    aria-label="Remove saved path"
                    onClick={(e) => { e.stopPropagation(); removePath(pm.id); if (sameHops(pm.hops, highlightPath)) setHighlightPath(null); }}
                  >×</button>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
