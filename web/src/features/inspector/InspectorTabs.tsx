import { AbusePanel } from "@/features/inspector/AbusePanel";
import { CredentialVault } from "@/features/inspector/CredentialVault";
import { Paths } from "@/features/inspector/Paths";
import { SidePanel } from "@/features/inspector/SidePanel";
import { TeamPanel } from "@/features/inspector/TeamPanel";
import { Icon } from "@/ui";
import { useStore, type InspectorTab } from "@/state/store";

export type { InspectorTab };

const TABS: { id: InspectorTab; label: string; icon: Parameters<typeof Icon>[0]["name"] }[] = [
  { id: "inspect", label: "Inspect", icon: "focus" },
  { id: "abuse", label: "Abuse", icon: "alert" },
  { id: "paths", label: "Paths", icon: "path" },
  { id: "vault", label: "Vault", icon: "key" },
  { id: "team", label: "Team", icon: "team" },
];

export function InspectorTabs({ tab, setTab }: { tab: InspectorTab; setTab: (t: InspectorTab) => void }) {
  const pathCount = useStore((s) => s.attackPaths.length);
  const credCount = useStore((s) => s.credentials.length);
  const teamCount = useStore((s) => s.roster.filter((r) => r.status === "active").length);
  const scoped = useStore((s) => (s.queryScope ? s.queryScope.nodeIds.length + s.queryScope.edgeIds.length : 0));
  const counts: Record<InspectorTab, number | null> = {
    inspect: null, abuse: scoped || null, paths: pathCount, vault: credCount, team: teamCount,
  };
  return (
    <>
      <div className="insptabs" role="tablist" aria-label="Inspector">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={"insptab" + (tab === t.id ? " active" : "")}
            onClick={() => setTab(t.id)}
          >
            <Icon name={t.icon} size={14} />
            <span>{t.label}</span>
            {counts[t.id] ? <span className="insptab-count">{counts[t.id]}</span> : null}
          </button>
        ))}
      </div>

      <div className="insppanel" role="tabpanel">
        {tab === "inspect" && <SidePanel />}
        {tab === "abuse" && <AbusePanel />}
        {tab === "paths" && <Paths />}
        {tab === "vault" && <CredentialVault />}
        {tab === "team" && <TeamPanel />}
      </div>
    </>
  );
}
