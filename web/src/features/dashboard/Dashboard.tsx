import { useCallback, useEffect, useState } from "react";
import { migrateIdentityToFolder, signingPublicB64, wrappingPublicB64, type Identity } from "@/crypto/identity";
import { decodeCampaignFile } from "@/crypto/primitives";
import { loadSettings, saveSettings } from "@/campaign/persistence";
import { useStore } from "@/state/store";
import type { RecipientSpec } from "@/campaign/session";
import { platform, type CampaignFileEntry } from "@/io/platform";
import { Icon } from "@/ui";

type Panel = null | "new";

const fmtWhen = (ms?: number): string => {
  if (!ms)
      return "—";

  const d = new Date(ms);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
};

const fmtSize = (n: number): string =>
  n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`;

const campaignIdOf = (name: string): string => name.replace(/\.camp$/i, "");

export function Dashboard({ identity, onLock }: { identity: Identity; onLock: () => void }) {
  const createCampaign = useStore((s) => s.createCampaign);
  const openCampaignFile = useStore((s) => s.openCampaignFile);
  const pendingOpen = useStore((s) => s.pendingOpen);
  const setPendingOpen = useStore((s) => s.setPendingOpen);

  const [folder, setFolder] = useState<string | null>(null);
  const [files, setFiles] = useState<CampaignFileEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [panel, setPanel] = useState<Panel>(null);
  const [showKeys, setShowKeys] = useState(false);

  const refreshFiles = useCallback(async (dir: string | null) => {
    if (!dir) {
      setFiles([]);
      return;
    }
    try {
      setFiles(await platform.listCampaignFiles(dir));
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  const persist = useCallback(async (dir: string | null) => {
    await saveSettings({ campaignsFolder: dir });
  }, []);

  useEffect(() => {
    void (async () => {
      const s = await loadSettings();
      setFolder(s.campaignsFolder);
      await refreshFiles(s.campaignsFolder);
    })();
  }, [refreshFiles]);

  const chooseFolder = useCallback(async () => {
    const dir = await platform.pickDirectory();
    if (!dir)
        return;

    setFolder(dir);
    await persist(dir);
    await migrateIdentityToFolder();
    await refreshFiles(dir);
  }, [persist, refreshFiles]);

  const openLocal = useCallback(
    async (entry: CampaignFileEntry) => {
      if (!folder) return;
      setError(null);
      setBusy(entry.path);
      try {
        const file = await platform.readCampaignFile(folder, entry.path);
        if (!file)
            throw new Error("could not read the file");

        const bytes = new Uint8Array(await file.arrayBuffer());
        const { header } = decodeCampaignFile(bytes);

        if (!header.recipients?.some((r) => r.operator_id === identity.operatorId))
          throw new Error("you are not a recipient of this campaign");
        
        await openCampaignFile({
          identity,
          fileBytes: bytes,
          saveFolder: folder,
          saveFileName: entry.name,
        });
      } catch (e) {
        setError((e as Error).message);
        setBusy(null);
      }
    },
    [folder, identity, openCampaignFile],
  );

  const importFile = useCallback(
    async (incoming?: File | null) => {
      if (!folder) {
        setError("choose a campaigns folder first");
        return;
      }
      const file = incoming ?? (await platform.openCampaignFile());
      if (!file)
          return;
      
      const bytes = new Uint8Array(await file.arrayBuffer());
      try {
        decodeCampaignFile(bytes);
        await platform.writeCampaignFile(folder, file.name, bytes);
        await refreshFiles(folder);
      } catch (e) {
        setError(`not a campaign file: ${(e as Error).message}`);
      }
    },
    [folder, refreshFiles],
  );

  useEffect(() => {
    const un = platform.onMenu((id) => {
      if (id === "new_campaign") setPanel("new");
      else if (id === "open_campaign") void importFile();
    });
    return () => void un?.then((fn) => fn());
  }, [importFile]);

  useEffect(() => {
    if (!pendingOpen)
        return;
    void importFile(pendingOpen.file);
    setPendingOpen(null);
  }, [pendingOpen, setPendingOpen, importFile]);

  const create = useCallback(
    async (campaignId: string, recipients: RecipientSpec[], seedDemo: boolean) => {
      if (!folder)
          return;
      setError(null);
      setBusy(campaignId);
      try {
        await createCampaign({
          identity,
          campaignId,
          recipients,
          seedDemo,
          saveFolder: folder,
          saveFileName: `${campaignId}.camp`,
        });
      } catch (e) {
        setError((e as Error).message);
        setBusy(null);
      }
    },
    [folder, identity, createCampaign],
  );

  return (
    <div className="dash">
      <div className="dashframe">
        <header className="dashhead">
          <div>
            <div className="dashtitle">Campaigns</div>
            <div className="muted">
              {identity.operatorId} * {identity.displayName}
              <button className="linklike inline" onClick={() => setShowKeys((v) => !v)}>
                {showKeys ? "hide keys" : "show keys"}
              </button>
            </div>
          </div>
          <button className="ghost" onClick={onLock}>
            Lock
          </button>
        </header>

        {showKeys && (
          <div className="keys">
            <div className="muted">
              Share this line with a campaign lead:
            </div>
            <code className="kv invite">
              {identity.operatorId} {signingPublicB64(identity)} {wrappingPublicB64(identity)}
            </code>
          </div>
        )}

        <div className="dashfolder">
          <label className="field grow">
            <span>Campaigns folder</span>
            <button className="ghost folderbtn" onClick={() => void chooseFolder()} title="Choose where your .camp files are kept">
              <Icon name="folder" size={13} /> {folder ?? "Choose folder..."}
            </button>
          </label>
        </div>

        {error && <p className="error">{error}</p>}

        <div className="dashactions">
          <button
            className={panel === "new" ? "active" : ""}
            disabled={!folder}
            onClick={() => setPanel(panel === "new" ? null : "new")}
          >
            <Icon name="plus" size={14} /> New campaign
          </button>
          <button disabled={!folder} onClick={() => void importFile()}>
            <Icon name="import" size={14} /> Add file
          </button>
        </div>

        {panel === "new" && (
          <NewCampaignForm
            folder={folder}
            busy={!!busy}
            onCancel={() => setPanel(null)}
            onCreate={(campaignId, recipients, seedDemo) => void create(campaignId, recipients, seedDemo)}
          />
        )}

        <ul className="campaigns">
          {!folder && (
            <li className="empty muted">Choose a campaigns folder to see your sovereign `.camp` files.</li>
          )}
          {folder && files.length === 0 && (
            <li className="empty muted">No campaign files in this folder yet. Create one or add a file above.</li>
          )}
          {files.map((f) => (
            <li key={f.path} className="campaign">
              <div className="cmeta">
                <div className="cid">{campaignIdOf(f.name)}</div>
                <div className="csub muted">
                  {f.name} * {fmtSize(f.size)} * saved {fmtWhen(f.modified_ms)}
                </div>
              </div>
              <div className="cact">
                <button disabled={busy === f.path} onClick={() => void openLocal(f)}>
                  {busy === f.path ? "Opening..." : "Open"}
                </button>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function NewCampaignForm({
  folder,
  busy,
  onCreate,
  onCancel,
}: {
  folder: string | null;
  busy: boolean;
  onCreate: (campaignId: string, recipients: RecipientSpec[], seedDemo: boolean) => void;
  onCancel: () => void;
}) {
  const [campaignId, setCampaignId] = useState("");
  const [recipientsText, setRecipientsText] = useState("");
  // Demo seed is opt-in: real campaigns must start empty so demo nodes
  // (esx01, WS01->DC01 path...) never mix with actual engagement data.
  const [seedDemo, setSeedDemo] = useState(false);

  const parseRecipients = (): RecipientSpec[] =>
    recipientsText
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((line) => {
        const [operatorId, signingB64, wrappingB64, role] = line.split(/\s+/);
        return {
          operatorId: operatorId ?? "",
          signingB64: signingB64 ?? "",
          wrappingB64: wrappingB64 ?? "",
          grantVault: role !== "observer",
        };
      })
      .filter((r) => r.operatorId && r.signingB64 && r.wrappingB64);

  return (
    <form
      className="subform"
      onSubmit={(e) => {
        e.preventDefault();
        onCreate(campaignId.trim(), parseRecipients(), seedDemo);
      }}
    >
      <div className="subhead">New campaign ({folder}/{campaignId || "..."}.camp)</div>
      <label className="field">
        <span>Campaign ID</span>
        <input value={campaignId} onChange={(e) => setCampaignId(e.target.value)} placeholder="camp_alpha" required />
      </label>
      <label className="field">
        <span>Co-operators (one per line: id sign wrap [observer])</span>
        <textarea
          value={recipientsText}
          onChange={(e) => setRecipientsText(e.target.value)}
          placeholder={"op_bob <sign_b64> <wrap_b64>\nop_obs <sign_b64> <wrap_b64> observer"}
          rows={3}
        />
      </label>
      <label className="check">
        <input type="checkbox" checked={seedDemo} onChange={(e) => setSeedDemo(e.target.checked)} />
        <span>Seed a demo network</span>
      </label>
      <div className="subbtns">
        <button type="submit" disabled={busy || !campaignId.trim()}>
          {busy ? "Creating..." : "Create & connect"}
        </button>
        <button type="button" className="ghost" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
