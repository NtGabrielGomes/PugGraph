import { useCallback, useEffect, useState } from "react";
import {
  createIdentity,
  forgetIdentity,
  storedIdentityMeta,
  unlockIdentity,
  type Identity,
} from "@/crypto/identity";
import { loadSettings, saveSettings } from "@/campaign/persistence";
import { platform } from "@/io/platform";
import { Icon } from "@/ui";

export function IdentityUnlock({ onUnlock }: { onUnlock: (id: Identity) => void }) {
  const [hasId, setHasId] = useState(false);
  const [operatorId, setOperatorId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [folder, setFolder] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const desktop = platform.isTauri();

  const refreshIdentity = useCallback(async () => {
    const meta = await storedIdentityMeta();
    setHasId(!!meta);
    setOperatorId(meta?.operatorId ?? "");
    setDisplayName(meta?.displayName ?? "");
  }, []);

  useEffect(() => {
    void (async () => {
      setFolder((await loadSettings()).campaignsFolder);
      await refreshIdentity();
    })();
  }, [refreshIdentity]);

  const chooseFolder = async () => {
    const dir = await platform.pickDirectory();
    if (!dir) return;
    const s = await loadSettings();
    await saveSettings({ ...s, campaignsFolder: dir });
    setFolder(dir);
    setPassphrase("");
    setError(null);
    await refreshIdentity();
  };

  const useDifferent = async () => {
    await forgetIdentity();
    setHasId(false);
    setOperatorId("");
    setDisplayName("");
    setPassphrase("");
    setError(null);
  };

  const submit = async (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const id = hasId
        ? await unlockIdentity(passphrase)
        : await createIdentity(operatorId.trim(), displayName.trim() || operatorId.trim(), passphrase);
      onUnlock(id);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div className="connect">
      <div className="card">
        <form onSubmit={submit}>
          <h2>{hasId ? "unlock device identity" : "create or restore identity"}</h2>
          <p className="muted">
            Your keys are derived from your operator id + passphrase, so the same id and
            passphrase restore the same identity on any device. Keep your passphrase safe!
          </p>

          {desktop && (
            <div className="field">
              <span>Profile folder</span>
              <button
                type="button"
                className="ghost folderbtn"
                onClick={() => void chooseFolder()}
                disabled={busy}
                title={folder ?? "Choose where your profile and campaign files are kept"}
              >
                <Icon name="folder" size={13} /> {folder ?? "Choose a folder..."}
              </button>
              <small className="hint">
                {folder
                  ? hasId
                    ? "An profile in this folder will be unlocked."
                    : "Your profile will be saved here."
                  : "No folder chosen."}
              </small>
            </div>
          )}

          {!hasId && (
            <>
              <label className="field">
                <span>Operator ID</span>
                <input value={operatorId} onChange={(e) => setOperatorId(e.target.value)} placeholder="op_1337" required />
              </label>
              <label className="field">
                <span>Display Name</span>
                <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="1337" />
              </label>
            </>
          )}
          {hasId && (
            <p className="muted">
              Identity: <strong>{operatorId}</strong> ({displayName})
            </p>
          )}
          <label className="field">
            <span>Passphrase</span>
            <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} required autoFocus />
          </label>
          {error && <p className="error">{error}</p>}
          <button type="submit" disabled={busy}>
            {busy ? "..." : hasId ? "Unlock" : "Create / restore"}
          </button>
          {hasId && (
            <button type="button" className="linklike" onClick={() => void useDifferent()} disabled={busy}>
              Use a different identity
            </button>
          )}
        </form>
      </div>
    </div>
  );
}
