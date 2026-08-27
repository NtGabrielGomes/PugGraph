// Platform seam — the single boundary between the React/Loro client and the
// native Tauri desktop shell. The product is desktop-only: every native
// capability is a typed Rust command (see src-tauri/src/lib.rs), invoked here.
// Outside the desktop shell (the Node test runner) the native methods no-op, so
// importing this module never touches the Tauri API or crashes.
//
// The Tauri JS API is loaded by *dynamic import* inside `isTauri()`-guarded
// methods only.

import { kvDelete, kvGet, kvSet } from "@/campaign/persistence";

type UnlistenFn = () => void;

/** A `.camp` file in the chosen campaigns folder (metadata only; the header is
 * parsed in the web layer on open). */
export interface CampaignFileEntry {
  name: string;
  path: string;
  modified_ms: number;
  size: number;
}

/** True when running inside the Tauri desktop shell. */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

async function listen<T>(event: string, cb: (payload: T) => void): Promise<UnlistenFn> {
  const { listen } = await import("@tauri-apps/api/event");
  return listen<T>(event, (e) => cb(e.payload));
}

// --- base64 over IPC (chunked to stay under the arg-string call-stack limit) ---

function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

type PickedFile = { name: string; path: string; data_b64: string };
const toFile = (p: PickedFile): File =>
  new File([b64ToBytes(p.data_b64) as BlobPart], p.name, { type: "application/octet-stream" });

// --- campaigns folder: the sovereign `.camp` files live in an operator-chosen
//     directory; the dashboard lists them and reads/writes are folder-scoped. ---

/** Pick the folder where campaign files are kept. */
async function pickDirectory(): Promise<string | null> {
  if (!isTauri()) return null;
  return invoke<string | null>("pick_directory");
}

/** List the `.camp` files in `folder`, newest first. */
async function listCampaignFiles(folder: string): Promise<CampaignFileEntry[]> {
  if (!isTauri()) return [];
  return invoke<CampaignFileEntry[]>("list_campaign_files", { folder });
}

/** Read a campaign file from inside the chosen folder. */
async function readCampaignFile(folder: string, path: string): Promise<File | null> {
  if (!isTauri()) return null;
  const p = await invoke<PickedFile | null>("read_campaign_file", { folder, path });
  return p ? toFile(p) : null;
}

/** Write (or replace) a campaign file in the chosen folder. Returns its path. */
async function writeCampaignFile(folder: string, name: string, bytes: Uint8Array): Promise<string | null> {
  if (!isTauri()) return null;
  return invoke<string>("write_campaign_file", { folder, name, dataB64: bytesToB64(bytes) });
}

/** Delete a bare-named file from the chosen folder (no error if absent). */
async function deleteCampaignFile(folder: string, name: string): Promise<void> {
  if (!isTauri()) return;
  await invoke("delete_campaign_file", { folder, name });
}

// --- ad-hoc file dialogs (open a file from anywhere; export elsewhere) ---

/** Pick any `.camp` via the native open dialog (e.g. one handed over out of band). */
async function openCampaignFile(): Promise<File | null> {
  if (!isTauri()) return null;
  const p = await invoke<PickedFile | null>("pick_campaign_file");
  return p ? toFile(p) : null;
}

/** Read a `.camp` the OS handed us to open (file association / deep link). */
async function readCampaignPath(path: string): Promise<File | null> {
  if (!isTauri()) return null;
  const p = await invoke<PickedFile | null>("read_campaign_path", { path });
  return p ? toFile(p) : null;
}

/** Pick one or more scanner output files. Text formats come through as text;
 * `.zip` archives (SharpHound) come base64-encoded and are reconstituted as
 * binary Files — the importer unzips them. */
async function openScanFiles(): Promise<File[]> {
  if (!isTauri()) return [];
  const ps = await invoke<{ name: string; path: string; text: string }[]>("pick_scan_files");
  return ps.map((p) =>
    p.name.toLowerCase().endsWith(".zip")
      ? new File([b64ToBytes(p.text) as BlobPart], p.name, { type: "application/zip" })
      : new File([p.text], p.name, { type: "text/plain" }),
  );
}

/** Export the sovereign encrypted campaign file to a chosen path. */
async function saveCampaignFile(defaultName: string, bytes: Uint8Array): Promise<boolean> {
  if (!isTauri()) return false;
  const path = await invoke<string | null>("save_campaign_file", { defaultName, dataB64: bytesToB64(bytes) });
  return path != null;
}

async function saveTextFile(defaultName: string, content: string): Promise<boolean> {
  if (!isTauri()) return false;
  const path = await invoke<string | null>("save_text_file", { defaultName, content });
  return path != null;
}

async function saveBinaryFile(defaultName: string, bytes: Uint8Array): Promise<boolean> {
  if (!isTauri()) return false;
  const path = await invoke<string | null>("save_binary_file", { defaultName, dataB64: bytesToB64(bytes) });
  return path != null;
}

/** Save a data: URI (e.g. the map PNG produced by cytoscape) natively. */
async function saveDataUri(defaultName: string, dataUri: string): Promise<boolean> {
  const comma = dataUri.indexOf(",");
  const b64 = comma >= 0 ? dataUri.slice(comma + 1) : dataUri;
  return saveBinaryFile(defaultName, b64ToBytes(b64));
}

// --- secrets: device-identity seal in the OS keychain, IndexedDB otherwise ---
// In Tauri we try the OS secret store first and fall back to IndexedDB if no
// secret service is available (e.g. a headless host); outside Tauri (tests) the
// IndexedDB path is used directly.

async function secretGet(key: string): Promise<string | null> {
  if (isTauri()) {
    try {
      const v = await invoke<string | null>("secret_get", { key });
      if (v != null) return v;
    } catch {
      /* no secret service → fall through to local cache */
    }
  }
  return (await kvGet<string>(`secret:${key}`)) ?? null;
}

async function secretSet(key: string, value: string): Promise<void> {
  if (isTauri()) {
    try {
      await invoke("secret_set", { key, value });
      return;
    } catch {
      /* fall through to local cache */
    }
  }
  await kvSet(`secret:${key}`, value);
}

async function secretDelete(key: string): Promise<void> {
  if (isTauri()) {
    try {
      await invoke("secret_delete", { key });
    } catch {
      /* ignore */
    }
  }
  await kvDelete(`secret:${key}`);
}

// --- launch-time opens (file association / deep link) + native menu/events ---

async function takePendingOpen(): Promise<string | null> {
  if (!isTauri()) return null;
  return invoke<string | null>("take_pending_open");
}

function onOpenFile(cb: (path: string) => void): Promise<UnlistenFn> | undefined {
  return isTauri() ? listen<string>("open-file", cb) : undefined;
}

function onMenu(cb: (id: string) => void): Promise<UnlistenFn> | undefined {
  return isTauri() ? listen<string>("menu", cb) : undefined;
}

export const platform = {
  isTauri,
  pickDirectory,
  listCampaignFiles,
  readCampaignFile,
  writeCampaignFile,
  deleteCampaignFile,
  openCampaignFile,
  readCampaignPath,
  openScanFiles,
  saveCampaignFile,
  saveTextFile,
  saveDataUri,
  secretGet,
  secretSet,
  secretDelete,
  takePendingOpen,
  onOpenFile,
  onMenu,
};
