// IndexedDB-backed local persistence: the device identity (sealed at rest) and,
// per campaign, the latest document snapshot for instant reload.

const DB_NAME = "campaign-knowledge";
const DB_VERSION = 1;
const STORE = "kv";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB open failed"));
  });
}

async function run<T>(mode: IDBTransactionMode, op: (store: IDBObjectStore) => IDBRequest): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = op(tx.objectStore(STORE));
      req.onsuccess = () => resolve(req.result as T);
      req.onerror = () => reject(req.error ?? new Error("indexedDB request failed"));
    });
  } finally {
    db.close();
  }
}

export async function kvGet<T>(key: string): Promise<T | undefined> {
  return run<T | undefined>("readonly", (s) => s.get(key));
}

export async function kvSet(key: string, value: unknown): Promise<void> {
  await run("readwrite", (s) => s.put(value, key));
}

export async function kvDelete(key: string): Promise<void> {
  await run("readwrite", (s) => s.delete(key));
}

export interface AppSettings {
  campaignsFolder: string | null;
}

const SETTINGS_KEY = "settings";

export async function loadSettings(): Promise<AppSettings> {
  return (await kvGet<AppSettings>(SETTINGS_KEY)) ?? { campaignsFolder: null };
}

export async function saveSettings(settings: AppSettings): Promise<void> {
  await kvSet(SETTINGS_KEY, settings);
}

/** The locally cached state of one campaign for instant reload. */
export interface LocalCampaignState {
  /** A Loro snapshot of the campaign document at the time it was saved. */
  snapshot: Uint8Array;
}

const campaignKey = (campaignId: string): string => `campaign:${campaignId}`;

export async function loadCampaignState(campaignId: string): Promise<LocalCampaignState | undefined> {
  return kvGet<LocalCampaignState>(campaignKey(campaignId));
}

export async function saveCampaignState(campaignId: string, state: LocalCampaignState): Promise<void> {
  await kvSet(campaignKey(campaignId), state);
}
