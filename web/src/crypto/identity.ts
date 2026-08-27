// The operator's device identity: an Ed25519 signing key (authorship) and an
// X25519 wrapping key (campaign-key recipient). The 64-byte secret
// is sealed at rest under an Argon2id key derived from the operator's
// passphrase and stored in the OS keychain/profile folder. Unlocking re-derives
// the key from the passphrase; a wrong passphrase fails the AEAD open.

import {
  deriveDeviceKek,
  deriveOperatorSecret,
  fromB64,
  open,
  operatorPublic,
  operatorSecretBytes,
  operatorSecretFromBytes,
  randomSalt,
  ready,
  seal,
  toB64,
  type OperatorPublic,
  type OperatorSecret,
  type SealedBlob,
} from "@/crypto/primitives";
import { kvGet, loadSettings } from "@/campaign/persistence";
import { platform } from "@/io/platform";

const IDENTITY_KEY = "identity";
const IDENTITY_FILE = "identity.key";
const DEVICE_AAD = new TextEncoder().encode("campaign-device-secret-v1");

interface StoredIdentityRecord {
  operatorId: string;
  displayName: string;
  saltB64: string;
  sealed: SealedBlob;
}

// The device identity is sealed under the passphrase (the 64-byte secret is AEAD
// ciphertext), then stored — by preference — as `identity.key` IN the operator's
// chosen campaigns folder, so it travels with the campaigns and is easy to manage.
// Until a folder is chosen it lives in the OS keychain / IndexedDB (the pre-folder
// fallback). The record is JSON-safe, so it round-trips as a single string.
const folderPath = async (): Promise<string | null> => (await loadSettings()).campaignsFolder;

async function readFolderRecord(folder: string): Promise<StoredIdentityRecord | undefined> {
  try {
    const file = await platform.readCampaignFile(folder, `${folder}/${IDENTITY_FILE}`);
    if (file) return JSON.parse(await file.text()) as StoredIdentityRecord;
  } catch {
    /* not present in the folder yet */
  }
  return undefined;
}

async function loadRecord(): Promise<StoredIdentityRecord | undefined> {
  const folder = await folderPath();
  if (folder) {
    const rec = await readFolderRecord(folder);
    if (rec) return rec;
  }
  // Fallback: keychain / IndexedDB (pre-folder, or before migration).
  const s = await platform.secretGet(IDENTITY_KEY);
  if (s) return JSON.parse(s) as StoredIdentityRecord;
  const legacy = await kvGet<StoredIdentityRecord>(IDENTITY_KEY);
  if (legacy) {
    await platform.secretSet(IDENTITY_KEY, JSON.stringify(legacy));
    return legacy;
  }
  return undefined;
}

async function saveRecord(rec: StoredIdentityRecord): Promise<void> {
  const folder = await folderPath();
  if (folder) {
    const bytes = new TextEncoder().encode(JSON.stringify(rec));
    if (await platform.writeCampaignFile(folder, IDENTITY_FILE, bytes)) return;
  }
  await platform.secretSet(IDENTITY_KEY, JSON.stringify(rec));
}

/** After a campaigns folder is chosen, copy the sealed identity into it (unless
 * the folder already holds one) so it travels with the campaigns. */
export async function migrateIdentityToFolder(): Promise<void> {
  const folder = await folderPath();
  if (!folder || (await readFolderRecord(folder))) return;
  const s = await platform.secretGet(IDENTITY_KEY);
  if (s) await saveRecord(JSON.parse(s) as StoredIdentityRecord);
}

export interface Identity {
  operatorId: string;
  displayName: string;
  secret: OperatorSecret;
  pub: OperatorPublic;
}

/** The stored identity's public metadata, to pre-fill the unlock screen. */
export async function storedIdentityMeta(): Promise<{ operatorId: string; displayName: string } | undefined> {
  const rec = await loadRecord();
  return rec ? { operatorId: rec.operatorId, displayName: rec.displayName } : undefined;
}

/**
 * Create — or restore — a device identity. The keypair is *derived* from
 * (operatorId, passphrase), so the SAME id + passphrase always reproduces the
 * SAME identity on any device: losing this browser's cache no longer locks you
 * out, and the campaign file's envelopes still open. The derived secret is also
 * sealed locally for fast unlock and clear wrong-passphrase errors.
 */
export async function createIdentity(
  operatorId: string,
  displayName: string,
  passphrase: string,
): Promise<Identity> {
  await ready();
  const id = operatorId.trim();
  const secret = deriveOperatorSecret(id, passphrase);
  const salt = randomSalt();
  const kek = deriveDeviceKek(passphrase, salt);
  const sealed = seal(kek, operatorSecretBytes(secret), DEVICE_AAD);
  const rec: StoredIdentityRecord = { operatorId: id, displayName, saltB64: toB64(salt), sealed };
  await saveRecord(rec);
  return { operatorId: id, displayName, secret, pub: operatorPublic(secret) };
}

/** Forget the locally-stored identity (e.g. to switch operators) — from both the
 * folder and the keychain. The identity itself is recoverable any time from the
 * same operator id + passphrase. */
export async function forgetIdentity(): Promise<void> {
  const folder = await folderPath();
  if (folder) await platform.deleteCampaignFile(folder, IDENTITY_FILE);
  await platform.secretDelete(IDENTITY_KEY);
}

export async function unlockIdentity(passphrase: string): Promise<Identity> {
  await ready();
  const rec = await loadRecord();
  if (!rec) throw new Error("no device identity on this device");
  const kek = deriveDeviceKek(passphrase, fromB64(rec.saltB64));
  let bytes: Uint8Array;
  try {
    bytes = open(kek, rec.sealed, DEVICE_AAD);
  } catch {
    throw new Error("wrong passphrase");
  }
  const secret = operatorSecretFromBytes(bytes);
  return { operatorId: rec.operatorId, displayName: rec.displayName, secret, pub: operatorPublic(secret) };
}

/** The base64 Ed25519 verifying key to hand to a campaign lead for enrollment. */
export function signingPublicB64(id: Identity): string {
  return toB64(id.pub.signing);
}

/** The base64 X25519 public key, needed to add this operator as a file recipient. */
export function wrappingPublicB64(id: Identity): string {
  return toB64(id.pub.wrapping);
}
