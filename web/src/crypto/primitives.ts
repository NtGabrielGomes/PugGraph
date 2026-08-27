// Client crypto, mirroring `crypto` byte-for-byte so a campaign file or
// wrapped key produced by either stack opens in the other. Implemented with
// libsodium:
//   - content sealing:  XChaCha20-Poly1305 (crypto_aead_xchacha20poly1305_ietf)
//   - signing:          Ed25519 (crypto_sign_detached)
//   - key wrap (ECIES): X25519 (crypto_scalarmult) + HKDF-SHA256 + XChaCha20
//   - passphrase KDF:   Argon2id (crypto_pwhash) — device secret at rest only
//   - campaign file:    the sovereign `CAMP` container (header + sealed snapshot)
//
// Cross-stack parity is locked down by core/scripts/interop.sh (Rust <-> Node,
// both directions, including key-wrap and full CampaignFile open).

import sodium from "libsodium-wrappers";

export interface SealedBlob {
  nonce: string; // base64
  ct: string; // base64
}

export async function ready(): Promise<void> {
  await sodium.ready;
}

const enc = (b: Uint8Array): string => sodium.to_base64(b, sodium.base64_variants.ORIGINAL);
const dec = (s: string): Uint8Array => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);

export function seal(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): SealedBlob {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key);
  return { nonce: enc(nonce), ct: enc(ct) };
}

export function open(key: Uint8Array, blob: SealedBlob, aad: Uint8Array): Uint8Array {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    dec(blob.ct),
    aad,
    dec(blob.nonce),
    key,
  );
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** AAD binding content to the campaign id and key epoch. Epoch 0 reproduces the
 * legacy AAD (just the campaign id) so v1 files open unchanged; later epochs
 * suffix `:<epoch>` so a stale-epoch key cannot AEAD-open them. */
export function contentAad(campaignId: string, epoch = 0): Uint8Array {
  return utf8(epoch === 0 ? campaignId : `${campaignId}:${epoch}`);
}

/** Seal a CRDT update / snapshot under the campaign key at a given key epoch. */
export function sealContentAt(campaignKey: Uint8Array, campaignId: string, epoch: number, update: Uint8Array): SealedBlob {
  return seal(campaignKey, update, contentAad(campaignId, epoch));
}

export function openContentAt(campaignKey: Uint8Array, campaignId: string, epoch: number, blob: SealedBlob): Uint8Array {
  return open(campaignKey, blob, contentAad(campaignId, epoch));
}

/** Seal a CRDT update under the campaign key (epoch 0 / legacy AAD). */
export function sealContent(campaignKey: Uint8Array, campaignId: string, update: Uint8Array): SealedBlob {
  return sealContentAt(campaignKey, campaignId, 0, update);
}

export function openContent(campaignKey: Uint8Array, campaignId: string, blob: SealedBlob): Uint8Array {
  return openContentAt(campaignKey, campaignId, 0, blob);
}

// ---------------------------------------------------------------------------
// Key wrapping, operator identities, and the sovereign campaign-file codec.
// These mirror `crypto::{wrap, keys, lib, file}` exactly.
// ---------------------------------------------------------------------------

/** Base64 (standard, padded) — exported so other modules can move blobs. */
export const toB64 = enc;
export const fromB64 = dec;

const WRAP_INFO = utf8("campaign-key-wrap-v1");
const VAULT_AAD = utf8("campaign-credential-vault-v1");

const concatBytes = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

/**
 * HKDF-SHA256 (RFC 5869) over libsodium HMAC-SHA256, matching the Rust `hkdf`
 * crate constructed with `salt = None` (a zero-filled salt of the hash length).
 */
export function hkdfSha256(ikm: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const prk = sodium.crypto_auth_hmacsha256(ikm, new Uint8Array(32)); // extract; salt = 32 zero bytes
  const out = new Uint8Array(length);
  let prev: Uint8Array = new Uint8Array(0);
  let pos = 0;
  for (let counter = 1; pos < length; counter++) {
    const block = sodium.crypto_auth_hmacsha256(concatBytes(prev, info, Uint8Array.of(counter)), prk);
    const take = Math.min(block.length, length - pos);
    out.set(block.subarray(0, take), pos);
    pos += take;
    prev = block;
  }
  return out;
}

export interface WrappedKey {
  eph_pub: string; // base64 ephemeral X25519 public key
  blob: SealedBlob;
}

/** Wrap a 32-byte secret for the holder of `recipX25519Pub` (forward-secret ECIES). */
export function wrapKey(plain: Uint8Array, recipX25519Pub: Uint8Array): WrappedKey {
  const eph = sodium.crypto_box_keypair(); // curve25519 (X25519) ephemeral
  const shared = sodium.crypto_scalarmult(eph.privateKey, recipX25519Pub);
  const kek = hkdfSha256(shared, concatBytes(WRAP_INFO, eph.publicKey, recipX25519Pub), 32);
  return { eph_pub: enc(eph.publicKey), blob: seal(kek, plain, WRAP_INFO) };
}

/** Unwrap a secret previously wrapped for `recipX25519Secret`. Throws on failure. */
export function unwrapKey(w: WrappedKey, recipX25519Secret: Uint8Array): Uint8Array {
  const ephPub = dec(w.eph_pub);
  const recipPub = sodium.crypto_scalarmult_base(recipX25519Secret);
  const shared = sodium.crypto_scalarmult(recipX25519Secret, ephPub);
  const kek = hkdfSha256(shared, concatBytes(WRAP_INFO, ephPub, recipPub), 32);
  return open(kek, w.blob, WRAP_INFO);
}

export interface OperatorSecret {
  /** Ed25519 seed (32) — the portable secret; the 64-byte signing key derives from it. */
  ed25519Seed: Uint8Array;
  /** X25519 secret (32) — the recipient end of the campaign-key envelope. */
  x25519Secret: Uint8Array;
}

export interface OperatorPublic {
  signing: Uint8Array; // Ed25519 verifying key (32)
  wrapping: Uint8Array; // X25519 public key (32)
}

export function generateOperator(): OperatorSecret {
  return { ed25519Seed: sodium.randombytes_buf(32), x25519Secret: sodium.randombytes_buf(32) };
}

export function operatorPublic(s: OperatorSecret): OperatorPublic {
  return {
    signing: sodium.crypto_sign_seed_keypair(s.ed25519Seed).publicKey,
    wrapping: sodium.crypto_scalarmult_base(s.x25519Secret),
  };
}

/** 64-byte `seed ‖ x25519` serialization (matches Rust `OperatorSecret::to_secret_bytes`). */
export function operatorSecretBytes(s: OperatorSecret): Uint8Array {
  return concatBytes(s.ed25519Seed, s.x25519Secret);
}

export function operatorSecretFromBytes(b: Uint8Array): OperatorSecret {
  return { ed25519Seed: b.slice(0, 32), x25519Secret: b.slice(32, 64) };
}

// --- passphrase KDF (Argon2id): protects the device secret at rest only ---

// crypto_pwhash_SALTBYTES for Argon2id. A literal because libsodium constants
// are only populated after `sodium.ready` resolves — reading the property at
// module-load time yields undefined (and `randombytes_buf(undefined)` throws
// "length cannot be null or undefined").
export const SALT_LEN = 16;

export function randomSalt(): Uint8Array {
  return sodium.randombytes_buf(SALT_LEN);
}

export function deriveDeviceKek(passphrase: string, salt: Uint8Array): Uint8Array {
  return sodium.crypto_pwhash(
    32,
    passphrase,
    salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

// Identity-derivation work factor — stronger than the at-rest seal above, because
// the derived value *is* the identity and is brute-forceable from the public
// campaign file. Fixed constants so derivation is deterministic across devices.
const ID_OPS = 3;
const ID_MEM = 128 * 1024 * 1024; // 128 MiB

/**
 * Deterministically derive an operator's 64-byte secret from (operatorId,
 * passphrase). The same inputs always reproduce the same signing + wrapping
 * keys, so an operator restores their identity on any device from memory alone —
 * no exported key file, no lost-cache lockout, and the campaign file's envelopes
 * still open. The passphrase is the only secret and must be strong.
 */
export function deriveOperatorSecret(operatorId: string, passphrase: string): OperatorSecret {
  const salt = sodium.crypto_generichash(SALT_LEN, utf8(`campaign-operator-v1:${operatorId}`), null);
  const bytes = sodium.crypto_pwhash(64, passphrase, salt, ID_OPS, ID_MEM, sodium.crypto_pwhash_ALG_ARGON2ID13);
  return operatorSecretFromBytes(bytes);
}

// --- campaign keys, recipients, and the credential vault ---

export interface CampaignKeys {
  campaignKey: Uint8Array;
  vaultKey?: Uint8Array;
}

export function generateCampaignKeys(): CampaignKeys {
  return { campaignKey: sodium.randombytes_buf(32), vaultKey: sodium.randombytes_buf(32) };
}

export function sealSecret(vaultKey: Uint8Array, plaintext: Uint8Array): SealedBlob {
  return seal(vaultKey, plaintext, VAULT_AAD);
}

export function openSecret(vaultKey: Uint8Array, blob: SealedBlob): Uint8Array {
  return open(vaultKey, blob, VAULT_AAD);
}

export interface Recipient {
  operator_id: string;
  signing_public_key: string;
  wrapped_campaign_key: WrappedKey;
  wrapped_vault_key: WrappedKey | null;
}

export interface CampaignFileHeader {
  format_version: number;
  campaign_id: string;
  recipients: Recipient[];
  snapshot_version: number;
  /** Key-rotation epoch (revocation). Bound into the content AAD so a stale key
   * cannot open a newer snapshot. Absent (v1) is treated as 0. */
  key_epoch?: number;
}

export interface CampaignFile {
  header: CampaignFileHeader;
  sealed_snapshot: SealedBlob;
}

export function buildRecipient(
  operatorId: string,
  pub: OperatorPublic,
  keys: CampaignKeys,
  grantVault: boolean,
): Recipient {
  return {
    operator_id: operatorId,
    signing_public_key: enc(pub.signing),
    wrapped_campaign_key: wrapKey(keys.campaignKey, pub.wrapping),
    wrapped_vault_key: grantVault && keys.vaultKey ? wrapKey(keys.vaultKey, pub.wrapping) : null,
  };
}

/** Recover the campaign keys an operator is entitled to from a file header. */
export function openCampaignKeys(
  header: CampaignFileHeader,
  operatorId: string,
  secret: OperatorSecret,
): CampaignKeys {
  const r = header.recipients.find((x) => x.operator_id === operatorId);
  if (!r) throw new Error("not a recipient of this campaign");
  const campaignKey = unwrapKey(r.wrapped_campaign_key, secret.x25519Secret);
  const vaultKey = r.wrapped_vault_key ? unwrapKey(r.wrapped_vault_key, secret.x25519Secret) : undefined;
  return { campaignKey, vaultKey };
}

// --- the sovereign campaign-file container ---
//   "CAMP" | ver(1) | hdr_len(u32 LE) | header(JSON) | pay_len(u32 LE) | payload(JSON)

const MAGIC = utf8("CAMP");
const FORMAT_VERSION = 2;
const MIN_FORMAT_VERSION = 1;

export function encodeCampaignFile(file: CampaignFile): Uint8Array {
  const header = utf8(JSON.stringify(file.header));
  const payload = utf8(JSON.stringify(file.sealed_snapshot));
  const out = new Uint8Array(4 + 1 + 4 + header.length + 4 + payload.length);
  const dv = new DataView(out.buffer);
  let o = 0;
  out.set(MAGIC, o);
  o += 4;
  out[o] = FORMAT_VERSION;
  o += 1;
  dv.setUint32(o, header.length, true);
  o += 4;
  out.set(header, o);
  o += header.length;
  dv.setUint32(o, payload.length, true);
  o += 4;
  out.set(payload, o);
  return out;
}

export function decodeCampaignFile(bytes: Uint8Array): CampaignFile {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const td = new TextDecoder();
  let o = 0;
  const need = (n: number): void => {
    if (o + n > bytes.length) throw new Error("campaign file truncated");
  };
  need(4);
  for (let i = 0; i < 4; i++) if (bytes[o + i] !== MAGIC[i]) throw new Error("bad campaign file magic");
  o += 4;
  need(1);
  if (bytes[o]! < MIN_FORMAT_VERSION || bytes[o]! > FORMAT_VERSION) throw new Error("unsupported campaign file version");
  o += 1;
  need(4);
  const hlen = dv.getUint32(o, true);
  o += 4;
  need(hlen);
  const header = JSON.parse(td.decode(bytes.subarray(o, o + hlen))) as CampaignFileHeader;
  o += hlen;
  need(4);
  const plen = dv.getUint32(o, true);
  o += 4;
  need(plen);
  const sealed_snapshot = JSON.parse(td.decode(bytes.subarray(o, o + plen))) as SealedBlob;
  return { header, sealed_snapshot };
}
