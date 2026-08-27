// Cross-stack interop harness (Node/TypeScript side, libsodium).
//
//   node interop.mjs emit          -> prints artifacts JSON
//   node interop.mjs check < json  -> verifies artifacts from the other stack
//
// Imports the working CommonJS libsodium build directly (the published ESM build
// is broken), matching the alias used by the app/test config. The wrap/file
// primitives below mirror src/crypto.ts; the Rust side (examples/interop.rs)
// is the independent counterpart this is checked against.

import sodiumModule from "../node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js";

const sodium = sodiumModule.default ?? sodiumModule;
await sodium.ready;

const B64 = sodium.base64_variants.ORIGINAL; // standard + padding (matches Rust)
const enc = (b) => sodium.to_base64(b, B64);
const dec = (s) => sodium.from_base64(s, B64);
const utf8 = (s) => new TextEncoder().encode(s);

const SHARED_KEY = new Uint8Array(32).fill(0x42);
const CAMPAIGN = "camp_interop";
const FILE_OPERATOR = "op_interop";
const WRAP_INFO = utf8("campaign-key-wrap-v1");
const MAGIC = utf8("CAMP");
const FORMAT_VERSION = 2;

const concatBytes = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

function seal(key, plaintext, aad) {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key);
  return { nonce: enc(nonce), ct: enc(ct) };
}

function open(key, blob, aad) {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, dec(blob.ct), aad, dec(blob.nonce), key);
}

function hkdfSha256(ikm, info, length) {
  const prk = sodium.crypto_auth_hmacsha256(ikm, new Uint8Array(32));
  const out = new Uint8Array(length);
  let prev = new Uint8Array(0);
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

function unwrapKey(w, recipX25519Secret) {
  const ephPub = dec(w.eph_pub);
  const recipPub = sodium.crypto_scalarmult_base(recipX25519Secret);
  const shared = sodium.crypto_scalarmult(recipX25519Secret, ephPub);
  const kek = hkdfSha256(shared, concatBytes(WRAP_INFO, ephPub, recipPub), 32);
  return open(kek, w.blob, WRAP_INFO);
}

function wrapKey(plain, recipX25519Pub) {
  const eph = sodium.crypto_box_keypair();
  const shared = sodium.crypto_scalarmult(eph.privateKey, recipX25519Pub);
  const kek = hkdfSha256(shared, concatBytes(WRAP_INFO, eph.publicKey, recipX25519Pub), 32);
  return { eph_pub: enc(eph.publicKey), blob: seal(kek, plain, WRAP_INFO) };
}

function encodeCampaignFile(header, sealedSnapshot) {
  const h = utf8(JSON.stringify(header));
  const p = utf8(JSON.stringify(sealedSnapshot));
  const out = new Uint8Array(4 + 1 + 4 + h.length + 4 + p.length);
  const dv = new DataView(out.buffer);
  let o = 0;
  out.set(MAGIC, o);
  o += 4;
  out[o] = FORMAT_VERSION;
  o += 1;
  dv.setUint32(o, h.length, true);
  o += 4;
  out.set(h, o);
  o += h.length;
  dv.setUint32(o, p.length, true);
  o += 4;
  out.set(p, o);
  return out;
}

function decodeCampaignFile(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const td = new TextDecoder();
  let o = 0;
  o += 4; // magic (checked by the Rust side's framing on round-trip)
  o += 1; // version
  const hlen = dv.getUint32(o, true);
  o += 4;
  const header = JSON.parse(td.decode(bytes.subarray(o, o + hlen)));
  o += hlen;
  const plen = dv.getUint32(o, true);
  o += 4;
  const sealed_snapshot = JSON.parse(td.decode(bytes.subarray(o, o + plen)));
  return { header, sealed_snapshot };
}

function emit() {
  // 1. AEAD content seal + Ed25519 authorship (from a seed, like the app).
  const plaintext = utf8("cross-stack CRDT update sealed by Node");
  const sealed = seal(SHARED_KEY, plaintext, utf8(CAMPAIGN));
  const seed = sodium.randombytes_buf(32);
  const kp = sodium.crypto_sign_seed_keypair(seed);
  const payload = JSON.stringify(sealed);
  const sig = sodium.crypto_sign_detached(utf8(payload), kp.privateKey);

  // 2. X25519 key wrap for a recipient whose secret we publish.
  const recipSecret = sodium.randombytes_buf(32);
  const recipPub = sodium.crypto_scalarmult_base(recipSecret);
  const wrapSecret = new Uint8Array(32).fill(0x37);
  const wrapped = wrapKey(wrapSecret, recipPub);
  // Publish a 64-byte (ed25519 seed ‖ x25519) secret so the Rust side can rebuild it.
  const recipSecret64 = concatBytes(sodium.randombytes_buf(32), recipSecret);

  // 3. A campaign file with one recipient (vault granted) + a sealed snapshot.
  const campaignKey = sodium.randombytes_buf(32);
  const vaultKey = sodium.randombytes_buf(32);
  const fileSeed = sodium.randombytes_buf(32);
  const fileX = sodium.randombytes_buf(32);
  const fileSignPub = sodium.crypto_sign_seed_keypair(fileSeed).publicKey;
  const fileXPub = sodium.crypto_scalarmult_base(fileX);
  const header = {
    format_version: FORMAT_VERSION,
    campaign_id: CAMPAIGN,
    recipients: [
      {
        operator_id: FILE_OPERATOR,
        signing_public_key: enc(fileSignPub),
        wrapped_campaign_key: wrapKey(campaignKey, fileXPub),
        wrapped_vault_key: wrapKey(vaultKey, fileXPub),
      },
    ],
    snapshot_version: 1,
    key_epoch: 0,
  };
  const snapshot = utf8("<interop loro snapshot bytes>");
  const sealedSnapshot = seal(campaignKey, snapshot, utf8(CAMPAIGN));
  const fileBytes = encodeCampaignFile(header, sealedSnapshot);

  process.stdout.write(
    JSON.stringify({
      producer: "node",
      key_b64: enc(SHARED_KEY),
      campaign_id: CAMPAIGN,
      plaintext_b64: enc(plaintext),
      sealed,
      sign_pub_b64: enc(kp.publicKey),
      payload,
      sig_b64: enc(sig),
      wrap: {
        recipient_secret64_b64: enc(recipSecret64),
        wrapped,
        expected_secret_b64: enc(wrapSecret),
      },
      file: {
        operator_id: FILE_OPERATOR,
        operator_secret64_b64: enc(concatBytes(fileSeed, fileX)),
        file_b64: enc(fileBytes),
        snapshot_b64: enc(snapshot),
      },
    }) + "\n",
  );
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

function eq(a, b) {
  return Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
}

async function check() {
  const j = JSON.parse(await readStdin());

  // 1. Open the peer-sealed ciphertext + verify authorship.
  const opened = open(dec(j.key_b64), j.sealed, utf8(j.campaign_id));
  if (!eq(opened, dec(j.plaintext_b64))) throw new Error("decrypted plaintext mismatch");
  if (!sodium.crypto_sign_verify_detached(dec(j.sig_b64), utf8(j.payload), dec(j.sign_pub_b64))) {
    throw new Error("Ed25519 signature failed to verify");
  }

  // 2. Unwrap the peer-wrapped key with the published recipient X25519 secret.
  const recip64 = dec(j.wrap.recipient_secret64_b64);
  const unwrapped = unwrapKey(j.wrap.wrapped, recip64.slice(32, 64));
  if (!eq(unwrapped, dec(j.wrap.expected_secret_b64))) throw new Error("unwrapped secret mismatch");

  // 3. Decode the campaign file, recover the campaign key, open the snapshot.
  const op64 = dec(j.file.operator_secret64_b64);
  const opX = op64.slice(32, 64);
  const { header, sealed_snapshot } = decodeCampaignFile(dec(j.file.file_b64));
  const r = header.recipients.find((x) => x.operator_id === j.file.operator_id);
  if (!r) throw new Error("operator is not a recipient of the campaign file");
  const campaignKey = unwrapKey(r.wrapped_campaign_key, opX);
  const snapshot = open(campaignKey, sealed_snapshot, utf8(header.campaign_id));
  if (!eq(snapshot, dec(j.file.snapshot_b64))) throw new Error("snapshot mismatch");

  process.stdout.write(
    `node-check: OK (AEAD+sig, key-wrap, and campaign-file all interop with ${j.producer})\n`,
  );
}

const cmd = process.argv[2];
if (cmd === "emit") emit();
else if (cmd === "check") await check();
else {
  process.stderr.write("usage: interop.mjs <emit|check>\n");
  process.exit(2);
}
