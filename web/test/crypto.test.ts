import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers";
import {
  buildRecipient,
  decodeCampaignFile,
  deriveDeviceKek,
  deriveOperatorSecret,
  encodeCampaignFile,
  generateCampaignKeys,
  generateOperator,
  open,
  openCampaignKeys,
  openContent,
  openContentAt,
  openSecret,
  operatorPublic,
  operatorSecretBytes,
  operatorSecretFromBytes,
  randomSalt,
  ready,
  seal,
  sealContent,
  sealContentAt,
  sealSecret,
  unwrapKey,
  wrapKey,
} from "@/crypto/primitives";

beforeAll(async () => {
  await ready();
});

describe("client crypto (libsodium, mirrors crypto)", () => {
  it("seals and opens, binding AAD", () => {
    const key = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    const pt = new TextEncoder().encode("loot");
    const aad = new TextEncoder().encode("campaign-1");
    const blob = seal(key, pt, aad);
    expect(new TextDecoder().decode(open(key, blob, aad))).toBe("loot");
    // wrong AAD must fail authentication
    expect(() => open(key, blob, new TextEncoder().encode("campaign-2"))).toThrow();
  });

  it("detects ciphertext tampering", () => {
    const key = sodium.randombytes_buf(32);
    const blob = seal(key, new TextEncoder().encode("x"), new Uint8Array());
    const raw = sodium.from_base64(blob.ct, sodium.base64_variants.ORIGINAL);
    raw[0] = raw[0]! ^ 0x01;
    blob.ct = sodium.to_base64(raw, sodium.base64_variants.ORIGINAL);
    expect(() => open(key, blob, new Uint8Array())).toThrow();
  });

  it("derives a device key and seals/unseals the operator secret (identity at rest)", () => {
    const salt = randomSalt();
    expect(salt.length).toBe(16); // must work before/after ready without throwing
    const op = generateOperator();
    const kek = deriveDeviceKek("correct horse battery staple", salt);
    const aad = new TextEncoder().encode("campaign-device-secret-v1");
    const sealed = seal(kek, operatorSecretBytes(op), aad);

    // Right passphrase recovers the operator; a wrong one fails the AEAD open.
    const recovered = operatorSecretFromBytes(open(deriveDeviceKek("correct horse battery staple", salt), sealed, aad));
    expect(Array.from(recovered.ed25519Seed)).toEqual(Array.from(op.ed25519Seed));
    expect(() => open(deriveDeviceKek("wrong", salt), sealed, aad)).toThrow();
  });

  it("derives a deterministic, recoverable identity from operator id + passphrase", () => {
    const a = deriveOperatorSecret("op_john", "correct horse battery staple");
    const b = deriveOperatorSecret("op_john", "correct horse battery staple");
    // Same id + passphrase → identical keys, so the identity restores on any
    // device and the campaign file's envelopes still open (no lost-cache lockout).
    expect(Array.from(operatorSecretBytes(a))).toEqual(Array.from(operatorSecretBytes(b)));
    expect(Array.from(operatorPublic(a).wrapping)).toEqual(Array.from(operatorPublic(b).wrapping));
    // A different passphrase, or a different operator id, yields a different identity.
    expect(Array.from(operatorSecretBytes(deriveOperatorSecret("op_john", "other")))).not.toEqual(Array.from(operatorSecretBytes(a)));
    expect(Array.from(operatorSecretBytes(deriveOperatorSecret("op_jane", "correct horse battery staple")))).not.toEqual(Array.from(operatorSecretBytes(a)));
  });

  it("wraps a key for a recipient and refuses the wrong one", () => {
    const alice = generateOperator();
    const bob = generateOperator();
    const secret = sodium.randombytes_buf(32);
    const wrapped = wrapKey(secret, operatorPublic(alice).wrapping);
    expect(Array.from(unwrapKey(wrapped, alice.x25519Secret))).toEqual(Array.from(secret));
    expect(() => unwrapKey(wrapped, bob.x25519Secret)).toThrow();
  });
});

describe("sovereign campaign file (role-limited vault)", () => {
  it("recovers keys per role and round-trips through the CAMP container", () => {
    const campaignId = "camp_file";
    const keys = generateCampaignKeys();
    const lead = generateOperator();
    const observer = generateOperator();
    const stranger = generateOperator();

    const header = {
      format_version: 1,
      campaign_id: campaignId,
      recipients: [
        buildRecipient("op_lead", operatorPublic(lead), keys, true),
        buildRecipient("op_obs", operatorPublic(observer), keys, false),
      ],
      snapshot_version: 1,
    };
    const snapshot = new TextEncoder().encode("<snapshot>");
    const file = { header, sealed_snapshot: sealContent(keys.campaignKey, campaignId, snapshot) };

    const decoded = decodeCampaignFile(encodeCampaignFile(file));
    expect(decoded.header.campaign_id).toBe(campaignId);

    // Lead recovers both keys and reads content + a sealed secret.
    const leadKeys = openCampaignKeys(decoded.header, "op_lead", lead);
    expect(leadKeys.vaultKey).toBeDefined();
    expect(new TextDecoder().decode(openContent(leadKeys.campaignKey, campaignId, decoded.sealed_snapshot))).toBe("<snapshot>");
    const sealedSecret = sealSecret(leadKeys.vaultKey!, new TextEncoder().encode("P@ssw0rd!"));
    expect(new TextDecoder().decode(openSecret(leadKeys.vaultKey!, sealedSecret))).toBe("P@ssw0rd!");

    // Observer reads the graph but the vault is withheld.
    const obsKeys = openCampaignKeys(decoded.header, "op_obs", observer);
    expect(obsKeys.vaultKey).toBeUndefined();
    expect(new TextDecoder().decode(openContent(obsKeys.campaignKey, campaignId, decoded.sealed_snapshot))).toBe("<snapshot>");

    // Stranger is not a recipient.
    expect(() => openCampaignKeys(decoded.header, "op_lead", stranger)).toThrow();
  });

  it("binds the key epoch into the content AAD (rotation defense in depth)", () => {
    const campaignId = "camp_epoch";
    const keys = generateCampaignKeys();
    const snap = new TextEncoder().encode("<v2>");
    const sealed1 = sealContentAt(keys.campaignKey, campaignId, 1, snap);

    // Right key, right epoch opens.
    expect(new TextDecoder().decode(openContentAt(keys.campaignKey, campaignId, 1, sealed1))).toBe("<v2>");
    // Right key, wrong epoch (0 / legacy) must fail — the epoch is bound in.
    expect(() => openContentAt(keys.campaignKey, campaignId, 0, sealed1)).toThrow();
    expect(() => openContent(keys.campaignKey, campaignId, sealed1)).toThrow();
    // Epoch 0 reproduces the legacy AAD exactly (v1 compatibility).
    const sealed0 = sealContent(keys.campaignKey, campaignId, snap);
    expect(new TextDecoder().decode(openContentAt(keys.campaignKey, campaignId, 0, sealed0))).toBe("<v2>");
  });

  it("decodes a v1 file (no key_epoch field, v1 version byte) with epoch 0", () => {
    const campaignId = "camp_v1";
    const keys = generateCampaignKeys();
    const lead = generateOperator();
    const header = {
      format_version: 1,
      campaign_id: campaignId,
      recipients: [buildRecipient("op_lead", operatorPublic(lead), keys, true)],
      snapshot_version: 1,
      // no key_epoch — a genuine v1 header
    };
    const file = { header, sealed_snapshot: sealContent(keys.campaignKey, campaignId, new TextEncoder().encode("<s>")) };
    const bytes = encodeCampaignFile(file);
    bytes[4] = 1; // downgrade the byte version to v1
    const decoded = decodeCampaignFile(bytes);
    expect(decoded.header.key_epoch ?? 0).toBe(0);
    const lk = openCampaignKeys(decoded.header, "op_lead", lead);
    expect(new TextDecoder().decode(openContent(lk.campaignKey, campaignId, decoded.sealed_snapshot))).toBe("<s>");
  });

  it("re-seals a vault secret from an old key to a new key (rotation safety)", () => {
    // Guards Session.resealVault: on key rotation every sealed secret must be
    // re-sealed old->new, or it becomes permanently undecryptable.
    const oldKeys = generateCampaignKeys();
    const newKeys = generateCampaignKeys();
    const secret = new TextEncoder().encode("aad3b435b51404eeaad3b435b51404ee");
    const blobOld = JSON.stringify(sealSecret(oldKeys.vaultKey!, secret));
    const reSealed = JSON.stringify(
      sealSecret(newKeys.vaultKey!, openSecret(oldKeys.vaultKey!, JSON.parse(blobOld))),
    );
    expect(openSecret(newKeys.vaultKey!, JSON.parse(reSealed))).toEqual(secret);
    expect(() => openSecret(oldKeys.vaultKey!, JSON.parse(reSealed))).toThrow();
  });
});
