// The campaign session: the seat of truth and intelligence on the client.
// Local-only by design — there is no relay, no transport, no network at all.
// It owns the campaign keys (minted on create, recovered from the encrypted
// file header on open), the roster, and the live Loro document, and keeps two
// local copies current as edits happen:
//
//   * the sovereign `.camp` file in the operator's chosen folder — the
//     authoritative copy, sealed under the campaign key, portable between
//     machines and shareable out of band with any enrolled recipient;
//   * an IndexedDB snapshot cache for instant reload.
//
// Multi-operator workflows are file-based: enrolling a co-operator seals the
// campaign key to their public key inside the file, so handing them the `.camp`
// (out of band) is all they need to open it.

import { Campaign } from "@/campaign/document";
import {
  buildRecipient,
  decodeCampaignFile,
  encodeCampaignFile,
  fromB64,
  generateCampaignKeys,
  openCampaignKeys,
  openContentAt,
  openSecret,
  ready,
  sealContentAt,
  sealSecret,
  toB64,
  type CampaignFileHeader,
  type CampaignKeys,
  type Recipient,
  type SealedBlob,
} from "@/crypto/primitives";
import type { Identity } from "@/crypto/identity";
import { loadCampaignState, saveCampaignState } from "@/campaign/persistence";
import { platform } from "@/io/platform";
import { seedDemoCampaign } from "@/campaign/seed";
import type { Provenance } from "@/domain/types";

/** The only connection state a local-only session ever reports. */
export type SessionStatus = "local";

/** A co-operator to seal the campaign keys for inside the file. */
export interface RecipientSpec {
  operatorId: string;
  signingB64: string;
  wrappingB64: string;
  grantVault: boolean;
  /** Human-readable name for the roster; defaults to the operator id. */
  displayName?: string;
}

export interface SessionCallbacks {
  onChange: () => void;
  onStatus: (status: SessionStatus) => void;
  /** A non-fatal notice for the UI to surface. */
  onNotice?: (message: string) => void;
}

export interface SessionOpts extends SessionCallbacks {
  identity: Identity;
  campaignId: string;
  /** When set (desktop), the sovereign `.camp` is auto-saved back to this folder
   * file as the campaign changes, so the local copy stays the source of truth. */
  saveFolder?: string;
  saveFileName?: string;
}

const PERSIST_DEBOUNCE = 800;

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const utf8d = (b: Uint8Array): string => new TextDecoder().decode(b);

const randomPeerId = (): bigint => {
  const buf = new Uint32Array(2);
  crypto.getRandomValues(buf);
  return (BigInt(buf[0]!) << 32n) | BigInt(buf[1]!);
};

export class Session {
  readonly campaign: Campaign;
  readonly operatorId: string;
  readonly displayName: string;

  private keys: CampaignKeys = { campaignKey: new Uint8Array(32) };
  private readonly identity: Identity;
  private recipients: Recipient[] = [];
  private snapshotVersion = 0;
  private keyEpoch = 0;
  /** Destination for the auto-saved sovereign file (desktop folder model). */
  private readonly saveFolder: string | null;
  private readonly saveFileName: string | null;

  private bootstrapped = false;
  private persistTimer: ReturnType<typeof setTimeout> | null = null;

  private readonly cb: SessionCallbacks;

  private constructor(opts: SessionOpts, campaign: Campaign) {
    this.identity = opts.identity;
    this.operatorId = opts.identity.operatorId;
    this.displayName = opts.identity.displayName;
    this.campaign = campaign;
    this.saveFolder = opts.saveFolder ?? null;
    this.saveFileName = opts.saveFileName ?? null;
    this.cb = opts;
  }

  /** Create a new campaign: mint keys, seal them for each recipient. */
  static async create(
    opts: SessionOpts & { recipients: RecipientSpec[]; seedDemo: boolean },
  ): Promise<Session> {
    await ready();
    const campaign = new Campaign(opts.campaignId, randomPeerId());
    const s = new Session(opts, campaign);
    const keys = generateCampaignKeys();
    s.keys = keys;
    const others = opts.recipients.filter((r) => r.operatorId !== opts.identity.operatorId);
    const self = buildRecipient(opts.identity.operatorId, opts.identity.pub, keys, true);
    s.recipients = [
      self,
      ...others.map((r) =>
        buildRecipient(
          r.operatorId,
          { signing: fromB64(r.signingB64), wrapping: fromB64(r.wrappingB64) },
          keys,
          r.grantVault,
        ),
      ),
    ];
    // Seed the in-doc roster (the team management source of truth).
    const at = Date.now();
    s.campaign.setRosterEntry({
      operator_id: opts.identity.operatorId,
      display_name: opts.identity.displayName,
      signing_pubkey: toB64(opts.identity.pub.signing),
      wrapping_pubkey: toB64(opts.identity.pub.wrapping),
      role: "lead",
      status: "active",
      added_by: opts.identity.operatorId,
      added_at: at,
    });
    for (const r of others) {
      s.campaign.setRosterEntry({
        operator_id: r.operatorId,
        display_name: r.displayName || r.operatorId,
        signing_pubkey: r.signingB64,
        wrapping_pubkey: r.wrappingB64,
        role: r.grantVault ? "operator" : "observer",
        status: "active",
        added_by: opts.identity.operatorId,
        added_at: at,
      });
    }
    s.snapshotVersion = s.nextSnapshotVersion();
    if (opts.seedDemo) seedDemoCampaign(campaign, () => s.provenance());
    return s.start();
  }

  /** Open a sovereign campaign file (a `.camp`): decode the header, recover the
   * keys with this operator's secret (which also proves recipiency), and load
   * the sealed snapshot. The file's `campaign_id` is authoritative for the
   * session. Any local snapshot cache for the campaign is merged in — Loro
   * converges the two rather than letting a stale cache collide with the file. */
  static async fromFile(opts: SessionOpts, fileBytes: Uint8Array): Promise<Session> {
    await ready();
    const decoded = decodeCampaignFile(fileBytes); // throws on a bad/foreign file
    const campaignId = decoded.header.campaign_id;
    const keys = openCampaignKeys(decoded.header, opts.identity.operatorId, opts.identity.secret);
    const epoch = decoded.header.key_epoch ?? 0;
    const snapshot = openContentAt(keys.campaignKey, campaignId, epoch, decoded.sealed_snapshot);

    // The cache is an optimization — a cache-layer failure is a cold start,
    // never a reason to fail the session.
    const restored = await loadCampaignState(campaignId).catch(() => undefined);
    const campaign = restored
      ? Campaign.fromSnapshot(campaignId, randomPeerId(), restored.snapshot)
      : new Campaign(campaignId, randomPeerId());
    campaign.import(snapshot);

    const s = new Session({ ...opts, campaignId }, campaign);
    s.keys = keys;
    s.recipients = decoded.header.recipients;
    s.snapshotVersion = decoded.header.snapshot_version;
    s.keyEpoch = epoch;
    return s.start();
  }

  private async start(): Promise<Session> {
    this.bootstrapped = true;
    this.cb.onStatus("local");
    void this.persistNow();
    this.cb.onChange();
    return this;
  }

  // ---- public surface used by the store ----------------------------------

  get connected(): boolean {
    return this.bootstrapped;
  }

  hasVault(): boolean {
    return this.keys.vaultKey !== undefined;
  }

  provenance(): Provenance {
    const t = Date.now();
    return {
      author: this.operatorId,
      source: { kind: "manual" },
      confidence: "confirmed",
      first_seen: t,
      last_verified: t,
    };
  }

  /** Persist everything changed locally (debounced; the folder `.camp` and the
   * IndexedDB cache are both rewritten). */
  flush(): void {
    this.schedulePersist();
  }

  /** Enroll a co-operator (lead action): record them in the doc roster and seal
   * the *unchanged* campaign key to their wrapping key, so the next auto-saved
   * file opens for them. No key rotation — all existing content stays readable.
   * `this.recipients` is mutated synchronously before any persist, so a
   * concurrent auto-save also carries the new envelope. Hand the resulting
   * `.camp` to the operator out of band. */
  enrollOperator(spec: RecipientSpec): void {
    if (!this.bootstrapped) throw new Error("cannot enroll before bootstrap");
    if (spec.operatorId === this.operatorId) return;
    this.campaign.setRosterEntry({
      operator_id: spec.operatorId,
      display_name: spec.displayName || spec.operatorId,
      signing_pubkey: spec.signingB64,
      wrapping_pubkey: spec.wrappingB64,
      role: spec.grantVault ? "operator" : "observer",
      status: "active",
      added_by: this.operatorId,
      added_at: Date.now(),
    });
    // Add the recipient, or REPLACE an existing one whose keys changed — the
    // latter is the lost-device recovery path: an operator returns with a new
    // derived identity, a teammate re-enrolls them, and their envelope is
    // re-sealed to the new keys (the old device's envelope is dropped). The
    // campaign key is unchanged, so every prior snapshot stays readable.
    const existing = this.recipients.find((r) => r.operator_id === spec.operatorId);
    if (!existing || existing.signing_public_key !== spec.signingB64) {
      const recipient = buildRecipient(
        spec.operatorId,
        { signing: fromB64(spec.signingB64), wrapping: fromB64(spec.wrappingB64) },
        this.keys,
        spec.grantVault,
      );
      this.recipients = existing
        ? this.recipients.map((r) => (r.operator_id === spec.operatorId ? recipient : r))
        : [...this.recipients, recipient];
    }
    this.snapshotVersion = this.nextSnapshotVersion();
    this.flush(); // persist the roster edit + the new envelope
  }

  /** Revoke a co-operator (lead action): mark them revoked in the roster, then
   * rotate the campaign keys so a copy of the file they still hold opens nothing
   * new — the next auto-saved file is sealed under fresh keys they lack. */
  removeOperator(operatorId: string): void {
    if (!this.bootstrapped) throw new Error("cannot remove before bootstrap");
    if (operatorId === this.operatorId) throw new Error("cannot remove yourself");
    this.campaign.setRosterStatus(operatorId, "revoked");
    this.rotateCampaign();
  }

  /** Rotate the campaign keys. Mint fresh keys, re-wrap them for the **active**
   * roster only (read from the converged doc at rebuild time, so a concurrently
   * enrolled operator is never dropped), and re-seal the snapshot at the next
   * epoch — so a removed operator can neither recover keys nor read anything
   * saved after the rotation. */
  rotateCampaign(): void {
    if (!this.bootstrapped) throw new Error("cannot rotate before bootstrap");
    const keys = generateCampaignKeys();
    // Re-seal every vaulted secret old-key -> new-key BEFORE swapping keys in.
    // Otherwise rotation mints a fresh random vaultKey, leaves every existing
    // `secret_sealed` blob encrypted under the old key, and re-wraps only the new
    // (unusable) vault key to the roster — silently bricking the whole loot vault.
    this.resealVault(this.keys.vaultKey, keys.vaultKey);
    this.keys = keys;
    this.recipients = this.recipientsFromRoster(keys);
    this.keyEpoch += 1;
    this.snapshotVersion = this.nextSnapshotVersion();
    void this.persistNow();
  }

  /** Recipient envelopes for the active roster (self always included, with vault). */
  private recipientsFromRoster(keys: CampaignKeys): Recipient[] {
    const self = buildRecipient(this.operatorId, this.identity.pub, keys, true);
    const others = this.campaign
      .roster()
      .filter(
        (e) =>
          e.status === "active" &&
          e.operator_id !== this.operatorId &&
          e.signing_pubkey &&
          e.wrapping_pubkey,
      )
      .map((e) =>
        buildRecipient(
          e.operator_id,
          { signing: fromB64(e.signing_pubkey), wrapping: fromB64(e.wrapping_pubkey) },
          keys,
          e.role !== "observer",
        ),
      );
    return [self, ...others];
  }

  /** Re-seal every vaulted secret (credentials + folded loot members) from an old
   * vault key to a new one. Invoked by rotateCampaign before the key swap. Blobs
   * that fail to open under the old key are left untouched; never throws. */
  private resealVault(oldKey: Uint8Array | undefined, newKey: Uint8Array | undefined): void {
    if (!oldKey || !newKey) return; // no vault on one side — nothing to migrate
    const reseal = (blob: string): string | null => {
      try {
        const plaintext = openSecret(oldKey, JSON.parse(blob) as SealedBlob);
        return JSON.stringify(sealSecret(newKey, plaintext));
      } catch {
        return null;
      }
    };
    for (const c of this.campaign.credentials()) {
      if (!c.secret_sealed) continue;
      const next = reseal(c.secret_sealed);
      if (next) this.campaign.setCredentialSecretSealed(c.id, next);
    }
    for (const coll of this.campaign.collections()) {
      for (const member of this.campaign.collectionMembers(coll.id)) {
        if (!member.sealed_secrets?.length) continue;
        let changed = false;
        const resealed = member.sealed_secrets.map((s) => {
          if (!s.sealed) return s;
          const next = reseal(s.sealed);
          if (!next) return s;
          changed = true;
          return { ...s, sealed: next };
        });
        if (changed) this.campaign.setMemberSealedSecrets(coll.id, member.key, resealed);
      }
    }
  }

  sealCredentialSecret(plaintext: string): string {
    if (!this.keys.vaultKey) throw new Error("no vault access");
    return JSON.stringify(sealSecret(this.keys.vaultKey, utf8(plaintext)));
  }

  openCredentialSecret(sealedJson: string): string {
    if (!this.keys.vaultKey) throw new Error("no vault access");
    return utf8d(openSecret(this.keys.vaultKey, JSON.parse(sealedJson) as SealedBlob));
  }

  disconnect(): void {
    clearTimeout(this.persistTimer ?? undefined);
    this.persistTimer = null;
  }

  // ---- file & persistence internals ---------------------------------------

  /** A strictly-increasing snapshot version. Wall-clock by default, but never
   * less than the previous local value + 1, so two saves in the same millisecond
   * still increase. */
  private nextSnapshotVersion(): number {
    return Math.max(this.snapshotVersion + 1, Date.now());
  }

  private buildFileBytes(): Uint8Array {
    const header: CampaignFileHeader = {
      format_version: 2,
      campaign_id: this.campaign.campaignId,
      recipients: this.recipients,
      snapshot_version: this.snapshotVersion,
      key_epoch: this.keyEpoch,
    };
    const sealed_snapshot = sealContentAt(
      this.keys.campaignKey,
      this.campaign.campaignId,
      this.keyEpoch,
      this.campaign.exportSnapshot(),
    );
    return encodeCampaignFile({ header, sealed_snapshot });
  }

  /** The campaign as a sovereign, portable, encrypted campaign file (header +
   * sealed snapshot). Everything stays sealed under the campaign key, so it is
   * safe to copy, archive, or hand off out of band; a holder still needs to be
   * a recipient to open it. */
  exportCampaignFile(): Uint8Array {
    if (!this.bootstrapped) throw new Error("the campaign is not ready to export yet");
    return this.buildFileBytes();
  }

  private schedulePersist(): void {
    clearTimeout(this.persistTimer ?? undefined);
    this.persistTimer = setTimeout(() => void this.persistNow(), PERSIST_DEBOUNCE);
  }

  private async persistNow(): Promise<void> {
    try {
      await saveCampaignState(this.campaign.campaignId, {
        snapshot: this.campaign.exportSnapshot(),
      });
      // Keep the sovereign file on disk current — it is the authoritative copy.
      if (this.saveFolder && this.saveFileName) {
        await platform.writeCampaignFile(this.saveFolder, this.saveFileName, this.buildFileBytes());
      }
    } catch (e) {
      console.warn("local persist failed:", e);
    }
  }
}
