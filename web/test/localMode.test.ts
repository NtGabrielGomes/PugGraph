// The local-only session contract: create, edit, export and reopen a campaign
// with no transport of any kind. The sovereign .camp file is the whole world;
// multi-operator sharing works by enrolling a recipient (key sealed into the
// file) and handing them the file out of band.

import { describe, it, expect, beforeAll } from "vitest";
import {
  ready,
  generateOperator,
  operatorPublic,
  toB64,
  decodeCampaignFile,
  openCampaignKeys,
  openContentAt,
} from "@/crypto/primitives";
import { Session, type SessionStatus } from "@/campaign/session";
import type { Identity } from "@/crypto/identity";
import type { GraphNode, Provenance } from "@/domain/types";

beforeAll(() => ready());

const makeIdentity = (operatorId: string): Identity => {
  const secret = generateOperator();
  return { operatorId, displayName: operatorId, secret, pub: operatorPublic(secret) };
};

const prov = (): Provenance => ({
  author: "solo",
  source: { kind: "manual" },
  confidence: "confirmed",
  first_seen: 1000,
  last_verified: 1000,
});

const node = (id: string): GraphNode => ({
  id,
  kind: "host_windows",
  label: id,
  identity_keys: [{ kind: "ip_address", value: "10.0.0.9", is_primary: true }],
  compromise_level: "unknown",
  fields: {},
  tags: [],
  provenance: prov(),
});

const localOpts = (identity: Identity, statuses: SessionStatus[]) => ({
  identity,
  campaignId: "local-op",
  onChange: () => {},
  onStatus: (s: SessionStatus) => {
    statuses.push(s);
  },
});

describe("local-only session", () => {
  it("creates, edits and exports a campaign with no transport anywhere", async () => {
    const identity = makeIdentity("solo");
    const statuses: SessionStatus[] = [];
    const s = await Session.create({ ...localOpts(identity, statuses), recipients: [], seedDemo: false });
    try {
      expect(s.connected).toBe(true);
      expect(statuses).toContain("local");

      s.campaign.upsertNode(node("n1"));
      s.flush();

      const bytes = s.exportCampaignFile();
      const decoded = decodeCampaignFile(bytes);
      expect(decoded.header.campaign_id).toBe("local-op");
      const keys = openCampaignKeys(decoded.header, "solo", identity.secret);
      const snap = openContentAt(keys.campaignKey, "local-op", decoded.header.key_epoch ?? 0, decoded.sealed_snapshot);
      expect(snap.length).toBeGreaterThan(0);
    } finally {
      s.disconnect();
    }
  });

  it("reopens an exported file and sees the prior edits", async () => {
    const identity = makeIdentity("solo");
    const first = await Session.create({ ...localOpts(identity, []), recipients: [], seedDemo: false });
    first.campaign.upsertNode(node("n1"));
    first.flush();
    const bytes = first.exportCampaignFile();
    first.disconnect();

    const statuses: SessionStatus[] = [];
    const reopened = await Session.fromFile(localOpts(identity, statuses), bytes);
    try {
      expect(reopened.connected).toBe(true);
      expect(statuses).toContain("local");
      expect(reopened.campaign.nodes().map((n) => n.id)).toContain("n1");
    } finally {
      reopened.disconnect();
    }
  });

  it("shares the campaign by file: an enrolled co-operator opens the exported bytes", async () => {
    const alice = makeIdentity("alice");
    const bob = makeIdentity("bob");

    const s = await Session.create({ ...localOpts(alice, []), recipients: [], seedDemo: false });
    s.campaign.upsertNode(node("shared-host"));
    s.enrollOperator({
      operatorId: "bob",
      signingB64: toB64(bob.pub.signing),
      wrappingB64: toB64(bob.pub.wrapping),
      grantVault: true,
      displayName: "bob",
    });
    const bytes = s.exportCampaignFile();
    s.disconnect();

    // Bob opens the handed-off file with his own identity — no server involved.
    const bobs = await Session.fromFile(localOpts(bob, []), bytes);
    try {
      expect(bobs.connected).toBe(true);
      expect(bobs.campaign.nodes().map((n) => n.id)).toContain("shared-host");
      expect(bobs.hasVault()).toBe(true);
    } finally {
      bobs.disconnect();
    }
  });

  it("a revoked operator cannot open files saved after the rotation", async () => {
    const alice = makeIdentity("alice");
    const bob = makeIdentity("bob");

    const s = await Session.create({ ...localOpts(alice, []), recipients: [], seedDemo: false });
    s.enrollOperator({
      operatorId: "bob",
      signingB64: toB64(bob.pub.signing),
      wrappingB64: toB64(bob.pub.wrapping),
      grantVault: true,
    });
    s.removeOperator("bob");
    const rotatedBytes = s.exportCampaignFile();
    s.disconnect();

    expect(() =>
      openCampaignKeys(decodeCampaignFile(rotatedBytes).header, "bob", bob.secret),
    ).toThrow();
  });
});
