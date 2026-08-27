// The command layer is the design-pattern win of the store refactor: business logic
// + activity-log rules live in pure functions over (campaign, session), so they are
// testable WITHOUT constructing the store, the relay, or a real Session.

import { describe, it, expect } from "vitest";
import { Campaign } from "@/campaign/document";
import type { Session } from "@/campaign/session";
import type { Provenance } from "@/domain/types";
import type { TimelineEvent } from "@/data/repositories/CampaignRepository";
import * as m from "@/state/mutations";

const prov = (): Provenance => ({
  author: "op1",
  source: { kind: "manual" },
  confidence: "confirmed",
  first_seen: 0,
  last_verified: 0,
});

// The commands only touch operatorId / provenance() / hasVault() / sealCredentialSecret().
const fakeSession = {
  operatorId: "op1",
  provenance: () => prov(),
  hasVault: () => false,
  sealCredentialSecret: () => "",
} as unknown as Session;

describe("command layer (state/mutations) — testable without the store", () => {
  it("createNode + setCompromise mutate the doc and log the activity", () => {
    const c = new Campaign("c", 1n);
    const id = m.createNode(c, fakeSession, "host_windows", "WS01", "unknown");
    expect(c.nodes().find((n) => n.id === id)?.label).toBe("WS01");

    m.setCompromise(c, fakeSession, id, "admin");
    expect(c.nodes().find((n) => n.id === id)?.compromise_level).toBe("admin");
    expect((c.events() as TimelineEvent[]).some((e) => e.action === "node.compromise" && e.summary.includes("admin"))).toBe(true);
  });

  it("createEdge links two nodes and logs a labelled summary", () => {
    const c = new Campaign("c", 1n);
    const a = m.createNode(c, fakeSession, "host_windows", "A", "admin");
    const b = m.createNode(c, fakeSession, "domain", "CORP", "unknown");
    const eid = m.createEdge(c, fakeSession, a, b, "dc_sync", "confirmed", (id) => (id === a ? "A" : "CORP"));
    expect(c.edges().find((e) => e.id === eid)?.kind).toBe("dc_sync");
    expect((c.events() as TimelineEvent[]).some((e) => e.action === "edge.add" && e.summary.includes("A -[dc_sync]-> CORP"))).toBe(true);
  });

  it("addCredential records the credential and a redacted log line (no secret)", () => {
    const c = new Campaign("c", 1n);
    m.addCredential(c, fakeSession, {
      username: "svc_sql",
      domain: "corp",
      credential_type: "password_ntlm",
      source: "dump",
      secret: "hunter2",
    });
    expect(c.credentials()[0]?.username).toBe("svc_sql");
    const ev = (c.events() as TimelineEvent[]).find((e) => e.action === "credential.add");
    expect(ev?.summary).toBe("svc_sql@corp (password_ntlm)");
    expect(ev?.summary).not.toContain("hunter2");
  });
});

describe("clearGraph (hard reset)", () => {
  it("wipes nodes, edges and positions in one action", () => {
    const c = new Campaign("clear", 1n);
    const mk = (id: string) =>
      m.createNode(c, fakeSession, "host_windows", id, "unknown");
    const a = mk("WS01");
    const b = mk("WS02");
    c.addEdge({ id: "e1", kind: "member_of", source: a, target: b, confidence: "confirmed", fields: {}, provenance: prov() });
    c.setNodePosition(a, 10, 20);
    m.clearGraph(c, fakeSession);
    expect(c.nodes()).toHaveLength(0);
    expect(c.edges()).toHaveLength(0);
    expect(c.positions()).toEqual({});
    expect((c.events() as TimelineEvent[]).some((e) => e.action === "graph.clear")).toBe(true);
  });
});
