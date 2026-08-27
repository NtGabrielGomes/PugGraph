// Collaboration & engagement-lifecycle containers: claims (deconfliction),
// detections (OPSEC log), tasks (board), objectives (SOW), scope (RoE). All
// web-managed, sealed-op synced, and convergent like the rest of the document.

import { describe, it, expect } from "vitest";
import { Campaign } from "@/campaign/document";
import type { Claim, Detection, Objective, Scope, Task } from "@/domain/types";

const claim = (node_id: string, op: string): Claim => ({ node_id, operator_id: op, intent: "beaconing", claimed_at: 10, expires_at: 1010 });
const det = (id: string): Detection => ({ id, at: 5, operator: "op", vector: "T1003.001", tooling: "nanodump", noise_level: "loud", outcome: "alerted", control: "MDE" });
const task = (id: string, over: Partial<Task> = {}): Task => ({ id, title: id, created_by: "op", status: "todo", priority: "med", created_at: 1, updated_at: 1, ...over });
const obj = (id: string): Objective => ({ id, title: id, status: "not_started", priority: "high", created_by: "op", created_at: 1 });

describe("claims (deconfliction)", () => {
  it("holds one claim per node and releases it; converges across replicas", () => {
    const a = new Campaign("c", 1n);
    const b = new Campaign("c", 2n);
    a.setClaim(claim("dc01", "alice"));
    b.import(a.exportSnapshot());
    expect(b.claims()[0]!.operator_id).toBe("alice");
    a.releaseClaim("dc01");
    b.import(a.exportSnapshot());
    expect(b.claims()).toHaveLength(0);
  });
});

describe("detections (OPSEC log)", () => {
  it("records detection events and round-trips through a snapshot", () => {
    const a = new Campaign("c", 1n);
    a.addDetection(det("d1"));
    const b = Campaign.fromSnapshot("c", 2n, a.exportSnapshot());
    const d = b.detections()[0]!;
    expect(d).toMatchObject({ vector: "T1003.001", noise_level: "loud", outcome: "alerted", control: "MDE" });
  });
});

describe("tasks (board)", () => {
  it("creates, assigns, and transitions tasks", () => {
    const c = new Campaign("c", 1n);
    c.addTask(task("t1", { node_ref: "ws01" }));
    c.assignTask("t1", "bob", 2);
    c.setTaskStatus("t1", "in_progress", 3);
    const t = c.tasks()[0]!;
    expect(t.assignee).toBe("bob");
    expect(t.status).toBe("in_progress");
    expect(t.updated_at).toBe(3);
    c.assignTask("t1", undefined, 4); // unassign
    expect(c.tasks()[0]!.assignee).toBeUndefined();
  });

  it("converges concurrent task edits across two replicas", () => {
    const a = new Campaign("c", 1n);
    const b = new Campaign("c", 2n);
    a.addTask(task("t1"));
    b.import(a.exportSnapshot());
    a.addTask(task("t2"));
    b.setTaskStatus("t1", "done", 9);
    a.import(b.exportSnapshot());
    b.import(a.exportSnapshot());
    expect(a.toJSON()).toEqual(b.toJSON());
    expect(a.tasks().map((t) => t.id).sort()).toEqual(["t1", "t2"]);
  });
});

describe("objectives (SOW)", () => {
  it("tracks objective status + achievement", () => {
    const c = new Campaign("c", 1n);
    c.addObjective(obj("o1"));
    c.setObjectiveStatus("o1", "achieved", 500);
    const o = c.objectives()[0]!;
    expect(o.status).toBe("achieved");
    expect(o.achieved_at).toBe(500);
  });
});

describe("scope / RoE", () => {
  it("round-trips the scope record and clears optional notes", () => {
    const a = new Campaign("c", 1n);
    const s: Scope = {
      in_scope_cidrs: ["10.0.0.0/8"],
      out_of_scope_cidrs: ["10.9.9.0/24"],
      forbidden_node_ids: ["prod-db"],
      time_windows: [{ start: "18:00", end: "06:00", tz: "UTC", label: "after hours" }],
      notes: "no destructive actions",
    };
    a.setScope(s);
    const b = Campaign.fromSnapshot("c", 2n, a.exportSnapshot());
    expect(b.scope()).toEqual(s);
    a.setScope({ ...s, notes: undefined });
    expect(a.scope().notes).toBeUndefined();
  });

  it("defaults to empty arrays when unset", () => {
    const c = new Campaign("c", 1n);
    expect(c.scope()).toEqual({ in_scope_cidrs: [], out_of_scope_cidrs: [], forbidden_node_ids: [], time_windows: [], notes: undefined });
  });
});
