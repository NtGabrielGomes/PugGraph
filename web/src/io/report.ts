// Structured report export. A pure projection of the decrypted campaign into a
// Markdown document (the canonical format) plus the structured object behind it
// (the JSON export). Everything is assembled client-side from already-decrypted
// state; credential *secrets* are never included - only existence and validity -
// so a report can be shared without leaking the vault.

import { readFindings, SEVERITIES, type Finding } from "@/domain/fieldSchema";
import { isHighValue } from "@/domain/types";
import type { Credential, GraphNode } from "@/domain/types";

export interface ReportPath {
  hops: string[];
  to: string;
}

export interface ReportInput {
  campaignId: string;
  generatedAt: number;
  nodes: GraphNode[];
  credentials: Credential[];
  events: { author: string; at: number; action: string; summary: string }[];
  attackPaths: ReportPath[];
  operators: { operatorId: string; displayName: string }[];
}

export interface ReportData {
  campaignId: string;
  generatedAt: number;
  operators: string[];
  summary: {
    compromised: number;
    byLevel: Record<string, number>;
    highValueReached: string[];
    findingCounts: Record<string, number>;
  };
  access: { host: string; method: string; note?: string }[];
  attackPaths: { path: string[]; hops: number }[];
  findings: { host: string; title: string; severity: string; status: string; note?: string }[];
  credentials: { principal: string; type: string; validity: string; source: string; validOn: string[] }[];
  assets: Record<string, string[]>;
  timeline: { author: string; at: number; action: string; summary: string }[];
}

const sevRank = (s: string): number => SEVERITIES.indexOf(s as Finding["severity"]);

/** Build the structured report data and its Markdown rendering. */
export function buildReport(input: ReportInput): { markdown: string; data: ReportData } {
  const { nodes, credentials, events, attackPaths, operators, campaignId, generatedAt } = input;
  const labelOf = new Map(nodes.map((n) => [n.id, n.label || n.id]));

  const compromised = nodes.filter((n) => n.compromise_level !== "unknown" && n.compromise_level !== "none");
  const byLevel: Record<string, number> = {};
  for (const n of compromised) byLevel[n.compromise_level] = (byLevel[n.compromise_level] ?? 0) + 1;
  const highValueReached = compromised.filter((n) => isHighValue(n.kind)).map((n) => n.label || n.id);

  const findings = nodes
    .flatMap((n) => readFindings(n.fields).map((f) => ({ host: n.label || n.id, title: f.title, severity: f.severity, status: f.status, note: f.note })))
    .sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  const findingCounts: Record<string, number> = {};
  for (const f of findings) findingCounts[f.severity] = (findingCounts[f.severity] ?? 0) + 1;

  const access = nodes
    .filter((n) => typeof n.fields["compromise_method"] === "string" && n.fields["compromise_method"])
    .map((n) => ({
      host: n.label || n.id,
      method: String(n.fields["compromise_method"]),
      note: typeof n.fields["compromise_note"] === "string" ? String(n.fields["compromise_note"]) : undefined,
    }));

  const creds = credentials.map((c) => ({
    principal: c.domain ? `${c.username}@${c.domain}` : c.username,
    type: c.credential_type,
    validity: c.validity,
    source: c.source,
    // Only where-valid; never the secret.
    validOn: c.tested_against.filter((t) => t.succeeded).map((t) => labelOf.get(t.host) ?? t.host),
  }));

  const assets: Record<string, string[]> = {};
  for (const n of nodes) (assets[n.kind] ??= []).push(n.label || n.id);

  const paths = attackPaths.map((p) => ({ path: p.hops.map((h) => labelOf.get(h) ?? h), hops: Math.max(0, p.hops.length - 1) }));

  const data: ReportData = {
    campaignId,
    generatedAt,
    operators: operators.map((o) => o.displayName || o.operatorId),
    summary: { compromised: compromised.length, byLevel, highValueReached, findingCounts },
    access,
    attackPaths: paths,
    findings,
    credentials: creds,
    assets,
    timeline: events,
  };

  return { markdown: renderMarkdown(data), data };
}

const ts = (at: number): string => (at ? new Date(at).toISOString() : "");

function renderMarkdown(d: ReportData): string {
  const L: string[] = [];
  L.push(`# Campaign Report`);
  L.push("");
  L.push(`**Campaign:** \`${d.campaignId}\``);
  L.push(`**Generated:** ${ts(d.generatedAt)}`);
  L.push(`**Operators:** ${d.operators.join(", ") || "-"}`);
  L.push("");

  L.push(`## Executive Summary`);
  L.push(`- **Compromised assets:** ${d.summary.compromised}` + (Object.keys(d.summary.byLevel).length ? ` (${Object.entries(d.summary.byLevel).map(([k, v]) => `${v} ${k}`).join(", ")})` : ""));
  L.push(`- **High-value targets reached:** ${d.summary.highValueReached.length ? d.summary.highValueReached.join(", ") : "none"}`);
  const fc = SEVERITIES.slice().reverse().filter((s) => d.summary.findingCounts[s]).map((s) => `${d.summary.findingCounts[s]} ${s}`);
  L.push(`- **Findings:** ${fc.length ? fc.join(", ") : "none"}`);
  L.push("");

  L.push(`## How Access Was Obtained`);
  if (d.access.length === 0) L.push(`_No access vectors recorded._`);
  else for (const a of d.access) L.push(`- **${a.host}** — ${a.method}${a.note ? ` (${a.note})` : ""}`);
  L.push("");

  L.push(`## Attack Paths`);
  if (d.attackPaths.length === 0) L.push(`_No path from a compromised host to a high-value target._`);
  else for (const p of d.attackPaths) L.push(`- ${p.path.join(" → ")} _(${p.hops} hop${p.hops === 1 ? "" : "s"})_`);
  L.push("");

  L.push(`## Findings`);
  if (d.findings.length === 0) L.push(`_No findings recorded._`);
  else {
    L.push(`| Severity | Host | Finding | Status |`);
    L.push(`| --- | --- | --- | --- |`);
    for (const f of d.findings) L.push(`| ${f.severity} | ${f.host} | ${f.title} | ${f.status} |`);
  }
  L.push("");

  L.push(`## Credentials`);
  L.push(`_Existence and validity only - secrets are never exported._`);
  if (d.credentials.length === 0) L.push(`_No credentials recorded._`);
  else {
    L.push(`| Principal | Type | Validity | Valid on |`);
    L.push(`| --- | --- | --- | --- |`);
    for (const c of d.credentials) L.push(`| ${c.principal} | ${c.type} | ${c.validity} | ${c.validOn.join(", ") || "-"} |`);
  }
  L.push("");

  L.push(`## Asset Inventory`);
  for (const [kind, labels] of Object.entries(d.assets)) {
    L.push(`### ${kind} (${labels.length})`);
    L.push(labels.map((l) => `- ${l}`).join("\n"));
  }
  L.push("");

  L.push(`## Timeline (audit trail)`);
  L.push(`${d.timeline.length} event(s). Append-only and hash-chained in the campaign core.`);
  L.push("");
  for (const e of d.timeline.slice().reverse()) L.push(`- \`${ts(e.at)}\` **${e.author}** ${e.action}: ${e.summary}`);
  L.push("");

  return L.join("\n");
}
