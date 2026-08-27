// @vitest-environment jsdom
import { describe, it, expect } from "vitest";
import { Campaign } from "@/campaign/document";
import {
  applyBloodhound,
  applyNessus,
  applyNetexec,
  applyNmap,
  importFiles,
  parseBloodhound,
  parseNessus,
  parseNetexec,
  parseNmap,
} from "@/io/import";

const ctx = { author: "op", now: 1000 };

// Fixtures match the Rust importer tests, so TS and Rust produce the same graph.
const NMAP = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <address addr="00:0c:29:aa:bb:cc" addrtype="mac"/>
    <hostnames><hostname name="DC01.corp.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows" version="2019"/></port>
      <port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec"/></port>
      <port protocol="tcp" portid="139"><state state="closed"/><service name="netbios-ssn"/></port>
    </ports>
    <os><osmatch name="Microsoft Windows Server 2019"/></os>
  </host>
</nmaprun>`;

const BH_DOMAINS = `{"meta":{"type":"domains"},"data":[{"objectid":"S-1-5-21-DOMAIN","name":"CORP.LOCAL","properties":{"name":"CORP.LOCAL","domain":"CORP.LOCAL"},"Trusts":[{"TargetDomainSid":"S-1-5-21-PARTNER","TargetDomainName":"PARTNER.LOCAL"}]}]}`;
const BH_COMPUTERS = `{"meta":{"type":"computers"},"data":[{"objectid":"S-1-5-21-DOMAIN-1001","name":"DC01.CORP.LOCAL","properties":{"name":"DC01.CORP.LOCAL","operatingsystem":"Windows Server 2019","domain":"CORP.LOCAL"},"LocalAdmins":{"Results":[{"ObjectIdentifier":"S-1-5-21-DOMAIN-512"}]},"Sessions":{"Results":[{"ComputerSID":"S-1-5-21-DOMAIN-1001","UserSID":"S-1-5-21-DOMAIN-1105"}]}}]}`;
const BH_USERS = `{"meta":{"type":"users"},"data":[{"objectid":"S-1-5-21-DOMAIN-1105","name":"JDOE@CORP.LOCAL","properties":{"name":"JDOE@CORP.LOCAL"},"Aces":[{"PrincipalSID":"S-1-5-21-DOMAIN-512","RightName":"GenericAll"}]}]}`;
const BH_GROUPS = `{"meta":{"type":"groups"},"data":[{"objectid":"S-1-5-21-DOMAIN-512","name":"DOMAIN ADMINS@CORP.LOCAL","properties":{"name":"DOMAIN ADMINS@CORP.LOCAL"},"Members":[{"ObjectIdentifier":"S-1-5-21-DOMAIN-1105"}]}]}`;

const NXC = `SMB  10.0.0.1  445  DC01  [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL)
SMB  10.0.0.1  445  DC01  [+] CORP.LOCAL\\administrator:Passw0rd! (Pwn3d!)
SMB  10.0.0.2  445  WS01  [*] Windows 10 (name:WS01) (domain:CORP.LOCAL)
SMB  10.0.0.2  445  WS01  [-] CORP.LOCAL\\guest:badpass STATUS_LOGON_FAILURE
SMB  10.0.0.2  445  WS01  [+] CORP.LOCAL\\administrator:Passw0rd!`;

const NESSUS = `<?xml version="1.0"?>
<NessusClientData_v2><Report name="scan"><ReportHost name="10.0.0.1">
  <HostProperties>
    <tag name="host-ip">10.0.0.1</tag>
    <tag name="host-fqdn">dc01.corp.local</tag>
    <tag name="operating-system">Microsoft Windows Server 2019</tag>
  </HostProperties>
  <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="4" pluginName="MS17-010"></ReportItem>
  <ReportItem port="3389" svc_name="msrdp" protocol="tcp" severity="2" pluginName="RDP weak crypto"></ReportItem>
  <ReportItem port="0" protocol="tcp" severity="0" pluginName="Nessus Scan Info"></ReportItem>
</ReportHost></Report></NessusClientData_v2>`;

describe("browser import (TS parity with the Rust importers)", () => {
  it("nmap: 1 host + 2 open services + 2 edges", () => {
    const c = new Campaign("c1", 1n);
    const s = applyNmap(c, parseNmap(NMAP), ctx);
    expect([s.hosts, s.services, s.edges]).toEqual([1, 2, 2]);
    expect(c.nodes().length).toBe(3);
    expect(c.edges().length).toBe(2);
    const host = c.nodes().find((n) => n.kind === "host_windows")!;
    expect(host.fields.os_version).toBe("Microsoft Windows Server 2019");
  });

  it("bloodhound: 5 nodes + 5 canonical edges", () => {
    const c = new Campaign("c1", 1n);
    const files = [BH_DOMAINS, BH_COMPUTERS, BH_USERS, BH_GROUPS].map(parseBloodhound);
    applyBloodhound(c, files, ctx);
    expect(c.nodes().length).toBe(5);
    expect(c.edges().length).toBe(5);
    const kinds = new Set(c.edges().map((e) => e.kind));
    for (const k of ["member_of", "generic_all", "trusts", "has_session", "admin_to"]) {
      expect(kinds.has(k as never)).toBe(true);
    }
  });

  it("bloodhound: parses abuse properties + the full ACE set the importer used to drop", () => {
    const BH_ABUSE_USERS = `{"meta":{"type":"users"},"data":[
      {"objectid":"S-1-5-21-D-1106","name":"SVC_SQL@CORP.LOCAL","properties":{"name":"SVC_SQL@CORP.LOCAL","hasspn":true,"serviceprincipalnames":["MSSQLSvc/db:1433"],"admincount":true}},
      {"objectid":"S-1-5-21-D-1107","name":"NOPRE@CORP.LOCAL","properties":{"name":"NOPRE@CORP.LOCAL","dontreqpreauth":true}}
    ]}`;
    const BH_ABUSE_COMPUTERS = `{"meta":{"type":"computers"},"data":[{"objectid":"S-1-5-21-D-2001","name":"WS9.CORP.LOCAL","properties":{"name":"WS9.CORP.LOCAL","unconstraineddelegation":true},"Aces":[
      {"PrincipalSID":"S-1-5-21-D-1106","RightName":"GenericWrite"},
      {"PrincipalSID":"S-1-5-21-D-1106","RightName":"WriteOwner"},
      {"PrincipalSID":"S-1-5-21-D-1106","RightName":"AllExtendedRights"},
      {"PrincipalSID":"S-1-5-21-D-1106","RightName":"WriteGPLink"}
    ]}]}`;
    const c = new Campaign("c1", 1n);
    applyBloodhound(c, [BH_ABUSE_USERS, BH_ABUSE_COMPUTERS].map(parseBloodhound), ctx);
    const svc = c.nodes().find((n) => n.id && n.label === "SVC_SQL@CORP.LOCAL")!;
    expect(svc.kind).toBe("service_account"); // SPN-bearing user reclassified
    expect(svc.fields.kerberoastable).toBe(true);
    expect(svc.fields.admin_count).toBe(true);
    expect(svc.fields.spn).toEqual(["MSSQLSvc/db:1433"]);
    const nopre = c.nodes().find((n) => n.label === "NOPRE@CORP.LOCAL")!;
    expect(nopre.fields.asrep_roastable).toBe(true);
    const ws9 = c.nodes().find((n) => n.label === "WS9.CORP.LOCAL")!;
    expect(ws9.fields.unconstrained_delegation).toBe(true);
    const kinds = new Set(c.edges().map((e) => e.kind));
    for (const k of ["generic_write", "write_owner", "all_extended_rights", "write_gp_link"]) {
      expect(kinds.has(k as never)).toBe(true);
    }
  });

  it("bloodhound: carries trust semantics (direction/type/transitive/sid_filtering) the cost model routes on (B3)", () => {
    const BH_DOM = `{"meta":{"type":"domains"},"data":[{"objectid":"S-1-5-21-A","name":"A.LOCAL","properties":{"name":"A.LOCAL"},"Trusts":[{"TargetDomainSid":"S-1-5-21-B","TargetDomainName":"B.LOCAL","TrustDirection":2,"TrustType":"Forest","IsTransitive":true,"SidFilteringEnabled":false}]}]}`;
    const c = new Campaign("c1", 1n);
    applyBloodhound(c, [BH_DOM].map(parseBloodhound), ctx);
    const trust = c.edges().find((e) => e.kind === "trusts")!;
    expect(trust.fields?.direction).toBe("outbound");
    expect(trust.fields?.trust_type).toBe("Forest");
    expect(trust.fields?.transitive).toBe(true);
    expect(trust.fields?.sid_filtering).toBe(false);
  });

  it("netexec: 2 hosts, aggregated credentials, admin compromise on Pwn3d", () => {
    const c = new Campaign("c1", 1n);
    const s = applyNetexec(c, parseNetexec(NXC), ctx);
    expect(s.hosts).toBe(2);
    expect(c.nodes().length).toBe(2);
    expect(c.credentials().length).toBe(2); // administrator (aggregated) + guest
    const dc = c.nodes().find((n) => n.label === "DC01")!;
    expect(dc.compromise_level).toBe("admin");
    const admin = c.credentials().find((cr) => cr.username === "administrator")!;
    expect(admin.tested_against.filter((t) => t.succeeded).length).toBe(2);
  });

  it("nessus: 2 services + 2 edges + a structured critical finding", () => {
    const c = new Campaign("c1", 1n);
    const s = applyNessus(c, parseNessus(NESSUS), ctx);
    expect([s.services, s.edges]).toEqual([2, 2]);
    const svc = c.nodes().find((n) => n.kind === "service" && n.fields.port === 445)!;
    const findings = svc.fields.findings as { title: string; severity: string }[];
    expect(findings.some((f) => f.title === "MS17-010" && f.severity === "critical")).toBe(true);
  });

  it("importFiles dispatches by content and reconciles across tools", () => {
    const c = new Campaign("c1", 1n);
    importFiles(
      c,
      [
        { name: "scan.xml", content: NMAP },
        { name: "computers.json", content: BH_COMPUTERS },
        { name: "domains.json", content: BH_DOMAINS },
        { name: "users.json", content: BH_USERS },
        { name: "groups.json", content: BH_GROUPS },
      ],
      ctx,
    );
    // The Nmap host and the BloodHound computer (same FQDN) collapse to one node.
    const dc = c.nodes().filter((n) => n.label.toLowerCase().includes("dc01"));
    expect(dc.length).toBe(1);
  });
});
