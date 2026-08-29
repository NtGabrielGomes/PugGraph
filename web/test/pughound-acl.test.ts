// Pughound ACL/Azure import: the full-DACL ACLs table is derived with
// SharpHound-parity rules (allow-only, filtered trustees, inheritance class
// matching, rights×GUID×class mapping), and AzureAD_* tables become cloud
// nodes with member_of/owns edges.

import { describe, it, expect } from "vitest";
import { Campaign } from "@/campaign/document";
import { importFiles, type ImportCtx } from "@/io/import";

const ctx: ImportCtx = { author: "op_test", now: 1000 };

const table = (name: string, columns: string[], rows: Record<string, string>[]): string =>
  JSON.stringify({ query: name, columns, rowCount: rows.length, rows });

const DOMAIN_SID = "S-1-5-21-1000-2000-3000";
const USER_DN = "CN=victim,CN=Users,DC=x,DC=lab";
const ATTACKER_SID = `${DOMAIN_SID}-1105`;

const baseTables = (): { name: string; content: string }[] => [
  { name: "DomainSID.json", content: table("DomainSID", ["DomainSID"], [{ DomainSID: DOMAIN_SID }]) },
  {
    name: "Users.json",
    content: table(
      "Users",
      ["sAMAccountName", "distinguishedName", "objectSid", "userPrincipalName"],
      [
        { sAMAccountName: "victim", distinguishedName: USER_DN, objectSid: `${DOMAIN_SID}-1106`, userPrincipalName: "victim@x.lab" },
        { sAMAccountName: "attacker", distinguishedName: "CN=attacker,CN=Users,DC=x,DC=lab", objectSid: ATTACKER_SID, userPrincipalName: "attacker@x.lab" },
      ],
    ),
  },
];

const ACL_COLS = ["Object", "DN", "ObjectClass", "ACE_Type", "SID", "Rights", "ObjectType", "InheritedObjectType", "Flags"];

const importWithAcl = (aclRows: Record<string, string>[], extra: { name: string; content: string }[] = []): Campaign => {
  const c = new Campaign("ph", 1n);
  importFiles(
    c,
    [...baseTables(), { name: "ACLs.json", content: table("ACLs", ACL_COLS, aclRows) }, ...extra],
    ctx,
  );
  return c;
};

const userRow = (over: Partial<Record<string, string>>): Record<string, string> => ({
  Object: "victim",
  DN: USER_DN,
  ObjectClass: "user",
  ACE_Type: "AccessAllowed",
  SID: ATTACKER_SID,
  Rights: "GenericAll",
  ObjectType: "",
  InheritedObjectType: "",
  Flags: "0x00",
  ...over,
});

describe("pughound ACLs table derivation (SharpHound parity)", () => {
  it("allow ACE with unscoped GenericAll yields exactly one generic_all edge", () => {
    const c = importWithAcl([userRow({})]);
    const edges = c.edges().filter((e) => e.kind === "generic_all");
    expect(edges).toHaveLength(1);
    const nodes = c.nodes();
    const attacker = nodes.find((n) => n.label === "attacker")!;
    const victim = nodes.find((n) => n.label === "victim")!;
    expect(edges[0]!.source).toBe(attacker.id);
    expect(edges[0]!.target).toBe(victim.id);
    // GenericAll is exclusive — no sub-right edges from the same ACE.
    expect(c.edges().filter((e) => e.source === attacker.id && e.target === victim.id)).toHaveLength(1);
  });

  it("deny and audit ACEs never become edges", () => {
    const c = importWithAcl([
      userRow({ ACE_Type: "AccessDenied" }),
      userRow({ ACE_Type: "SystemAudit", SID: `${DOMAIN_SID}-1107` }),
    ]);
    expect(c.edges()).toHaveLength(0);
  });

  it("filtered trustees (SYSTEM, Creator Owner, Principal Self) never become edges", () => {
    const c = importWithAcl(["S-1-5-18", "S-1-3-0", "S-1-5-10"].map((sid) => userRow({ SID: sid })));
    expect(c.edges()).toHaveLength(0);
  });

  it("inherited ACE applies only when inheritedObjectType matches the target class", () => {
    const FCP = "00299570-246d-11d0-a768-00aa006e0529";
    const USER_CLASS = "bf967aba-0de6-11d0-a285-00aa003049e2";
    const COMPUTER_CLASS = "bf967a86-0de6-11d0-a285-00aa003049e2";
    const match = importWithAcl([
      userRow({ Rights: "ExtendedRight", ObjectType: FCP, InheritedObjectType: USER_CLASS, Flags: "0x10", ACE_Type: "AccessAllowedObject" }),
    ]);
    expect(match.edges().some((e) => e.kind === "force_change_password")).toBe(true);

    const mismatch = importWithAcl([
      userRow({ Rights: "ExtendedRight", ObjectType: FCP, InheritedObjectType: COMPUTER_CLASS, Flags: "0x10", ACE_Type: "AccessAllowedObject" }),
    ]);
    expect(mismatch.edges().some((e) => e.kind === "force_change_password")).toBe(false);
  });

  it("inherit-only non-inherited ACEs (Exchange-style) are skipped", () => {
    const c = importWithAcl([
      userRow({ Rights: "ExtendedRight", ObjectType: "00299570-246d-11d0-a768-00aa006e0529", InheritedObjectType: "bf967aba-0de6-11d0-a285-00aa003049e2", Flags: "0x08", ACE_Type: "AccessAllowedObject" }),
    ]);
    expect(c.edges()).toHaveLength(0);
  });

  it("class gating: ForceChangePassword GUID on a group target yields nothing", () => {
    const c = importWithAcl([
      userRow({
        Object: "somegroup", DN: "CN=somegroup,CN=Users,DC=x,DC=lab", ObjectClass: "group",
        Rights: "ExtendedRight", ObjectType: "00299570-246d-11d0-a768-00aa006e0529", ACE_Type: "AccessAllowedObject",
      }),
    ]);
    expect(c.edges().some((e) => e.kind === "force_change_password")).toBe(false);
  });

  it("new GUID mappings: WriteGPLink on OU, AddAllowedToAct and AddKeyCredentialLink on computer", () => {
    const ou = userRow({
      Object: "OU=Corp", DN: "OU=Corp,DC=x,DC=lab", ObjectClass: "organizationalUnit",
      Rights: "WriteProperty", ObjectType: "f30e3bbe-9ff0-11d1-b603-0000f80367c1", ACE_Type: "AccessAllowedObject",
    });
    const c = importWithAcl([ou]);
    expect(c.edges().some((e) => e.kind === "write_gp_link")).toBe(true);

    const rbcd = userRow({
      Object: "PC01$", DN: "CN=PC01,CN=Computers,DC=x,DC=lab", ObjectClass: "computer",
      Rights: "WriteProperty", ObjectType: "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79", ACE_Type: "AccessAllowedObject",
    });
    const shadow = userRow({
      Object: "PC01$", DN: "CN=PC01,CN=Computers,DC=x,DC=lab", ObjectClass: "computer",
      Rights: "WriteProperty", ObjectType: "5b47d60f-6090-40b2-9f37-2a4de88f3063", ACE_Type: "AccessAllowedObject",
    });
    const c2 = importWithAcl([rbcd, shadow]);
    expect(c2.edges().some((e) => e.kind === "allowed_to_act")).toBe(true);
    expect(c2.edges().some((e) => e.kind === "shadow_credentials")).toBe(true);
  });

  it("CA bitmask reinterpretation: CreateChild on certificationAuthority becomes manage_ca, never on users", () => {
    const c = importWithAcl([
      userRow({
        Object: "CA01", DN: "CN=CA01,CN=Enrollment Services,DC=x,DC=lab", ObjectClass: "certificationAuthority",
        Rights: "CreateChild",
      }),
    ]);
    expect(c.edges().some((e) => e.kind === "manage_ca")).toBe(true);
    const c2 = importWithAcl([userRow({ Rights: "CreateChild" })]);
    expect(c2.edges().some((e) => e.kind === "manage_ca")).toBe(false);
  });

  it("LAPS: schema-resolved GUID yields read_laps_password only on computers", () => {
    const lapsGuid = "aabbccdd-1111-2222-3333-444455556666";
    const schema = {
      name: "SchemaAttrs.json",
      content: table("SchemaAttrs", ["Name", "SchemaIDGUID"], [{ Name: "ms-LAPS-Password", SchemaIDGUID: lapsGuid }]),
    };
    const row = userRow({
      Object: "PC01$", DN: "CN=PC01,CN=Computers,DC=x,DC=lab", ObjectClass: "computer",
      Rights: "ExtendedRight", ObjectType: lapsGuid, ACE_Type: "AccessAllowedObject",
    });
    const c = importWithAcl([row], [schema]);
    expect(c.edges().some((e) => e.kind === "read_laps_password")).toBe(true);

    // Same ACE on a user target: nothing.
    const c2 = importWithAcl([userRow({ Rights: "ExtendedRight", ObjectType: lapsGuid, ACE_Type: "AccessAllowedObject" })], [schema]);
    expect(c2.edges().some((e) => e.kind === "read_laps_password")).toBe(false);
  });

  it("owner rows yield owns edges, except for filtered SIDs", () => {
    const c = importWithAcl([userRow({ ACE_Type: "Owner", Rights: "" })]);
    expect(c.edges().some((e) => e.kind === "owns")).toBe(true);
    const c2 = importWithAcl([userRow({ ACE_Type: "Owner", SID: "S-1-5-18", Rights: "" })]);
    expect(c2.edges().some((e) => e.kind === "owns")).toBe(false);
  });
});

describe("pughound supporting tables (GMSA, FCP, PSO)", () => {
  it("GMSA_Readers yields read_gmsa_password edges onto the gMSA node", () => {
    const c = new Campaign("ph", 1n);
    importFiles(
      c,
      [
        ...baseTables(),
        {
          name: "GMSA.json",
          content: table("GMSA", ["sAMAccountName", "distinguishedName"], [
            { sAMAccountName: "svc-sql$", distinguishedName: "CN=svc-sql,CN=Managed Service Accounts,DC=x,DC=lab" },
          ]),
        },
        {
          name: "GMSA_Readers.json",
          content: table("GMSA_Readers", ["GMSA", "GMSA_DN", "ReaderName", "ReaderSID", "Rights"], [
            { GMSA: "svc-sql$", GMSA_DN: "CN=svc-sql,CN=Managed Service Accounts,DC=x,DC=lab", ReaderName: "attacker", ReaderSID: ATTACKER_SID, Rights: "Read" },
          ]),
        },
      ],
      ctx,
    );
    const gmsa = c.nodes().find((n) => n.label === "svc-sql$")!;
    const attacker = c.nodes().find((n) => n.label === "attacker")!;
    expect(gmsa.kind).toBe("service_account");
    expect(c.edges().some((e) => e.kind === "read_gmsa_password" && e.source === attacker.id && e.target === gmsa.id)).toBe(true);
  });

  it("ForceChangePassword_ACL yields force_change_password edges; ForceChangePassword_Users flags the account", () => {
    const c = new Campaign("ph", 1n);
    importFiles(
      c,
      [
        ...baseTables(),
        {
          name: "ForceChangePassword_ACL.json",
          content: table("ForceChangePassword_ACL", ["TargetUser", "TargetDN", "AttackerSID", "AttackerName", "Right", "ObjectType"], [
            { TargetUser: "victim", TargetDN: USER_DN, AttackerSID: ATTACKER_SID, AttackerName: "attacker", Right: "ExtendedRight", ObjectType: "00299570-246d-11d0-a768-00aa006e0529" },
          ]),
        },
        {
          name: "ForceChangePassword_Users.json",
          content: table("ForceChangePassword_Users", ["sAMAccountName", "distinguishedName", "pwdLastSet"], [
            { sAMAccountName: "victim", distinguishedName: USER_DN, pwdLastSet: "0" },
          ]),
        },
      ],
      ctx,
    );
    const victim = c.nodes().find((n) => n.label === "victim")!;
    expect(c.edges().some((e) => e.kind === "force_change_password" && e.target === victim.id)).toBe(true);
    expect(victim.fields["must_change_password"]).toBe(true);
  });
});

describe("pughound Azure tables", () => {
  const azureTables = (): { name: string; content: string }[] => [
    { name: "AzureAD_Organization.json", content: table("AzureAD_Organization", ["ID", "DisplayName", "VerifiedDomains"], [{ ID: "tenant-guid", DisplayName: "corp tenant", VerifiedDomains: "corp.onmicrosoft.com" }]) },
    { name: "AzureAD_Users.json", content: table("AzureAD_Users", ["id", "displayName", "userPrincipalName"], [{ id: "user-guid-1", displayName: "Alice", userPrincipalName: "alice@corp.onmicrosoft.com" }]) },
    { name: "AzureAD_Groups.json", content: table("AzureAD_Groups", ["id", "displayName"], [{ id: "group-guid-1", displayName: "Cloud Ops" }]) },
    { name: "AzureAD_GroupMembers.json", content: table("AzureAD_GroupMembers", ["GroupName", "GroupID", "MemberName", "MemberID", "MemberType"], [{ GroupName: "Cloud Ops", GroupID: "group-guid-1", MemberName: "Alice", MemberID: "user-guid-1", MemberType: "User" }]) },
    { name: "AzureAD_ServicePrincipals.json", content: table("AzureAD_ServicePrincipals", ["id", "appId", "displayName"], [{ id: "sp-guid-1", appId: "app-guid-1", displayName: "backup-sp" }]) },
    { name: "AzureAD_ServicePrincipalOwners.json", content: table("AzureAD_ServicePrincipalOwners", ["SPName", "SPObjectID", "OwnerName", "OwnerID", "OwnerType"], [{ SPName: "backup-sp", SPObjectID: "sp-guid-1", OwnerName: "Alice", OwnerID: "user-guid-1", OwnerType: "User" }]) },
    { name: "AzureAD_RoleAssignments.json", content: table("AzureAD_RoleAssignments", ["RoleName", "RoleID", "PrincipalName", "PrincipalID", "PrincipalType"], [{ RoleName: "", RoleID: "62e90394-69f5-4237-9190-012177145e10", PrincipalName: "Alice", PrincipalID: "user-guid-1", PrincipalType: "User" }]) },
    { name: "AzureAD_RoleDefinitions.json", content: table("AzureAD_RoleDefinitions", ["ObjectID", "TemplateID", "DisplayName", "Description", "IsBuiltIn"], [{ ObjectID: "rd-1", TemplateID: "62e90394-69f5-4237-9190-012177145e10", DisplayName: "Global Administrator", Description: "", IsBuiltIn: "True" }]) },
  ];

  it("builds cloud nodes and member_of/owns/role edges", () => {
    const c = new Campaign("ph", 1n);
    importFiles(c, azureTables(), ctx);
    const nodes = c.nodes();
    const alice = nodes.find((n) => n.label === "Alice")!;
    const group = nodes.find((n) => n.label === "Cloud Ops")!;
    const sp = nodes.find((n) => n.label === "backup-sp")!;
    const ga = nodes.find((n) => n.label === "Global Administrator")!;

    expect(alice.kind).toBe("cloud_identity");
    expect(alice.fields["upn"]).toBe("alice@corp.onmicrosoft.com");
    expect(sp.fields["service_principal"]).toBe(true);
    expect(ga.fields["is_tier_zero"]).toBe(true);

    const edges = c.edges();
    expect(edges.some((e) => e.kind === "member_of" && e.source === alice.id && e.target === group.id)).toBe(true);
    expect(edges.some((e) => e.kind === "owns" && e.source === alice.id && e.target === sp.id)).toBe(true);
    expect(edges.some((e) => e.kind === "member_of" && e.source === alice.id && e.target === ga.id)).toBe(true);
  });
});
