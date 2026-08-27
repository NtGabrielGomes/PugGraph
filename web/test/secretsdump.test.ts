// The NTDS.dit / secretsdump importer: the crown-jewel hash set lands as ONE
// folded collection with NT hashes sealed into the vault — zero graph nodes — and
// individual principals are promoted (with their sealed cred) only on demand.

import { describe, it, expect } from "vitest";
import { Campaign } from "@/campaign/document";
import { parseSecretsdump, applySecretsdump, detectFormat, importFiles } from "@/io/import";
import type { Provenance } from "@/domain/types";

const NTDS = [
  "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
  "CORP\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a59bd44fe5bec39c44c8cd3524deeab:::",
  "CORP\\svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::",
  "CORP\\WS01$:1105:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::",
  "CORP\\alice_history0:1106:aad3b435b51404eeaad3b435b51404ee:00000000000000000000000000000000:::",
  "garbage line that should be ignored",
].join("\n");

const ctx = (seal?: (p: string) => string) => ({ author: "op", now: 1000, seal });
const prov = (): Provenance => ({ author: "op", source: { kind: "import", tool: "secretsdump" }, confidence: "confirmed", first_seen: 1000, last_verified: 1000 });

describe("secretsdump / NTDS importer", () => {
  it("parses NTDS rows, skips history, flags machine + krbtgt, dedups", () => {
    const p = parseSecretsdump(NTDS);
    expect(p.domain).toBe("CORP");
    expect(p.accounts.map((a) => a.sam).sort()).toEqual(["Administrator", "WS01$", "krbtgt", "svc_sql"]);
    expect(p.accounts.find((a) => a.sam === "WS01$")!.is_machine).toBe(true);
    expect(p.accounts.find((a) => a.sam === "krbtgt")!.is_krbtgt).toBe(true);
  });

  it("detects the format from content", () => {
    expect(detectFormat("dump.txt", NTDS)).toBe("secretsdump");
  });

  it("folds the whole dump into one collection with sealed hashes — zero graph nodes", () => {
    const c = new Campaign("camp", 1n);
    const summary = applySecretsdump(c, parseSecretsdump(NTDS), ctx((p) => `SEALED(${p})`));
    expect(c.nodes()).toHaveLength(0);
    expect(summary.credentials).toBe(4);
    const coll = c.collections()[0]!;
    expect(coll.count).toBe(4);
    expect(coll.stats).toMatchObject({ total: 4, machines: 1, krbtgt: 1 });
    const krbtgt = c.collectionMember("coll:secretsdump:corp", "corp\\krbtgt")!;
    expect(krbtgt.tags).toContain("golden-ticket");
    expect(krbtgt.sealed_secrets![0]!.sealed).toBe("SEALED(1a59bd44fe5bec39c44c8cd3524deeab)");
  });

  it("promotes a principal on demand, lifting its sealed hash into the vault", () => {
    const c = new Campaign("camp", 1n);
    applySecretsdump(c, parseSecretsdump(NTDS), ctx((p) => `SEALED(${p})`));
    const id = c.promoteMember("coll:secretsdump:corp", "corp\\svc_sql", prov())!;
    expect(c.nodes().map((n) => n.id)).toEqual([id]);
    const cred = c.credentials()[0]!;
    expect(cred.belongs_to).toBe(id);
    expect(cred.credential_type).toBe("password_ntlm");
    expect(cred.secret_sealed).toBe("SEALED(5835048ce94ad0564e29a924a03510ef)");
  });

  it("records existence without a secret when no vault is held", () => {
    const c = new Campaign("camp", 1n);
    applySecretsdump(c, parseSecretsdump(NTDS), ctx(undefined));
    const m = c.collectionMember("coll:secretsdump:corp", "corp\\svc_sql")!;
    expect(m.sealed_secrets![0]!.sealed).toBeUndefined();
  });

  it("routes through importFiles end-to-end", () => {
    const c = new Campaign("camp", 1n);
    importFiles(c, [{ name: "ntds.txt", content: NTDS }], ctx((p) => `S(${p})`));
    expect(c.nodes()).toHaveLength(0);
    expect(c.collections()[0]!.count).toBe(4);
  });
});
