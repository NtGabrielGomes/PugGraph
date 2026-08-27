// The credential vault - a view *of the graph*, grouped by validity so the
// loot that still works rises to the top. Secrets stay sealed under the campaign
// vault sub-key (observer/auditor roles see existence + validity, never the
// secret), are revealed in-place behind an explicit toggle, and are NEVER
// indexed by search. Each credential links to the principal it authenticates as
// and the host it came from (both click-to-jump), and its spray/where-valid
// record is an at-a-glance success/fail matrix.

import { useMemo, useState } from "react";
import { useStore } from "@/state/store";
import type { CredentialSource, CredentialType, GraphNode, ValidityState } from "@/domain/types";
import { Icon, Select } from "@/ui";

const TYPES: CredentialType[] = [
  "password_plaintext", "password_ntlm", "password_net_ntlmv2", "kerberos_ticket",
  "kerberos_key", "ssh_key", "api_key", "token", "cookie", "certificate",
];
const SOURCES: CredentialSource[] = [
  "dump", "spray", "phishing", "mitm", "service_exploit", "config_file", "memory_dump", "manual",
];
const VALIDITIES: ValidityState[] = ["unknown", "valid", "invalid", "expired", "rotated"];
// Validity ordering for the grouped view: still-good loot first.
const GROUP_ORDER: ValidityState[] = ["valid", "unknown", "invalid", "expired", "rotated"];

function NodePicker({ value, nodes, placeholder, onChange, size }: {
  value: string | undefined;
  nodes: GraphNode[];
  placeholder: string;
  onChange: (id: string | undefined) => void;
  size?: "sm" | "md";
}) {
  return (
    <Select
      size={size}
      value={value ?? ""}
      placeholder={placeholder}
      ariaLabel={placeholder}
      onChange={(v) => onChange(v || undefined)}
      options={nodes.map((n) => ({ value: n.id, label: n.label || n.id, hint: n.kind }))}
    />
  );
}

export function CredentialVault() {
  const credentials = useStore((s) => s.credentials);
  const nodes = useStore((s) => s.nodes);
  const vault = useStore((s) => s.vaultAvailable);
  const addCredential = useStore((s) => s.addCredential);
  const setValidity = useStore((s) => s.setCredentialValidity);
  const setLinks = useStore((s) => s.setCredentialLinks);
  const addTest = useStore((s) => s.addCredentialTest);
  const removeCredential = useStore((s) => s.removeCredential);
  const revealSecret = useStore((s) => s.revealSecret);
  const select = useStore((s) => s.select);

  const sortedNodes = useMemo(
    () => [...nodes].sort((a, b) => (a.label || a.id).localeCompare(b.label || b.id)),
    [nodes],
  );
  const principals = useMemo(
    () => sortedNodes.filter((n) => ["user_account", "computer_account", "service_account", "group"].includes(n.kind)),
    [sortedNodes],
  );
  const labelOf = (id: string) => nodes.find((n) => n.id === id)?.label ?? id;

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [username, setUsername] = useState("");
  const [domain, setDomain] = useState("");
  const [type, setType] = useState<CredentialType>("password_plaintext");
  const [source, setSource] = useState<CredentialSource>("dump");
  const [secret, setSecret] = useState("");
  const [belongsTo, setBelongsTo] = useState<string | undefined>(undefined);
  const [obtainedFrom, setObtainedFrom] = useState<string | undefined>(undefined);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [testFor, setTestFor] = useState<string | null>(null);
  const [testHost, setTestHost] = useState<string>("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return credentials;
    return credentials.filter((c) => {
      const hay = [
        c.username, c.domain, c.credential_type, c.source, c.validity,
        c.belongs_to ? labelOf(c.belongs_to) : "",
        c.obtained_from ? labelOf(c.obtained_from) : "",
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [credentials, query, nodes]);

  const groups = useMemo(
    () => GROUP_ORDER.map((v) => ({ validity: v, items: filtered.filter((c) => c.validity === v) })).filter((g) => g.items.length),
    [filtered],
  );

  const submit = (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!username.trim()) return;
    addCredential({
      username: username.trim(), domain: domain.trim(), credential_type: type, source, secret,
      belongs_to: belongsTo, obtained_from: obtainedFrom,
    });
    setUsername(""); setDomain(""); setSecret(""); setBelongsTo(undefined); setObtainedFrom(undefined);
    setOpen(false);
  };

  const reveal = (id: string) => setRevealed((r) => ({ ...r, [id]: revealSecret(id) ?? "(unavailable)" }));
  const hide = (id: string) => setRevealed((r) => { const n = { ...r }; delete n[id]; return n; });
  const submitTest = (id: string, succeeded: boolean) => {
    if (!testHost) return;
    addTest(id, testHost, succeeded);
    setTestFor(null); setTestHost("");
  };

  return (
    <div className="vault">
      <h2>Credentials {credentials.length > 0 && <span className="vaultn">{credentials.length}</span>}{vault ? "" : <span className="muted small"> * sealed (no vault for your role)</span>}</h2>
      {credentials.length > 3 && (
        <div className="vaultsearch">
          <Icon name="search" size={13} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="search user / host / source..." aria-label="Search credentials" />
        </div>
      )}

      {filtered.length === 0 && <p className="muted vaultempty">{credentials.length ? "No match." : "No credentials captured yet. Loot appears here, sealed under the team vault key."}</p>}

      {groups.map((g) => (
        <div className="credgroup" key={g.validity}>
          <div className="credgrouphead">
            <span className={`vdot v-${g.validity}`} />
            <span>{g.validity}</span>
            <span className="n">{g.items.length}</span>
          </div>
          <ul className="creds">
            {g.items.map((c) => (
              <li key={c.id}>
                <div className="credtop">
                  <strong>{c.username}{c.domain ? "@" + c.domain : ""}</strong>
                  <span className="ctype">{c.credential_type}</span>
                  <Select
                    size="sm"
                    ariaLabel="Validity"
                    value={c.validity}
                    onChange={(v) => setValidity(c.id, v as ValidityState)}
                    options={VALIDITIES.map((v) => ({ value: v, label: v }))}
                  />
                  <button className="x" title="Remove credential" aria-label="Remove credential" onClick={() => removeCredential(c.id)}><Icon name="trash" size={13} /></button>
                </div>
                <div className="credbot">
                  <span className="muted">{c.source}</span>
                  {c.secret_sealed ? (
                    vault ? (
                      revealed[c.id] !== undefined ? (
                        <>
                          <code className="secret">{revealed[c.id]}</code>
                          <button className="reveal" onClick={() => hide(c.id)} aria-label="Hide secret"><Icon name="eye-off" size={12} /></button>
                        </>
                      ) : (
                        <button className="reveal" onClick={() => reveal(c.id)}><Icon name="eye" size={12} /> reveal</button>
                      )
                    ) : (
                      <span className="muted">secret sealed</span>
                    )
                  ) : (
                    <span className="muted">no secret</span>
                  )}
                </div>
                {/* Links to the graph: click to jump to the principal / host. */}
                <div className="credjump">
                  {c.belongs_to && <button className="jchip" onClick={() => select(c.belongs_to!)} title="Go to the principal">{labelOf(c.belongs_to)}</button>}
                  {c.obtained_from && <button className="jchip from" onClick={() => select(c.obtained_from!)} title="Go to the source host">from {labelOf(c.obtained_from)}</button>}
                </div>
                {vault && (
                  <div className="credlinks">
                    <label><span>belongs to</span>
                      <NodePicker size="sm" value={c.belongs_to} nodes={principals} placeholder="- principal -" onChange={(v) => setLinks(c.id, v, c.obtained_from)} />
                    </label>
                    <label><span>from host</span>
                      <NodePicker size="sm" value={c.obtained_from} nodes={sortedNodes} placeholder="- host -" onChange={(v) => setLinks(c.id, c.belongs_to, v)} />
                    </label>
                  </div>
                )}
                {c.tested_against.length > 0 && (
                  <div className="credtests">
                    {c.tested_against.map((t, i) => (
                      <button key={i} className={"testchip " + (t.succeeded ? "ok" : "no")} onClick={() => select(t.host)} title={`${t.succeeded ? "valid" : "failed"} on ${labelOf(t.host)} - go to host`}>
                        {t.succeeded ? "✓" : "✕"} {labelOf(t.host)}
                      </button>
                    ))}
                  </div>
                )}
                {vault && (testFor === c.id ? (
                  <div className="addtest">
                    <NodePicker size="sm" value={testHost || undefined} nodes={sortedNodes} placeholder="- host -" onChange={(v) => setTestHost(v ?? "")} />
                    <button onClick={() => submitTest(c.id, true)} className="tok">valid</button>
                    <button onClick={() => submitTest(c.id, false)} className="tno">failed</button>
                    <button onClick={() => { setTestFor(null); setTestHost(""); }} aria-label="Cancel">x</button>
                  </div>
                ) : (
                  <button className="addtestbtn" onClick={() => setTestFor(c.id)}><Icon name="plus" size={11} /> test result</button>
                ))}
              </li>
            ))}
          </ul>
        </div>
      ))}

      {vault &&
        (open ? (
          <form className="credadd" onSubmit={submit}>
            <div className="subhead">Capture a credential</div>
            <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" required autoFocus />
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="domain (optional)" />
            <div className="credselects">
              <Select
                ariaLabel="Credential type"
                value={type}
                onChange={(v) => setType(v as CredentialType)}
                options={TYPES.map((t) => ({ value: t, label: t }))}
              />
              <Select
                ariaLabel="Source"
                value={source}
                onChange={(v) => setSource(v as CredentialSource)}
                options={SOURCES.map((t) => ({ value: t, label: t }))}
              />
            </div>
            <div className="credselects">
              <NodePicker value={belongsTo} nodes={principals} placeholder="belongs to (principal)" onChange={setBelongsTo} />
              <NodePicker value={obtainedFrom} nodes={sortedNodes} placeholder="obtained from (host)" onChange={setObtainedFrom} />
            </div>
            <input value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="secret (sealed under the vault key)" />
            <div className="credactions">
              <button type="submit">Save</button>
              <button type="button" onClick={() => setOpen(false)}>Cancel</button>
            </div>
          </form>
        ) : (
          <button className="addcred" onClick={() => setOpen(true)}><Icon name="plus" size={14} /> Capture credential</button>
        ))}
    </div>
  );
}
