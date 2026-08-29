import { useEffect, useMemo, useRef, useState } from "react";
import { useStore } from "@/state/store";
import { announce, Icon } from "@/ui";
import { operatorHue } from "@/viz/viz";

const fmt = (at: number): string =>
  at ? new Date(at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
const tag = (name: string): string => name.replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "?";

type Item =
  | { t: "event"; key: string; at: number; author: string; action: string; summary: string }
  | { t: "msg"; key: string; at: number; author: string; body: string; ref?: string };

interface SlashCommand {
  cmd: string;
  args: string;
  desc: string;
}

const SLASH: SlashCommand[] = [
  { cmd: "/node", args: "<label> : <kind>", desc: "Create a node (e.g. /node DC01 : domain_controller)" },
  { cmd: "/edge", args: "<A> > <B> : <relation>", desc: "Create a relation (e.g. /edge WS01 > FS01 : admin_to)" },
  { cmd: "/compromise", args: "<label> <level>", desc: "Set a node's access level (unknown...domain_admin)" },
  { cmd: "/tag", args: "<label> <tag>", desc: "Tag a node (e.g. /tag DC01 crown-jewel)" },
  { cmd: "/find", args: "<query>", desc: "Filter the map. kind: compromise:>=admin tag: has:finding" },
  { cmd: "/clear", args: "", desc: "Clear the map filter" },
];

export function ActivityStream({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  const events = useStore((s) => s.events);
  const messages = useStore((s) => s.messages);
  const nodes = useStore((s) => s.nodes);
  const me = useStore((s) => s.me);
  const viewAsOf = useStore((s) => s.viewAsOf);
  const sendMessage = useStore((s) => s.sendMessage);
  const quickAdd = useStore((s) => s.quickAdd);
  const setFilterQuery = useStore((s) => s.setFilterQuery);
  const select = useStore((s) => s.select);
  const selectedId = useStore((s) => s.selectedId);

  const labelOf = useMemo(() => {
    const m = new Map(nodes.map((n) => [n.id, n.label || n.id]));
    return (id: string) => m.get(id) ?? id;
  }, [nodes]);

  const feed = useMemo<Item[]>(() => {
    const items: Item[] = [];
    events.forEach((e, i) => items.push({ t: "event", key: `e${i}`, at: e.at, author: e.author, action: e.action, summary: e.summary }));
    for (const m of messages) items.push({ t: "msg", key: m.id, at: m.at, author: m.author, body: m.body, ref: m.ref });
    items.sort((a, b) => a.at - b.at);
    return items.slice(-250);
  }, [events, messages]);

  const feedRef = useRef<HTMLOListElement | null>(null);
  const stick = useRef(true);
  useEffect(() => {
    const el = feedRef.current;
    if (el && stick.current)
      el.scrollTop = el.scrollHeight;
  });
  const onScroll = () => {
    const el = feedRef.current;
    if (el)
      stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
  };

  const lastSeen = useRef<string | null>(null);
  useEffect(() => {
    const last = messages[messages.length - 1];
    if (!last) return;
    if (lastSeen.current === null) {
      lastSeen.current = last.id;
      return;
    }
    if (last.id !== lastSeen.current && last.author !== me?.operatorId)
      announce(`${last.author}: ${last.body}`);

    lastSeen.current = last.id;
  }, [messages, me]);

  const [value, setValue] = useState("");
  const [status, setStatus] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const slashMode = value.startsWith("/") && !value.includes(" ");
  const matches = slashMode ? SLASH.filter((c) => c.cmd.startsWith(value.toLowerCase())) : [];
  useEffect(() => { if (active >= matches.length) setActive(0); }, [matches.length, active]);

  const runCommand = (raw: string): string => {
    const trimmed = raw.trim();
    const sp = trimmed.indexOf(" ");
    const cmd = (sp === -1 ? trimmed : trimmed.slice(0, sp)).toLowerCase();
    const rest = sp === -1 ? "" : trimmed.slice(sp + 1).trim();
    switch (cmd) {
      case "/node":
      case "/edge":
        return rest ? quickAdd(rest) : "give the command an argument";
      case "/compromise": {
        const m = rest.match(/^(.+)\s+(\w+)$/);
        return m ? quickAdd(`${m[1]!.trim()} ! ${m[2]}`) : "usage: /compromise <label> <level>";
      }
      case "/tag": {
        const m = rest.match(/^(.+)\s+(\S+)$/);
        return m ? quickAdd(`${m[1]!.trim()} # ${m[2]}`) : "usage: /tag <label> <tag>";
      }
      case "/find":
        setFilterQuery(rest);
        return rest ? `filtering: ${rest}` : "cleared filter";
      case "/clear":
        setFilterQuery("");
        return "cleared filter";
      default:
        return `unknown command ${cmd}. type / to see commands`;
    }
  };

  const submit = (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    const v = value.trim();
    if (!v) return;
    if (v.startsWith("/")) {
      if (slashMode && matches.length && !SLASH.some((c) => c.cmd === v)) {
        complete(matches[Math.min(active, matches.length - 1)]!);
        return;
      }
      setStatus(runCommand(v));
    } else {
      sendMessage(v, selectedId ?? undefined);
      setStatus("");
    }
    setValue("");
    setActive(0);
  };

  const complete = (c: SlashCommand) => {
    const next = c.args ? `${c.cmd} ` : c.cmd;
    setValue(next);
    setActive(0);
    inputRef.current?.focus();
    if (!c.args) {
      setStatus(runCommand(c.cmd));
      setValue("");
    }
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!slashMode || matches.length === 0)
        return;
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => (a + 1) % matches.length); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => (a - 1 + matches.length) % matches.length); }
    else if (e.key === "Tab") { e.preventDefault(); complete(matches[Math.min(active, matches.length - 1)]!); }
  };

  return (
    <section className={"activity" + (open ? "" : " collapsed")} aria-label="Team activity and chat">
      <div className="acthead">
        <button className="acttoggle" onClick={onToggle} aria-expanded={open} title={open ? "Collapse activity" : "Expand activity"}>
          <Icon name="chevron-down" size={14} className={open ? "" : "flip"} />
          <Icon name="chat" size={14} />
          <span className="lbl">Activity &amp; chat</span>
        </button>
      </div>

      {open && (
        <ol className="actfeed" ref={feedRef} onScroll={onScroll}>
          {feed.length === 0 && <li className="logempty">- no activity yet. the team's edits and messages appear here -</li>}
          {feed.map((it) => (
            <li
              key={it.key}
              className={
                "actline " + it.t + (viewAsOf !== null && it.at > viewAsOf ? " future" : "") +
                (it.t === "msg" && it.author === me?.operatorId ? " mine" : "")
              }
            >
              <span className="ltime">{fmt(it.at)}</span>
              <span className="lauthor" style={{ color: `hsl(${operatorHue(it.author)} 55% 64%)` }} title={it.author}>{tag(it.author)}</span>
              {it.t === "event" ? (
                <span className="lmain">
                  <span className="laction">{it.action}</span>
                  <span className="lsummary" title={it.summary}>{it.summary}</span>
                </span>
              ) : (
                <span className="lmain">
                  <span className="lbody">{it.body}</span>
                  {it.ref && (
                    <button className="refchip" onClick={() => select(it.ref!)} title="Go to the referenced node">{labelOf(it.ref)}</button>
                  )}
                </span>
              )}
            </li>
          ))}
        </ol>
      )}

      <form className="composer" onSubmit={submit}>
        <div className="composerwrap">
          {slashMode && matches.length > 0 && (
            <ul className="slashmenu" role="listbox" aria-label="Slash commands">
              {matches.map((c, i) => (
                <li
                  key={c.cmd}
                  role="option"
                  aria-selected={i === active}
                  className={"slashitem" + (i === active ? " active" : "")}
                  onMouseDown={(e) => { e.preventDefault(); complete(c); }}
                >
                  <code>{c.cmd}</code>
                  <span className="slashargs">{c.args}</span>
                  <span className="slashdesc">{c.desc}</span>
                </li>
              ))}
            </ul>
          )}
          <input
            ref={inputRef}
            value={value}
            onChange={(e) => { setValue(e.target.value); setStatus(""); }}
            onKeyDown={onKeyDown}
            placeholder="Message the team...   ( / for commands )"
            spellCheck={false}
            aria-label="Message the team or run a slash command"
          />
        </div>
        {status && <span className="actstatus" role="status">{status}</span>}
        <button type="submit" title={value.startsWith("/") ? "Run command" : "Send message"} aria-label="Send">
          <Icon name="send" size={15} />
        </button>
      </form>
    </section>
  );
}
