// A fully DOM-rendered, accessible dropdown (combobox + listbox). Unlike a native
// <select>, every part is real DOM we own and style, so it renders identically on
// every platform — including the Tauri WebKitGTK webview, which draws native form
// controls with the host GTK theme and ignores our dark brutalist CSS (the white
// dropdowns bug). Supports flat OR grouped (optgroup) options, a per-option /
// trigger swatch, value-colored trigger text, a placeholder, and a compact `sm`
// size. Keyboard: ↑/↓ (skipping disabled), Home/End, type-ahead, Enter/Space to
// choose, Esc/Tab to close. The open-state key handler runs on a WINDOW-capture
// listener so Escape closes the Select — not a surrounding ui/Dialog, which owns
// a document-capture Escape (window-capture fires first and stops propagation).

import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Icon } from "@/ui/Icon";

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
  swatch?: string; // color chip left of the label (and on the trigger when selected)
  color?: string; // colors the label text (and the trigger text when selected)
  hint?: string; // muted trailing text, e.g. " · host_windows"
}
export interface SelectGroup {
  label: string;
  options: SelectOption[];
}

const cn = (...xs: (string | false | undefined)[]) => xs.filter(Boolean).join(" ");
const isGrouped = (o: SelectOption[] | SelectGroup[]): o is SelectGroup[] =>
  o.length > 0 && "options" in o[0]!;

export function Select({
  value,
  onChange,
  options,
  placeholder,
  disabled,
  ariaLabel,
  id,
  className,
  size,
  triggerSwatch,
  triggerColor,
}: {
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[] | SelectGroup[];
  placeholder?: string;
  disabled?: boolean;
  ariaLabel?: string;
  id?: string;
  className?: string;
  size?: "sm" | "md";
  triggerSwatch?: string;
  triggerColor?: string;
}) {
  const groups: SelectGroup[] = isGrouped(options)
    ? options
    : [{ label: "", options }];

  const flat: SelectOption[] = groups.flatMap((g) => g.options);
  const rows: Array<{ head: string } | { opt: SelectOption; i: number }> = [];
  {
    let i = 0;
    for (const g of groups) {
      if (g.label) rows.push({ head: g.label });
      for (const o of g.options) rows.push({ opt: o, i: i++ });
    }
  }

  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const [pos, setPos] = useState({ left: 0, top: 0, minWidth: 0 });
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const typeBuf = useRef("");
  const typeAt = useRef(0);
  const listId = useId();
  const optId = (i: number) => `${listId}-o${i}`;

  const selected = flat.find((o) => o.value === value);

  const firstEnabled = () => flat.findIndex((o) => !o.disabled);
  const lastEnabled = () => {
    for (let i = flat.length - 1; i >= 0; i--) if (!flat[i]!.disabled) return i;
    return -1;
  };

  const move = (from: number, dir: 1 | -1): number => {
    let i = from < 0 ? (dir === 1 ? -1 : flat.length) : from;
    i += dir;
    while (i >= 0 && i < flat.length) {
      if (!flat[i]!.disabled) return i;
      i += dir;
    }
    return from < 0 ? (dir === 1 ? firstEnabled() : lastEnabled()) : from;
  };

  const openMenu = () => {
    if (disabled) return;
    const i = flat.findIndex((o) => o.value === value && !o.disabled);
    setActive(i >= 0 ? i : firstEnabled());
    setOpen(true);
  };
  const close = (refocus = true) => {
    setOpen(false);
    if (refocus) triggerRef.current?.focus();
  };
  const choose = (i: number) => {
    const o = flat[i];
    if (!o || o.disabled) return;
    onChange(o.value);
    close();
  };

  const typeahead = (ch: string) => {
    const now = Date.now();
    typeBuf.current = (now - typeAt.current < 600 ? typeBuf.current : "") + ch.toLowerCase();
    typeAt.current = now;
    const buf = typeBuf.current;
    const n = flat.length;
    if (!n) return;
    for (let k = 1; k <= n; k++) {
      const idx = (active + k + n) % n;
      const o = flat[idx]!;
      if (!o.disabled && o.label.toLowerCase().startsWith(buf)) {
        setActive(idx);
        setOpen(true);
        return;
      }
    }
  };

  const keyHandler = useRef<(e: KeyboardEvent) => void>(() => {});
  keyHandler.current = (e: KeyboardEvent) => {
    switch (e.key) {
      case "ArrowDown": e.preventDefault(); e.stopPropagation(); setActive((a) => move(a, 1)); break;
      case "ArrowUp": e.preventDefault(); e.stopPropagation(); setActive((a) => move(a, -1)); break;
      case "Home": e.preventDefault(); e.stopPropagation(); setActive(firstEnabled()); break;
      case "End": e.preventDefault(); e.stopPropagation(); setActive(lastEnabled()); break;
      case "Enter": e.preventDefault(); e.stopPropagation(); if (active >= 0) choose(active); break;
      case " ":
      case "Spacebar": e.preventDefault(); e.stopPropagation(); if (active >= 0) choose(active); break;
      case "Escape":
        e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); close();
        break;
      case "Tab": close(false); break; // let it propagate so focus moves (Dialog trap handles boundaries)
      default:
        if (e.key.length === 1 && !e.metaKey && !e.ctrlKey && !e.altKey) {
          e.stopPropagation();
          typeahead(e.key);
        }
    }
  };
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => keyHandler.current(e);
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [open]);


  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!triggerRef.current?.contains(t) && !listRef.current?.contains(t)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown, true);
    return () => document.removeEventListener("mousedown", onDown, true);
  }, [open]);

  useLayoutEffect(() => {
    if (!open) return;
    const tr = triggerRef.current?.getBoundingClientRect();
    if (!tr) return;
    const lr = listRef.current?.getBoundingClientRect();
    const h = lr?.height ?? 0;
    const w = lr?.width ?? tr.width;
    let top = tr.bottom + 2;
    if (top + h > window.innerHeight - 8 && tr.top - h - 2 > 8) top = tr.top - h - 2;
    const left = Math.max(8, Math.min(tr.left, window.innerWidth - w - 8));
    setPos({ left, top: Math.max(8, top), minWidth: tr.width });
  }, [open]);

  useEffect(() => {
    if (!open || active < 0) return;
    const el = document.getElementById(optId(active));
    if (el && typeof el.scrollIntoView === "function") {
      try { el.scrollIntoView({ block: "nearest" }); } catch { /* jsdom */ }
    }
  }, [open, active]);

  const swatch = triggerSwatch ?? selected?.swatch;
  const valColor = triggerColor ?? selected?.color;

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        id={id}
        className={cn("selecttrigger", size === "sm" && "sm", className)}
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-activedescendant={open && active >= 0 ? optId(active) : undefined}
        aria-label={ariaLabel}
        aria-disabled={disabled || undefined}
        disabled={disabled}
        onClick={() => (open ? close() : openMenu())}
        onKeyDown={(e) => {
          if (disabled || open) return;
          if (["ArrowDown", "ArrowUp", "Enter", " ", "Spacebar"].includes(e.key)) {
            e.preventDefault();
            openMenu();
          } else if (e.key.length === 1 && !e.metaKey && !e.ctrlKey && !e.altKey) {
            e.preventDefault();
            openMenu();
            typeahead(e.key);
          }
        }}
      >
        {swatch && <span className="selectswatch" style={{ background: swatch }} />}
        <span className="selectval" style={valColor ? { color: valColor } : undefined}>
          {selected ? selected.label : <span className="selectph">{placeholder ?? ""}</span>}
        </span>
        <Icon name="chevron-down" size={size === "sm" ? 12 : 14} className="selectcaret" />
      </button>
      {open &&
        createPortal(
          <ul
            ref={listRef}
            id={listId}
            role="listbox"
            aria-label={ariaLabel}
            tabIndex={-1}
            className={cn("selectmenu", size === "sm" && "sm")}
            style={{ left: pos.left, top: pos.top, minWidth: pos.minWidth }}
          >
            {rows.map((r, k) =>
              "head" in r ? (
                <li key={"h" + k} role="presentation" className="selecthead">{r.head}</li>
              ) : (
                <li
                  key={r.opt.value || "o" + r.i}
                  id={optId(r.i)}
                  role="option"
                  aria-selected={r.opt.value === value}
                  aria-disabled={r.opt.disabled || undefined}
                  className={cn("selectopt", r.i === active && "active", r.opt.disabled && "disabled")}
                  onMouseEnter={() => !r.opt.disabled && setActive(r.i)}
                  onMouseDown={(e) => { e.preventDefault(); choose(r.i); }}
                >
                  {r.opt.swatch && <span className="selectswatch" style={{ background: r.opt.swatch }} />}
                  <span className="selectoptlabel" style={r.opt.color ? { color: r.opt.color } : undefined}>
                    {r.opt.label}
                  </span>
                  {r.opt.hint && <span className="selecthint">{r.opt.hint}</span>}
                </li>
              ),
            )}
          </ul>,
          document.body,
        )}
    </>
  );
}
