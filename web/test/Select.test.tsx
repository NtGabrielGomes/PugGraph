// @vitest-environment jsdom
// Component test for the custom ui/Select (combobox + listbox). The rest of the
// suite is pure-logic node-env; this is the one file that needs a DOM, so it
// opts into jsdom per-file (the global env stays "node"). No Testing Library —
// we drive React 18 directly with react-dom/client + act() and dispatch real DOM
// events, asserting on the ARIA contract (roles/attributes), keyboard model, and
// the Escape-doesn't-bubble-to-a-parent-Dialog guard.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { Select, type SelectGroup, type SelectOption } from "@/ui/Select";

// Tell React we're in an act() environment (silences the warning, enforces flush).
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

const render = (ui: React.ReactElement) => act(() => root.render(ui));
const trigger = () => container.querySelector('[role="combobox"]') as HTMLButtonElement;
const listbox = () => document.querySelector('[role="listbox"]') as HTMLUListElement | null;
const options = () => Array.from(document.querySelectorAll('[role="option"]')) as HTMLElement[];
const activeId = () => trigger().getAttribute("aria-activedescendant");

const key = (k: string, init: KeyboardEventInit = {}) =>
  act(() => {
    trigger().dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true, ...init }));
  });
const click = (el: Element) =>
  act(() => {
    el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
  });
const mousedown = (el: Element) =>
  act(() => {
    el.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true }));
  });

const ABC: SelectOption[] = [
  { value: "a", label: "Alpha" },
  { value: "b", label: "Bravo" },
  { value: "c", label: "Charlie" },
];

describe("Select", () => {
  it("renders a combobox trigger with the placeholder, then the selected label", () => {
    render(<Select value="" placeholder="Pick one" options={ABC} onChange={() => {}} ariaLabel="t" />);
    const t = trigger();
    expect(t.getAttribute("role")).toBe("combobox");
    expect(t.getAttribute("aria-haspopup")).toBe("listbox");
    expect(t.getAttribute("aria-expanded")).toBe("false");
    expect(t.textContent).toContain("Pick one");
    expect(listbox()).toBeNull();

    render(<Select value="b" options={ABC} onChange={() => {}} ariaLabel="t" />);
    expect(trigger().textContent).toContain("Bravo");
  });

  it("opens on click and exposes listbox/option roles with the current value selected", () => {
    render(<Select value="b" options={ABC} onChange={() => {}} ariaLabel="t" />);
    click(trigger());
    expect(trigger().getAttribute("aria-expanded")).toBe("true");
    expect(listbox()).not.toBeNull();
    const opts = options();
    expect(opts.map((o) => o.getAttribute("role"))).toEqual(["option", "option", "option"]);
    expect(opts[1]!.getAttribute("aria-selected")).toBe("true");
    expect(opts[0]!.getAttribute("aria-selected")).toBe("false");
  });

  it("ArrowDown/Up move the active option and skip disabled ones", () => {
    const opts = [{ value: "a", label: "A" }, { value: "b", label: "B", disabled: true }, { value: "c", label: "C" }];
    render(<Select value="a" options={opts} onChange={() => {}} ariaLabel="t" />);
    click(trigger()); // active = selected "a" (index 0)
    key("ArrowDown"); // skip disabled b (1) → c (2)
    expect(activeId()).toBe(options()[2]!.id);
    expect(options()[2]!.classList.contains("active")).toBe(true);
    key("ArrowUp"); // back to a (0)
    expect(activeId()).toBe(options()[0]!.id);
  });

  it("Home/End jump to the first/last enabled option", () => {
    render(<Select value="b" options={ABC} onChange={() => {}} ariaLabel="t" />);
    click(trigger());
    key("End");
    expect(activeId()).toBe(options()[2]!.id);
    key("Home");
    expect(activeId()).toBe(options()[0]!.id);
  });

  it("type-ahead moves the active option to the first label match", () => {
    render(<Select value="a" options={ABC} onChange={() => {}} ariaLabel="t" />);
    click(trigger());
    key("c");
    expect(activeId()).toBe(options()[2]!.id); // Charlie
  });

  it("Enter selects the active option, fires onChange, closes, and returns focus to the trigger", () => {
    const onChange = vi.fn();
    render(<Select value="a" options={ABC} onChange={onChange} ariaLabel="t" />);
    click(trigger());
    key("ArrowDown"); // a → b
    key("Enter");
    expect(onChange).toHaveBeenCalledWith("b");
    expect(trigger().getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(trigger());
  });

  it("clicking an option selects it and closes the listbox", () => {
    const onChange = vi.fn();
    render(<Select value="a" options={ABC} onChange={onChange} ariaLabel="t" />);
    click(trigger());
    mousedown(options()[2]!); // Charlie
    expect(onChange).toHaveBeenCalledWith("c");
    expect(listbox()).toBeNull();
  });

  it("Escape closes without selecting and does NOT reach a document-capture Escape (Dialog guard)", () => {
    const onChange = vi.fn();
    const docEsc = vi.fn();
    document.addEventListener("keydown", docEsc, true); // mimics ui/Dialog's capture-phase Escape
    try {
      render(<Select value="a" options={ABC} onChange={onChange} ariaLabel="t" />);
      click(trigger());
      key("Escape");
      expect(trigger().getAttribute("aria-expanded")).toBe("false");
      expect(onChange).not.toHaveBeenCalled();
      expect(docEsc).not.toHaveBeenCalled(); // window-capture handler stopped it first

      // When CLOSED, Escape must propagate (so a parent Dialog can close).
      key("Escape");
      expect(docEsc).toHaveBeenCalledTimes(1);
    } finally {
      document.removeEventListener("keydown", docEsc, true);
    }
  });

  it("does not select a disabled option on click", () => {
    const onChange = vi.fn();
    const opts = [{ value: "a", label: "A" }, { value: "b", label: "B", disabled: true }];
    render(<Select value="a" options={opts} onChange={onChange} ariaLabel="t" />);
    click(trigger());
    const disabled = options()[1]!;
    expect(disabled.getAttribute("aria-disabled")).toBe("true");
    mousedown(disabled);
    expect(onChange).not.toHaveBeenCalled();
    expect(listbox()).not.toBeNull(); // stays open
  });

  it("a disabled Select does not open", () => {
    const onChange = vi.fn();
    render(<Select value="a" disabled options={ABC} onChange={onChange} ariaLabel="t" />);
    expect(trigger().disabled).toBe(true);
    click(trigger());
    expect(listbox()).toBeNull();
  });

  it("renders grouped options with headers and navigates across group boundaries", () => {
    const groups: SelectGroup[] = [
      { label: "Group One", options: [{ value: "a", label: "A" }] },
      { label: "Group Two", options: [{ value: "b", label: "B" }] },
    ];
    render(<Select value="a" options={groups} onChange={() => {}} ariaLabel="t" />);
    click(trigger());
    const heads = Array.from(document.querySelectorAll(".selecthead")).map((e) => e.textContent);
    expect(heads).toEqual(["Group One", "Group Two"]);
    expect(options().length).toBe(2);
    key("ArrowDown"); // a (group 1) → b (group 2)
    expect(activeId()).toBe(options()[1]!.id);
  });

  it("action-select pattern: with value='' it still fires onChange and reverts to the placeholder", () => {
    const onChange = vi.fn();
    render(<Select value="" placeholder="Action..." options={ABC} onChange={onChange} ariaLabel="t" />);
    click(trigger());
    mousedown(options()[0]!);
    expect(onChange).toHaveBeenCalledWith("a");
    expect(trigger().textContent).toContain("Action..."); // value stayed "", so placeholder shows
  });
});
