// An accessible popover anchored at a screen position (context menus, pickers).
// Dismisses on Escape, outside-click, or blur out of the popover; focus-traps
// while open and restores focus on close. Positions are clamped to the viewport.

import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { focusable, trapTab } from "@/ui/focus";

export function Popover({
  x,
  y,
  onClose,
  children,
  label,
  className,
}: {
  x: number;
  y: number;
  onClose: () => void;
  children: ReactNode;
  label: string;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [pos, setPos] = useState({ left: x, top: y });

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const left = Math.min(x, window.innerWidth - r.width - 8);
    const top = Math.min(y, window.innerHeight - r.height - 8);
    setPos({ left: Math.max(8, left), top: Math.max(8, top) });
  }, [x, y]);

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    focusable(ref.current!)[0]?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      } else if (ref.current) {
        trapTab(ref.current, e);
      }
    };
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("mousedown", onDown, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("mousedown", onDown, true);
      opener?.focus?.();
    };
  }, [onClose]);

  return createPortal(
    <div
      ref={ref}
      className={"popover" + (className ? " " + className : "")}
      role="menu"
      aria-label={label}
      style={{ left: pos.left, top: pos.top }}
    >
      {children}
    </div>,
    document.body,
  );
}
