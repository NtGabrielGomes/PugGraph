import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { focusable, trapTab } from "@/ui/focus";

export function Dialog({
  title,
  subtitle,
  onClose,
  children,
  className,
  initialFocus,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  className?: string;
  initialFocus?: string;
}) {
  const boxRef = useRef<HTMLDivElement | null>(null);
  const titleId = useId();
  const subId = useId();

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const box = boxRef.current;
    if (box) {
      const target = initialFocus ? box.querySelector<HTMLElement>(initialFocus) : focusable(box)[0];
      (target ?? box).focus();
    }
  
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      } else if (box) {
        trapTab(box, e);
      }
    };
  
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      opener?.focus?.();
    };
  }, [onClose, initialFocus]);

  return createPortal(
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div
        ref={boxRef}
        className={"modal" + (className ? " " + className : "")}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={subtitle ? subId : undefined}
        tabIndex={-1}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="modalhead">
          <h2 id={titleId}>{title}</h2>
          {subtitle && <p id={subId} className="modalsub">{subtitle}</p>}
        </div>
        {children}
      </div>
    </div>,
    document.body,
  );
}
