// A labelled form control with description + error wiring. Generates ids and
// passes aria-describedby/aria-invalid to the control via render-prop, so every
// new form is screen-reader-correct without repeating the boilerplate.

import { useId, type ReactNode } from "react";

export function Field({
  label,
  description,
  error,
  children,
  className,
}: {
  label: string;
  description?: string;
  error?: string | null;
  children: (ids: { id: string; describedBy?: string; invalid: boolean }) => ReactNode;
  className?: string;
}) {
  const id = useId();
  const descId = useId();
  const errId = useId();
  const describedBy = [description ? descId : "", error ? errId : ""].filter(Boolean).join(" ") || undefined;
  return (
    <div className={"uifield" + (className ? " " + className : "")}>
      <label className="uilabel" htmlFor={id}>{label}</label>
      {children({ id, describedBy, invalid: !!error })}
      {description && <span id={descId} className="uidesc">{description}</span>}
      {error && <span id={errId} className="uierr">{error}</span>}
    </div>
  );
}
