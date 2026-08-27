// The team roster — the management surface for who can open the campaign file.
// Reads the in-doc roster (the shared source of truth) and lets any member
// enroll a co-operator by pasting the `id sign wrap` line the operator shows on
// their dashboard, or revoke one (which also rotates the keys). Enrollment seals
// the campaign key to the new operator inside the file — hand them the `.camp`
// out of band and it opens for them; revocation re-keys so a removed operator
// keeps nothing readable from future saves.

import { useState } from "react";
import { useStore } from "@/state/store";
import type { OperatorRole } from "@/domain/types";

const roleLabel = (r: OperatorRole): string =>
  r === "lead" ? "lead" : r === "observer" || r === "auditor" ? "observer" : "operator";

export function TeamPanel() {
  const roster = useStore((s) => s.roster);
  const me = useStore((s) => s.me);
  const notice = useStore((s) => s.notice);
  const enrollOperator = useStore((s) => s.enrollOperator);
  const removeOperator = useStore((s) => s.removeOperator);
  const dismissNotice = useStore((s) => s.dismissNotice);

  const [open, setOpen] = useState(false);
  const [line, setLine] = useState("");
  const [confirm, setConfirm] = useState<string | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  const submit = (ev: React.SubmitEvent<HTMLFormElement>) => {
    ev.preventDefault();
    setParseError(null);
    const [opId, signB64, wrapB64, role] = line.trim().split(/\s+/);
    if (!opId || !signB64 || !wrapB64) {
      setParseError("Paste a line: operator-id  sign-key  wrap-key  [observer]");
      return;
    }
    enrollOperator({
      operatorId: opId,
      signingB64: signB64,
      wrappingB64: wrapB64,
      grantVault: role !== "observer",
      displayName: opId,
    });
    setLine("");
    setOpen(false);
  };

  return (
    <div className="team">
      <h2>Team</h2>
      {notice && (
        <div className="teamnotice">
          <span>{notice}</span>
          <button className="x" title="Dismiss" onClick={dismissNotice}>×</button>
        </div>
      )}
      <ul className="teamlist">
        {roster.length === 0 && <li className="muted">No roster yet.</li>}
        {roster.map((e) => {
          const self = e.operator_id === me?.operatorId;
          const revoked = e.status === "revoked";
          return (
            <li key={e.operator_id} className={revoked ? "revoked" : ""}>
              <span className="tname" title={e.operator_id}>
                {e.display_name}
                {self && <span className="muted"> * you</span>}
              </span>
              <span className={"trole r-" + roleLabel(e.role)}>{roleLabel(e.role)}</span>
              {revoked ? (
                <span className="badge revoked">revoked</span>
              ) : confirm === e.operator_id ? (
                <span className="trevoke">
                  <button className="tno" onClick={() => { removeOperator(e.operator_id); setConfirm(null); }}>
                    revoke + rotate
                  </button>
                  <button className="ghost" onClick={() => setConfirm(null)}>×</button>
                </span>
              ) : (
                !self && (
                  <button className="x" title="Revoke access (rotates the keys)" onClick={() => setConfirm(e.operator_id)}>×</button>
                )
              )}
            </li>
          );
        })}
      </ul>

      {open ? (
        <form className="teamadd" onSubmit={submit}>
          <div className="muted small">
            Paste the operator's line (from their dashboard “show keys”): <code>id sign wrap [observer]</code>
          </div>
          <textarea
            value={line}
            onChange={(e) => setLine(e.target.value)}
            placeholder="op_bob <sign_b64> <wrap_b64>"
            rows={2}
            autoFocus
          />
          {parseError && <p className="error">{parseError}</p>}
          <div className="teambtns">
            <button type="submit">Enroll</button>
            <button type="button" className="ghost" onClick={() => { setOpen(false); setParseError(null); }}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <button className="addcred" onClick={() => setOpen(true)}>+ add operator</button>
      )}
    </div>
  );
}
