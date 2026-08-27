// A context menu: a flat list of actions rendered inside a Popover. Each action
// may carry a leading line-icon or a color dot, and items can be grouped with
// separators or flagged `danger`. This is the single implementation behind every
// right-click / kebab menu in the app, so they look and behave identically —
// icons, arrow-key navigation, viewport clamping, focus trap, Escape to close.

import { Popover } from "@/ui/Popover";
import { Icon, type IconName } from "@/ui/Icon";

export type MenuAction =
  | { label: string; icon?: IconName; dot?: string; danger?: boolean; run: () => void }
  | { separator: true };

/** Move focus between sibling `.mitem` buttons with the up/down arrow keys.
 *  Attach to the keydown of any element wrapping a list of menu buttons. */
export function menuArrowKeys(e: React.KeyboardEvent<HTMLElement>): void {
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  e.preventDefault();
  const items = Array.from(e.currentTarget.querySelectorAll<HTMLButtonElement>("button.mitem"));
  const i = items.indexOf(document.activeElement as HTMLButtonElement);
  const next = e.key === "ArrowDown" ? i + 1 : i - 1;
  items[(next + items.length) % items.length]?.focus();
}

export function Menu({
  x,
  y,
  actions,
  onClose,
  label,
}: {
  x: number;
  y: number;
  actions: MenuAction[];
  onClose: () => void;
  label: string;
}) {
  return (
    <Popover x={x} y={y} onClose={onClose} label={label} className="navmenu">
      <ul className="menu" onKeyDown={menuArrowKeys}>
        {actions.map((action, i) =>
          "separator" in action ? (
            <li key={i} className="msep" aria-hidden />
          ) : (
            <li key={i}>
              <button
                type="button"
                role="menuitem"
                className={"mitem" + (action.danger ? " danger" : "")}
                onClick={() => {
                  action.run();
                  onClose();
                }}
              >
                {action.icon && <Icon name={action.icon} size={14} />}
                {action.dot && <span className="dot" style={{ background: action.dot }} />}
                <span>{action.label}</span>
              </button>
            </li>
          ),
        )}
      </ul>
    </Popover>
  );
}
