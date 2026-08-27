// One coherent monochrome line-glyph set for the application chrome — the HUD,
// toolbars, dashboard, panels. These are ACTION icons (distinct from the per-
// node-kind glyphs in `icons.ts`): drawn on a 24×24 grid with a uniform stroke,
// `fill: none`, and `stroke: currentColor` so they inherit the text color and
// stay legible at any contrast (brutalist: no emoji, no chromatic chrome). Size
// via the `size` prop or CSS font-size; color follows the surrounding text.

export type IconName =
  | "plus" | "link" | "fit" | "focus"
  | "import" | "export" | "theme" | "report" | "search"
  | "send" | "star" | "close" | "chevron-left" | "chevron-right"
  | "chevron-down" | "eye" | "eye-off" | "filter" | "trash" | "clone"
  | "team" | "chat" | "power" | "node" | "edge"
  | "alert" | "key" | "path" | "tag" | "folder" | "arrange";

// Inner SVG markup per icon (paths/shapes), 24×24 viewBox, stroked not filled.
const PATHS: Record<IconName, string> = {
  plus: "<path d='M12 5v14M5 12h14'/>",
  node: "<rect x='4.5' y='4.5' width='15' height='15' rx='2'/>",
  edge: "<circle cx='6' cy='12' r='2.4'/><circle cx='18' cy='12' r='2.4'/><path d='M8.4 12h7.2'/><path d='M14.4 9.6 16.8 12l-2.4 2.4'/>",
  link: "<path d='M9.5 14.5l5-5'/><path d='M8 11l-2.2 2.2a3.1 3.1 0 004.4 4.4L12.4 15.4'/><path d='M16 13l2.2-2.2a3.1 3.1 0 00-4.4-4.4L11.6 8.6'/>",
  fit: "<path d='M4 9V5.5A1.5 1.5 0 015.5 4H9'/><path d='M20 9V5.5A1.5 1.5 0 0018.5 4H15'/><path d='M4 15v3.5A1.5 1.5 0 005.5 20H9'/><path d='M20 15v3.5A1.5 1.5 0 0118.5 20H15'/>",
  focus: "<circle cx='12' cy='12' r='4'/><path d='M12 2v3M12 19v3M2 12h3M19 12h3'/>",
  import: "<path d='M12 3v10'/><path d='M8 9l4 4 4-4'/><path d='M4 17v2a1 1 0 001 1h14a1 1 0 001-1v-2'/>",
  export: "<path d='M12 14V4'/><path d='M8 8l4-4 4 4'/><path d='M4 17v2a1 1 0 001 1h14a1 1 0 001-1v-2'/>",
  theme: "<circle cx='12' cy='12' r='8.6'/><path d='M12 3.4v17.2'/><path d='M12 3.4a8.6 8.6 0 010 17.2z' fill='currentColor' stroke='none'/>",
  report: "<path d='M6 3.5h8L18.5 8v12.5a0 0 0 010 0H6z' /><path d='M14 3.5V8h4.5'/><path d='M8.5 12h7M8.5 15.5h7M8.5 18h4'/>",
  search: "<circle cx='10.5' cy='10.5' r='6.5'/><path d='M15.5 15.5L21 21'/>",
  send: "<path d='M4 12l16-7-7 16-2.5-6.5z'/><path d='M10.5 14.5L20 5'/>",
  star: "<path d='M12 3.6l2.6 5.3 5.8.85-4.2 4.1 1 5.78L12 17l-5.2 2.73 1-5.78-4.2-4.1 5.8-.85z'/>",
  close: "<path d='M6 6l12 12M18 6L6 18'/>",
  "chevron-left": "<path d='M15 5l-7 7 7 7'/>",
  "chevron-right": "<path d='M9 5l7 7-7 7'/>",
  "chevron-down": "<path d='M5 9l7 7 7-7'/>",
  eye: "<path d='M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z'/><circle cx='12' cy='12' r='2.8'/>",
  "eye-off": "<path d='M4 4l16 16'/><path d='M9.5 5.9A9.6 9.6 0 0112 5.5c6 0 9.5 6.5 9.5 6.5a16 16 0 01-2.8 3.3'/><path d='M6.2 7.7A16 16 0 002.5 12S6 18.5 12 18.5a9.3 9.3 0 003-.5'/><path d='M9.9 9.9a2.8 2.8 0 003.9 3.9'/>",
  filter: "<path d='M4 5h16l-6 7v6l-4 2v-8z'/>",
  trash: "<path d='M4 6.5h16'/><path d='M9 6.5V4.5h6v2'/><path d='M6.5 6.5l1 13h9l1-13'/><path d='M10 10v6M14 10v6'/>",
  clone: "<rect x='8' y='8' width='12' height='12' rx='1.6'/><path d='M16 8V5.5A1.5 1.5 0 0014.5 4H5.5A1.5 1.5 0 004 5.5v9A1.5 1.5 0 005.5 16H8'/>",
  team: "<circle cx='9' cy='9.4' r='3'/><path d='M3.5 19c0-3.2 2.6-5 5.5-5s5.5 1.8 5.5 5'/><circle cx='16.5' cy='8' r='2.6'/><path d='M14 19c0-2.9 2.3-4.4 4.5-4.4 1 0 1.8.3 2.5.7'/>",
  chat: "<path d='M4 5.5h16a1 1 0 011 1v8a1 1 0 01-1 1H9l-4 3.5V15.5H4a1 1 0 01-1-1v-8a1 1 0 011-1z'/><path d='M7.5 9.5h9M7.5 12.5h6'/>",
  power: "<path d='M12 3v9'/><path d='M7.5 6.3a8 8 0 109 0'/>",
  alert: "<path d='M12 3.5l9.5 16.5H2.5z'/><path d='M12 10v4.5M12 17.4h.01'/>",
  key: "<circle cx='8' cy='12' r='3.5'/><path d='M11.5 12H21'/><path d='M17.5 12v3M20.5 12v3'/>",
  path: "<circle cx='5.5' cy='6' r='2'/><circle cx='18.5' cy='18' r='2'/><circle cx='12' cy='12' r='2'/><path d='M7 7.4l3.6 3.2M13.4 13.4l3.7 3.4'/>",
  tag: "<path d='M3.6 12.6l7.8-7.8a1.5 1.5 0 011.06-.44H19a1.5 1.5 0 011.5 1.5v6.58a1.5 1.5 0 01-.44 1.06l-7.8 7.8a1.5 1.5 0 01-2.12 0L3.6 14.72a1.5 1.5 0 010-2.12z'/><circle cx='16' cy='8' r='1.4'/>",
  folder: "<path d='M3.5 6.5a1 1 0 011-1h4l2 2h8.5a1 1 0 011 1v8.5a1 1 0 01-1 1h-15a1 1 0 01-1-1z'/>",
  arrange: "<circle cx='7' cy='7' r='2'/><circle cx='17' cy='7' r='2'/><circle cx='7' cy='17' r='2'/><circle cx='17' cy='17' r='2'/><path d='M9 7h6M9 17h6M7 9v6M17 9v6'/>",
};

export function Icon({
  name,
  size = 16,
  className,
  title,
}: {
  name: IconName;
  size?: number;
  className?: string;
  title?: string;
}) {
  return (
    <svg
      className={className ? `icon ${className}` : "icon"}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={title ? undefined : true}
      role={title ? "img" : undefined}
      focusable="false"
      dangerouslySetInnerHTML={{ __html: (title ? `<title>${title}</title>` : "") + PATHS[name] }}
    />
  );
}
