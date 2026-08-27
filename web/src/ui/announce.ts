let message = "";
const listeners = new Set<() => void>();

export function announce(text: string): void {
  message = message === text ? text + " " : text;
  for (const l of listeners) l();
}

export function subscribeAnnounce(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function getAnnouncement(): string {
  return message;
}
