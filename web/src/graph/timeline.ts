// Timeline scrubbing: the "as-of-T" projection of the campaign. Entities carry a
// provenance `first_seen`, so a single predicate gives every consumer (the map,
// the navigator, the report) the same historical view — what the network looked
// like at a chosen moment — without versioning each field. `null` means "now"
// (no filtering). `timeBounds` gives the scrubber its range from the event log.

/** Keep only the items that existed at or before `at` (by `provenance.first_seen`).
 * `at === null` is the live view — every item passes. */
export function asOf<T extends { provenance: { first_seen: number } }>(
  items: T[],
  at: number | null,
): T[] {
  if (at === null) return items;
  return items.filter((i) => i.provenance.first_seen <= at);
}

/** The timestamp span of an event list, or `null` when empty. Drives the
 * timeline scrubber's min/max bounds. */
export function timeBounds(events: { at: number }[]): { min: number; max: number } | null {
  if (events.length === 0) return null;
  let min = Infinity;
  let max = -Infinity;
  for (const e of events) {
    if (e.at < min) min = e.at;
    if (e.at > max) max = e.at;
  }
  return { min, max };
}
