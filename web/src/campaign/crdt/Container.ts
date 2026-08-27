// The generic CRDT container abstraction. Every entity store in the campaign
// document is a top-level Loro map keyed by id, whose entries are child maps with
// the same shape of work: get-or-create the entry, write its fields (primitives
// direct, complex values JSON-encoded), and read it back tolerantly. Capturing
// that once here means a new container (findings, loot, collections, claims,
// tasks, …) is just a `Codec<T>` + one line in `document.ts`, not 50 lines of
// copy‑pasted `childMap`/`JSON.stringify`/parse loops.

import { LoroMap, LoroList } from "loro-crdt";

export type JsonObj = Record<string, unknown>;

/** Get‑or‑create a child `LoroMap` under a parent map key (idempotent). */
export function childMap(parent: LoroMap, key: string): LoroMap {
  const existing = parent.get(key);
  if (existing instanceof LoroMap) return existing;
  return parent.setContainer(key, new LoroMap());
}

/** Get‑or‑create a child `LoroList` under a parent map key (idempotent). */
export function childList(parent: LoroMap, key: string): LoroList {
  const existing = parent.get(key);
  if (existing instanceof LoroList) return existing;
  return parent.setContainer(key, new LoroList());
}

/** Turns a domain value into CRDT writes and back. `write` receives the entry's
 * (already‑created) child map; `read` parses one raw JSON entry, returning `null`
 * to skip malformed data (so hostile/partial state never throws a reader). */
export interface Codec<T> {
  id(value: T): string;
  write(entry: LoroMap, value: T): void;
  read(id: string, raw: JsonObj): T | null;
}

/** A keyed top‑level container (`LoroMap` of id → entry map) with a uniform
 * upsert / get / list / remove. `root` is a thunk so it resolves the live Loro
 * container handle on each call, exactly like the hand‑written methods did. */
export class MapContainer<T> {
  private readonly compare: (a: T, b: T) => number;

  constructor(
    private readonly root: () => LoroMap,
    private readonly codec: Codec<T>,
    compare?: (a: T, b: T) => number,
  ) {
    this.compare = compare ?? ((a, b) => this.codec.id(a).localeCompare(this.codec.id(b)));
  }

  /** The (created‑on‑demand) entry map for an id — for partial field mutators. */
  entry(id: string): LoroMap {
    return childMap(this.root(), id);
  }

  upsert(value: T): void {
    this.codec.write(this.entry(this.codec.id(value)), value);
  }

  get(id: string): T | null {
    const raw = this.root().get(id);
    return raw instanceof LoroMap ? this.codec.read(id, raw.toJSON() as JsonObj) : null;
  }

  has(id: string): boolean {
    return this.root().get(id) instanceof LoroMap;
  }

  list(): T[] {
    const json = (this.root().toJSON() ?? {}) as JsonObj;
    const out: T[] = [];
    for (const [id, v] of Object.entries(json)) {
      if (v && typeof v === "object") {
        const parsed = this.codec.read(id, v as JsonObj);
        if (parsed) out.push(parsed);
      }
    }
    return out.sort(this.compare);
  }

  remove(id: string): void {
    this.root().delete(id);
  }
}
