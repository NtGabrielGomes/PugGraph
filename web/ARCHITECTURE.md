# Web client architecture

This client mirrors the Rust core's Loro‑CRDT schema exactly. The app is
local‑only: Session owns the document and auto‑saves the sealed sovereign
`.camp` file to the operator's folder — there is no relay or network transport.
The layering below keeps that mirror clean and makes new capability (containers,
features, derived views) cheap to add without growing the god‑objects.

## Layers (outer depends on inner, never the reverse)

```
domain/         pure types + catalog + field schema (no React, no CRDT)
   ▲
campaign/crdt/  Container<T> + Codec<T> — the storage primitive
campaign/       Campaign (document.ts) + Session — CRDT containers & local persistence
   ▲
data/           repositories (typed read) · mutations (the only writers) · derived (memoized hooks)
   ▲
state/          store.ts — session lifecycle + UI state + refresh orchestration only
   ▲
features/<x>/   feature slices: index.tsx · hooks.ts · mutations.ts · types.ts
graph/ viz/     pure algorithms + presentation helpers (unit‑testable, no React)
```

## The container primitive (implemented)

Every entity store is a top‑level Loro map keyed by id whose entries are child
maps. `campaign/crdt/Container.ts` captures that shape once:

- `MapContainer<T>` — `upsert / get / has / list / remove`, sorted, tolerant.
- `Codec<T>` — `{ id, write(entry, value), read(id, raw) }`, one per entity type
  in `campaign/crdt/codecs.ts`. A `read` returns `null` to skip malformed data,
  so a hostile/partial snapshot never throws a reader.

Adding a container is a declaration in `document.ts`:

```ts
private readonly findingStore = new MapContainer<Finding>(
  () => this.doc.getMap("findings"), findingCodec,
);
```

plus thin delegating methods. No copy‑pasted `childMap`/`JSON.stringify`/parse
loops. The two flat presentation containers (`theme`, `positions`) and the
append‑only `events` list stay bespoke — they aren't keyed entity stores.

**Rust parity:** containers the Rust core reasons over (`nodes`, `edges`,
`credentials`, `idindex`, `findings`, `loot`, …) must be mirrored in
`crates/crdt`. Web‑managed containers (`theme`, `roster`, `pathmarks`,
`positions`, `filters`, `templates`, `messages`, and the upcoming `collections`,
`claims`, `scope`, `tasks`, `objectives`, `views`) round‑trip in the snapshot and
the Rust core ignores them.

## Conventions for new work (target — migrate strangler‑style)

- **Repositories** (`data/repositories/`) wrap a `Campaign` for typed reads; no
  React. Components never import `Campaign` directly.
- **Mutations** (`data/mutations/`) are the only writers. A mutation writes the
  CRDT, appends a structured (targeted) event, and flushes — replacing ad‑hoc
  `mutate()` closures. One place defines how each change touches the document.
- **Derived hooks** (`data/derived/`) — `useGraphModel`, `useAttackPaths`,
  `useSearchIndex` — are memoized on a cheap `signature` and computed off the edit
  hot path (debounced), so a keystroke or a teammate's op never triggers Dijkstra
  synchronously. The map and the navigator share one `useGraphModel` instance.
- **Feature slices** (`features/<x>/`) own their view + local selectors + local
  mutations; they depend on `data/`, never reach across into other features.
- **No silent caps.** Any truncated list shows its true count + a "show more".

## Verification

`npm run typecheck && npm test && npm run build`. Pure modules in `graph/`,
`viz/`, `io/`, and the `Campaign` document are covered by `test/*`; keep them green
on every change. CRDT convergence/LWW/snapshot invariants live in
`test/campaign.test.ts` and `test/containers.test.ts` — never regress them.
