# Campaign Knowledge platform — Core (Rust)

The local-first core of the campaign knowledge platform.

This workspace implements the convergent domain model, the end-to-end encryption
layer with the sovereign campaign-file format, and the scanner import pipeline.
There is no server component: campaigns live as local encrypted files. A
React/TypeScript desktop client (`web/`) shares the same Loro CRDT (via WASM)
and is proven byte-compatible with this core on the campaign-file crypto.
**Everything compiles and is covered by tests.**

```
$ cargo test --workspace        # 43 Rust tests: domain 15, crypto 8, crdt 7, import 13
$ cargo build --release         # builds the core crates (libraries)
$ bash scripts/interop.sh       # Rust<->Node E2E crypto interop (both directions)
$ cd web && npm test            # 86 frontend tests / 17 files (campaign, edge fields, queries, paths, crypto)
$ cd web && npm run typecheck    # tsc --noEmit, clean
$ cd web && npm run build        # production bundle (Vite + Loro WASM)
```

## Why Rust (the decision that drove the stack)

The hard part of this system is **a correct graph CRDT and correct E2E crypto,
identical in the core and in the desktop client.** Rust wins because
[Loro](https://loro.dev) is Rust-native, so the *same* convergence engine runs
here and (via WASM) in the client; because the RustCrypto ecosystem is
first-rate; and because memory-safe parsing is the right posture for a tool
that ingests hostile scanner output.
Full reasoning and the alternatives weighed (Go, Elixir, Automerge) are in the
plan, §2.

## Crate layout

| Crate | Role | Key tests |
|---|---|---|
| `domain` | Typed property-graph domain model (no I/O, no crypto). Node/edge taxonomy, credentials with validity states, identity keys, provenance envelope. | enum/serde round-trips, severity ordering |
| `crypto` | E2E primitives + the sovereign campaign-file format. XChaCha20-Poly1305 AEAD, Ed25519 signing, X25519/HKDF ECIES key-wrap, Argon2id KDF. | `full_campaign_file_flow_with_role_limited_vault`, tamper/wrong-key/wrong-recipient |
| `crdt` | The campaign document: domain graph mapped onto Loro. Reconciliation index, hash-chained events, snapshot/update export+import. | `replicas_converge_after_exchange` (80-case proptest), reconciliation, concurrent-field agreement |
| `import` | Scanner import pipeline (phase 3). Nmap XML → reconciled hosts + service nodes + `LISTENS_ON` edges. | parse, apply+reconciliation (re-import dedups), malformed→error, hostile-input-no-panic |

## How the architecture is realized (plan → code)

- **Property graph where attack paths emerge from structure** → `domain`
  closed `NodeKind`/`EdgeKind` taxonomies; `EdgeKind::is_traversable()` and
  `NodeKind::is_high_value()` give pathfinding its semantics.
- **Low-friction capture / automatic dedup** → `CampaignDoc::resolve_or_create`
  collapses the same host seen by Nmap (IP) and BloodHound (SID) onto one node
  via the identity-key index (`identity_reconciliation_collapses_observations`).
- **Concurrent collaboration converges with no lost data** → the whole campaign
  is one Loro document (`crdt`); the 80-case property test asserts two
  replicas reach byte-identical state after exchanging updates in any order.
- **Campaign = one sovereign encrypted file** → `crypto::file::CampaignFile`:
  `"CAMP" | ver | header(JSON) | sealed-snapshot`. The snapshot is the Loro
  document sealed under the campaign key; the header carries per-operator
  wrapped keys. Seizing the file yields only ciphertext.
- **Role-limited secrecy under E2E** → a separate credential **vault sub-key** is
  wrapped only for privileged operators; observers get the campaign key (read
  the graph) but not the vault (`full_campaign_file_flow_with_role_limited_vault`).
- **Tamper-evident authorship/audit** → every update is Ed25519-signed; the event
  timeline is a SHA-256 hash chain (`event_chain_links_and_verifies`,
  `CampaignDoc::verify_event_chain`).

## Security properties, demonstrated by tests (not asserted by prose)

- Confidentiality at rest: `open_content` fails for wrong key/AAD; the campaign
  file is ciphertext-only at rest by construction.
- Integrity/tamper-evidence: flipping one ciphertext byte → AEAD `Decrypt`
  error; forging an update signature → verify returns false.
- Forward-secret key wrap: ephemeral X25519 per envelope; wrong recipient cannot
  unwrap.

## Frontend (`web/`) — built and tested

The React/TypeScript client mirrors the Rust schema and runs the **same Loro
CRDT** (via WASM), so the campaign-document semantics are identical to the
core. It runs only inside the native desktop shell (there is no standalone
browser build); it typechecks, unit-tests, and builds. `src/` is a layered + feature
tree with stable `@/` (= `src/`) absolute imports:

- `@/domain` — types, the node/edge catalog, the per-kind field schema.
- `@/crypto` — `primitives` (libsodium sumo, **proven interoperable** with
  `crypto` by `scripts/interop.sh`), `identity`, social `recovery`.
- `@/campaign` — `document` (the Loro campaign doc + identity reconciliation),
  `session` (recovers the operator's keys, signs updates, and **auto-saves the
  sovereign `.camp` back to the operator's folder**), `persistence`, `seed`.
- `@/graph` (attack-path Dijkstra, view model, query, search, timeline, topology),
  `@/viz` (semantic encoding + per-kind icons), `@/io` (scan import, report,
  the native `platform` seam), `@/state` (zustand store).
- `@/features/*` — `auth`, `dashboard` (pick a folder → list its local `.camp`
  files → open/create/join), `map` (Cytoscape `NetworkMap` + toolbar), `navigator`,
  `inspector` (`SidePanel`/`CredentialVault`/`TeamPanel`/`Paths`), `activity`,
  `search`, `appearance`, `presence`, `report`; with `@/ui` brutalist primitives.

### Frontend production rework (latest cycle)

A focused rework of the client's information architecture, interaction model, and
visual identity — all in `web/`, no Rust schema change (new team-shared data lives
in web-managed Loro containers the core preserves, like `theme`/`roster`):

- **Topology legibility + scale.** `NetworkMap`/`viz.ts`: larger nodes with
  ellipsized label plates, visible compound containers, lifted edge contrast, and
  zoom-based **level-of-detail** (`min-zoomed-font-size`) + `textureOnViewport`/
  `hideEdgesOnViewport` + incremental, viewport-preserving layout (no full re-fit
  per change) so the map stays legible and responsive into the thousands.
- **Accessibility.** A keyboard-navigable, screen-reader `GraphNav` tree mirrors
  the canvas (which AT cannot read), driving the same selection and centering the
  map; a global keyboard map (`/ n e c f g Esc`, ⌘K) + accessible `Dialog`/
  `Popover` primitives (focus-trap, ESC, ARIA) + a polite live region.
- **Typed modeling.** Edges now carry a typed `fields` bag with per-edge-kind
  schemas (trust direction, ports, MITRE technique, evidence); node schemas
  deepened across the thin kinds; clone, multi-select **bulk edit**, and a
  right-click context menu.
- **Paths.** Weighted Dijkstra (per-kind cost × confidence), operator-defined
  goals (high-value kinds ∪ `#goal`/`#crown-jewel`), interactive whole-chain
  highlight + framing, and team-shared **saved paths**.
- **Queries/templates.** A structured query (`kind:`, `compromise:>=admin`,
  `tag:`, `has:`, text) that filters the map, **team-shared saved filters**, node
  **templates**, and a ⌘K **command palette**.
- **Brutalist identity** anchored on the shadcn aesthetic: high-contrast graphite
  tokens, square chrome, hairline grid, mono data.

## Desktop client (Tauri 2) — the native app

The brief's client is a **cross-platform native desktop app**, not a web page —
and it is the *only* client (no standalone browser deployment). `web/src-tauri/`
is a Tauri 2 shell that hosts the React/Loro frontend in a system webview, with
every native capability behind a single seam (`web/src/io/platform.ts`):

- **The sovereign `.camp` lives in an operator-chosen folder** — a native folder
  picker, folder-scoped list/read/write, and an `camp://` deep link + `.camp`
  file association, with the
  bytes read/written in Rust (the webview gets no general filesystem access).
- **Device-identity secret in the OS keychain** (`keyring`) instead of the
  browser profile — the already-*sealed* record only; nothing is decrypted here.
- **Native menu, window-state, single-instance.**

Security is preserved by construction: every file/secret action is a
typed `#[tauri::command]` (no `fs`/`shell` plugin permission is exposed to the
webview), the CSP is locked down (`script-src 'self' 'wasm-unsafe-eval'`,
`connect-src` only `self`/`ipc:`/`ws:`/`wss:`, `object-src 'none'`), and the
crate is a **detached workspace** so the heavy webkit build never enters
`cargo test --workspace`. Build/run: `web/src-tauri/README.md`.

## What is intentionally not yet built

Faithful to the plan's phasing: additional importers + coverage-driven fuzzing
(phase 3 beyond the Nmap/BloodHound/NetExec/Nessus set). Key
**rotation/revocation** is implemented and tested (`key_epoch` in the campaign
file header; `key_rotation_revokes_a_removed_operator`). **M-of-N social
recovery is wired end to end in the client**: set up a recovery package,
trustees produce re-wrapped shares (delivered out of band), and the recovering
operator reconstructs the original secret and restores their identity. The
credential vault, offline recovery, reporting/export, and timeline scrubbing
are done. All remaining items are named in the plan with their dependencies.
