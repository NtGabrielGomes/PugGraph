# PugGraph

**Diagram visualizer for red team operations.** PugGraph turns scanner output
into an interactive attack-path graph — part operations diagram, part ingestor
viewer. Drop in your **BloodHound** or **Pughound** logs (plus Nmap, NetExec
and Nessus) and explore the target environment as a living property graph:
hosts, users, groups, sessions, credentials, and the edges that connect them
into viable attack paths.

Everything is **local-first**: campaigns live as a single encrypted `.camp`
file on disk. No server, no account, no telemetry — seizing the file yields
only ciphertext.

<img width="1919" height="1035" alt="image" src="https://github.com/user-attachments/assets/c144a972-7402-4cbd-9811-2b674573d4ce" />

<img width="1920" height="999" alt="image" src="https://github.com/user-attachments/assets/84ba7c10-0252-42f8-bef2-b33707303812" />


## Two ways to use it

- **Red team diagram** — model the engagement as you go: nodes for assets and
  principals, typed edges (trusts, sessions, ACL abuse, credentials), tags like
  `#goal` / `#crown-jewel`, and weighted Dijkstra attack paths across the graph.
- **Ingestor viewer** — import BloodHound/Pughound JSON (and Nmap XML, NetExec,
  Nessus) to visualize what the collectors actually captured. Identity
  reconciliation collapses the same host seen by different scanners onto a
  single node.

## Features

- **Interactive map** (Cytoscape): compound containers, zoom level-of-detail,
  legible into the thousands of nodes.
- **Attack paths**: per-edge-kind cost × confidence weighting, operator-defined
  goals, whole-chain highlight, team-shared saved paths.
- **Structured search**: `kind:`, `compromise:>=admin`, `tag:`, `has:`, free
  text, saved filters, ⌘K command palette.
- **Typed modeling**: per-edge-kind field schemas (trust direction, ports,
  MITRE technique, evidence), bulk edit, templates.
- **Encrypted sovereign campaign file**: XChaCha20-Poly1305 AEAD, Ed25519-signed
  tamper-evident event chain, per-operator wrapped keys, role-limited credential
  vault, M-of-N social recovery.
- **CRDT collaboration**: the whole campaign is one [Loro](https://loro.dev)
  document — replicas converge with no lost data.
- **Desktop app** (Tauri 2): native folder picker, OS keychain for device keys,
  `.camp` file association, locked-down CSP. No standalone browser build.

## Stack

- **Core (`crates/`)** — Rust workspace: `domain` (typed property-graph model),
  `crypto` (E2E primitives + `.camp` file format), `crdt` (Loro campaign
  document), `import` (scanner pipeline: BloodHound, Nmap, NetExec, Nessus).
- **Client (`web/`)** — React 19 + TypeScript + Cytoscape, running the same
  Loro CRDT via WASM, byte-compatible crypto with the Rust core
  (`scripts/interop.sh` proves it both directions).
- **Desktop (`web/src-tauri/`)** — Tauri 2 shell; the webview gets no general
  filesystem access, all native I/O goes through typed commands.

## Build & test

```bash
cargo test --workspace        # Rust core: domain, crypto, crdt, import
bash scripts/interop.sh       # Rust <-> Node E2E crypto interop
cd web && npm install
npm test                      # frontend unit tests
npm run typecheck             # tsc --noEmit
npm run tauri:dev             # run the desktop app
```

## Importers

| Source | Format | Notes |
|---|---|---|
| BloodHound | JSON / ZIP | users, groups, computers, domains |
| Pughound | JSON | users, computers, DCSync rights, reports |
| Nmap | XML | hosts, services, `LISTENS_ON` edges |
| NetExec | logs | hosts, credentials |
| Nessus | XML | vulnerabilities |

Malformed or hostile input fails clean — memory-safe parsing is the posture
for a tool that ingests scanner output.

## License

Proprietary.
