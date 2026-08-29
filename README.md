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

### Prerequisites

- **Rust** (`cargo`, 1.82+) and **Node.js + npm** (20+).
  No-sudo Node install on any distro:
  ```bash
  mkdir -p ~/.local/opt ~/.local/bin
  curl -sLO https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.xz
  tar -xJf node-v24.20.0-linux-x64.tar.xz -C ~/.local/opt
  ln -sfn ~/.local/opt/node-v24.20.0-linux-x64 ~/.local/opt/node
  ln -sf ~/.local/opt/node/bin/{node,npm,npx} ~/.local/bin/
  # ensure ~/.local/bin is on PATH, e.g.: export PATH="$HOME/.local/bin:$PATH"
  ```
- **Desktop shell only** (skip for CLI/web-only work): WebKitGTK 4.1.
  Arch: `sudo pacman -S webkit2gtk-4.1` · Debian/Ubuntu: `sudo apt install libwebkit2gtk-4.1-dev`

### Core & web

```bash
cargo test --workspace        # Rust core: domain, crypto, crdt, import
bash scripts/interop.sh       # Rust <-> Node E2E crypto interop
cd web && npm install
npm test                      # frontend unit tests
npm run typecheck             # tsc --noEmit
npm run dev                   # web UI on http://localhost:5173
```

### Desktop app

```bash
cd web && npm run tauri:dev   # run the desktop app (dev mode)
bash scripts/build-desktop.sh # release bundles: AppImage + .deb + .rpm
```

`build-desktop.sh` wraps `tauri build` with the fixes modern distros need
(`CI=1` env clash, `NO_STRIP` for binutils RELR sections, FUSE-less AppImage
packaging, and a guard for the linuxdeploy gtk plugin on gdk-pixbuf >= 2.44).
Artifacts land in `web/src-tauri/target/release/bundle/`; the AppImage runs
stand-alone — on machines without FUSE, launch it with
`APPIMAGE_EXTRACT_AND_RUN=1 ./Campaign\ Knowledge_0.1.0_amd64.AppImage`.

### Hostile graphics/CPU environments (VMs)

The desktop binary self-configures WebKitGTK fallbacks at startup (Linux only,
only when the variable is not already set, so you can override):

| Variable | Why |
|---|---|
| `WEBKIT_DISABLE_DMABUF_RENDERER=1` | DMA-BUF renderer freezes without GPU accel |
| `WEBKIT_DISABLE_COMPOSITING_MODE=1` | threaded compositing crawls on software GL |
| `JSC_useJIT=0` | *(only when the CPU lacks AVX — checked via `/proc/cpuinfo`)* JavaScriptCore's `ctiMasmProbeTrampoline` executes AVX instructions whenever any JIT tier is active; on CPUs without AVX (old hardware, VMs masking AVX from the host, e.g. VMware on Zen 4) this is a SIGILL that kills the web process mid-operation (gray frozen window). Interpreted JS/WASM is the only config verified stable there. Machines with AVX keep the full JIT. |

The MESA `DRI3/DRI2` warnings at launch are cosmetic (software rendering
fallback). To silence: `LIBGL_ALWAYS_SOFTWARE=1`. The real fix for a VM is
enabling 3D acceleration in the hypervisor display settings.

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
