# Campaign Knowledge — desktop shell (Tauri 2)

The native, cross-platform client: the React/Loro/Cytoscape frontend (`../`)
hosted in a system webview, with the native capabilities a field tool needs.
**The app is local-only** — there is no server, no relay, no network transport.
Campaigns live as sealed `.camp` files in an operator-chosen folder; sharing is
out of band (hand the file to an enrolled co-operator).

## What the native layer adds

| Capability | How |
|---|---|
| Sovereign `.camp` files in an operator-chosen **folder** | native folder picker (`pick_directory`), folder-scoped list/read/write (`list_campaign_files`/`read_campaign_file`/`write_campaign_file`) in Rust |
| Open by double-click | `.camp` file association, read in Rust |
| Device-secret seal in the OS keychain | `keyring` crate (Secret Service / Keychain / Credential Manager) |
| Native menu, window-state, single-instance | `tauri::menu`, `tauri-plugin-window-state`, `tauri-plugin-single-instance` |
| Report / map-image export | native save dialog |

All native access lives behind one seam — `../src/io/platform.ts` — so no other
module touches the IPC boundary.

## The file model

The chosen folder holds the operator's sovereign `.camp` files and is the
**authoritative and only** copy. The client writes the latest sealed bytes back
to the folder file as the campaign changes (auto-save), so the file is always
current. Nothing campaign-related ever leaves the machine.

## Security posture (deliberate)

- **Tiny command surface.** Every file and secret action is a typed
  `#[tauri::command]` in `src/lib.rs`. The webview is granted **no** `fs`/`shell`
  plugin permission (`capabilities/default.json` is event + window focus only).
  Dialogs open and files are read/written *in Rust*, so a compromised frontend
  cannot touch arbitrary paths.
- **Folder-scoped I/O.** `read_campaign_file`/`write_campaign_file` canonicalize
  the target and reject anything outside the chosen folder (no traversal); writes
  require a bare filename; reads/writes are size-capped (256 MiB).
- **No network at all.** The CSP allows `connect-src 'self' ipc:
  http://ipc.localhost` only — no `ws:`/`wss:`, no remote hosts. The app cannot
  be made to talk to a server.
- **Zero-knowledge preserved.** Nothing here decrypts. The file commands move
  bytes the web layer already sealed; the keychain stores the *already-sealed*
  identity record (base64), never the unsealed secret.
- **Hardened CSP** (`tauri.conf.json`): `script-src 'self' 'wasm-unsafe-eval'`
  (Loro/libsodium WASM), `object-src 'none'`, `base-uri 'self'`,
  `form-action 'none'`. `devtools` is excluded from release builds.
- **Least privilege:** `read_campaign_path` reads only OS-handed open targets (an
  allowlist) with a size cap; the keychain commands accept only the single
  `identity` key.

**Accepted residual risk:** `keyring` vendors libdbus — track RUSTSEC
(cargo-audit/deny) in CI, or move to the pure-Rust `async-secret-service` (zbus)
backend.

## Build & run

From `../` (`core/web`):

```bash
# 1) one-time: system webview libs (Debian/Ubuntu)
sudo apt-get install -y libwebkit2gtk-4.1-dev libsoup-3.0-dev \
  libjavascriptcoregtk-4.1-dev librsvg2-dev build-essential pkg-config
npm install

# 2) dev (hot-reloads the frontend) or a distributable bundle
npm run tauri:dev
npm run tauri:build      # → src-tauri/target/release/bundle/  (.deb / .AppImage / .rpm)
```

Icons are generated from `icon-src.svg`:
`npx tauri icon src-tauri/icon-1024.png` (rasterize the SVG first).

## Layout

```
src-tauri/
  Cargo.toml          # detached workspace (NOT part of ../../Cargo.toml — keeps
                      # `cargo test --workspace` webkit-free)
  tauri.conf.json     # window, CSP, bundle, file association
  build.rs            # tauri-build
  src/main.rs         # thin shim → lib::run()
  src/lib.rs          # commands, native menu, plugins, launch open
  capabilities/       # minimal granted permissions
  icons/              # generated app icons
```
