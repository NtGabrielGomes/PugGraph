#!/usr/bin/env bash
# Cross-stack interop check: proves the Rust core and the TypeScript client agree
# byte-for-byte on the campaign-file crypto (XChaCha20-Poly1305 + Ed25519).
#
#   Rust seals+signs  -> Node opens+verifies
#   Node seals+signs  -> Rust opens+verifies
set -euo pipefail

# Toolchains: use whatever cargo/node are on PATH (source ~/.cargo/env or nvm
# first yourself if you installed them that way).
command -v cargo >/dev/null || { echo "cargo not on PATH"; exit 1; }
command -v node  >/dev/null || { echo "node not on PATH";  exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # -> core/
cd "$HERE"

echo "building Rust interop example..."
cargo build -q --example interop -p crypto
EX="target/debug/examples/interop"
NODE_SCRIPT="web/scripts/interop.mjs"

echo "[1/2] Rust emit -> Node check"
"$EX" emit | node "$NODE_SCRIPT" check

echo "[2/2] Node emit -> Rust check"
node "$NODE_SCRIPT" emit | "$EX" check

echo "INTEROP OK — both stacks interoperate on AEAD + signatures."
