#!/bin/sh
# Build the helwasm web bundle into helwasm/pkg/ (committed so GitHub Pages can
# serve the static dir directly, no CI). Requires the wasm32 target and a
# wasm-bindgen CLI matching the wasm-bindgen crate version:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version <crate version>
set -e
cd "$(dirname "$0")/.."
cargo build --target wasm32-unknown-unknown -p helwasm --release
wasm-bindgen --target web --out-dir helwasm/pkg \
  target/wasm32-unknown-unknown/release/helwasm.wasm
echo "built helwasm/pkg/ (helwasm.js + helwasm_bg.wasm)"

# Stamp the service worker with a content hash of the shipped shell, so the
# browser runs its update check exactly when the app's bytes change (and never
# needlessly). Generated from sw.template.js; both are committed (no CI).
sh helwasm/stamp-sw.sh
