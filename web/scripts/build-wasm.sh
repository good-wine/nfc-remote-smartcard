#!/usr/bin/env bash
# Compila il core Rust in WASM (`nfc-core-wasm`) e genera il glue JS con
# `wasm-bindgen` dentro `web/src/wasm/` (asset locale, niente CDN).
#
# Prerequisiti:
#   - target `wasm32-unknown-unknown` (rustup target add wasm32-unknown-unknown)
#   - `wasm-bindgen-cli` alla stessa versione della dipendenza (Cargo.lock),
#     es. `cargo install wasm-bindgen-cli --version <versione da Cargo.lock>`
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="$ROOT/web/src/wasm"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "ERROR: wasm-bindgen CLI mancante." >&2
  echo "Installa la versione pinnata in Cargo.lock:" >&2
  echo "  grep -A2 'name = \"wasm-bindgen\"' '$ROOT/Cargo.lock'" >&2
  echo "  cargo install wasm-bindgen-cli --version <versione> --locked" >&2
  exit 1
fi

# PATH: la riga riedita (roba di ci/cargo) — in CI il binario è già esposto.
export PATH="${HOME}/.cargo/bin:${PATH}"

echo "==> cargo build -p nfc-core-wasm --target wasm32-unknown-unknown --release"
(
  cd "$ROOT"
  cargo build -p nfc-core-wasm --target wasm32-unknown-unknown --release
)

echo "==> wasm-bindgen --target web -> $OUT_DIR"
mkdir -p "$OUT_DIR"
wasm-bindgen \
  --target web \
  --out-dir "$OUT_DIR" \
  --out-name nfc_core_wasm \
  "$ROOT/target/wasm32-unknown-unknown/release/nfc_core_wasm.wasm"

echo "==> glue WASM aggiornato in web/src/wasm/"