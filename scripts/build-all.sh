#!/usr/bin/env bash
# Build end-to-end: core test -> desktop bundle -> extension -> mobile -> webapp.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"

echo "== [1/5] nfc-core test =="
if command -v cargo >/dev/null; then
  (cd "$ROOT" && cargo test -p nfc-core)
else
  echo "cargo non trovato, salto test (installa rustup)"
fi

echo "== [2/5] desktop (Tauri v2) =="
(cd "$ROOT/desktop" && npm install && npm run build)
if command -v cargo >/dev/null; then
  (cd "$ROOT/desktop/src-tauri" && cargo build --release)
  if command -v tauri >/dev/null; then
    (cd "$ROOT/desktop/src-tauri" && tauri build)
  else
    echo "Tauri CLI non trovata: npm i -g @tauri-apps/cli"
  fi
fi

echo "== [3/5] extension =="
(cd "$ROOT/browser-extension" && npm install && npm run build && npm run zip || true)

echo "== [4/5] mobile UI nativa =="
(cd "$ROOT/mobile" && npm install && npm run build || true)

echo "== [5/5] webapp/PWA (desktop + mobile) =="
(cd "$ROOT/web" && npm install && npm run build)

if [ "${NFC_SKIP_E2E:-0}" != "1" ]; then
  echo "== [e2e] webapp in Chromium (engine --daemon + Playwright) =="
  "$ROOT/scripts/test-webapp.sh" || {
    echo "E2E webapp fallito (skip con NFC_SKIP_E2E=1)"; exit 1; }
fi

echo
echo "Build completata. Artefatti:"
echo "  - desktop/src-tauri/target/release/bundle/"
echo "  - browser-extension/dist/"
echo "  - web/dist/           (servita dall'engine su https://nfc.local:8443/)"
