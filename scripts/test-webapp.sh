#!/usr/bin/env bash
# Smoke test end-to-end della webapp: avvia l'engine in `--daemon`, aspetta che
# sia pronto, gira Playwright, poi spegne l'engine.
#
# Engine e test vivono nella stessa invocazione di shell di proposito: in questo
# ambiente i processi figli vengono terminati quando la sessione che li ha lanciati
# chiude, quindi un engine avviato in precedenza non sopravvive fino al test.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$HOME/.local/node/bin:$PATH"
export NODE_PATH="$ROOT/browser-extension/node_modules"

CA="${NFC_CA:-$HOME/.config/nfc-remote/ca/nfc-local-root.pem}"
BASE="${NFC_BASE:-https://localhost:8443}"
LOG="$ROOT/.webapp-test-engine.log"

cleanup() {
  [ -n "${ENGINE:-}" ] && kill "$ENGINE" 2>/dev/null || true
}
trap cleanup EXIT

if curl -sf -o /dev/null --cacert "$CA" "$BASE/v1/status" 2>/dev/null; then
  echo "engine già in ascolto su $BASE: lo riuso"
  ENGINE=""
else
  "$ROOT/target/debug/nfc-desktop" --daemon >"$LOG" 2>&1 &
  ENGINE=$!
  echo "engine avviato (pid $ENGINE), log: $LOG"
  for _ in $(seq 1 30); do
    if curl -sf -o /dev/null --cacert "$CA" "$BASE/v1/status" 2>/dev/null; then break; fi
    kill -0 "$ENGINE" 2>/dev/null || { echo "engine morto all'avvio:"; tail -20 "$LOG"; exit 1; }
    sleep 1
  done
  curl -sf -o /dev/null --cacert "$CA" "$BASE/v1/status" \
    || { echo "engine non pronto su $BASE"; tail -20 "$LOG"; exit 1; }
fi

echo "== test webapp =="
cd "$ROOT/web"
NFC_CA="$CA" NFC_BASE="$BASE" node tests/webapp.spec.mjs

# Percorso rootless: dentro il namespace `nfc.local` deve risolversi e il TLS
# validare senza eccezioni. È la prova che la soluzione senza root sia completa.
if [ "${NFC_SKIP_NAMESPACE:-0}" = "1" ] || ! command -v unshare >/dev/null 2>&1; then
  echo "== test namespace: saltato (unshare assente o NFC_SKIP_NAMESPACE=1) =="
else
  echo "== test namespace =="
  "$ROOT/scripts/with-nfc-local.sh" env NODE_PATH="$NODE_PATH" node tests/namespace.spec.mjs
fi