#!/usr/bin/env bash
# Linux: lettore PC/SC virtuale (adapter v1) come systemd user service.
#
# Installa `vpcd-stub` (il server compagno dell'engine, binario nel crate
# desktop): NON serve la build di vsmartcard — il demone `vpcd` di quel
# progetto usa un protocollo incompatibile con l'adapter v1 dell'engine.
# La parte root serve solo per le dipendenze PC/SC (optionale: i reader
# fisici richiedono la feature `physical`); lo stub gira in loopback come
# utente, senza privilegi.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$HOME/.local/node/bin:$PATH"

# pcscd serve solo al probe `physical` (reader USB); se manca, try apt/dnf ma
# non blocca: lo stub è un puro TCP loopback e non ha bisogno di pcscd.
if ! command -v pcscd >/dev/null 2>&1; then
  sudo apt-get update >/dev/null 2>&1 && sudo apt-get install -y libpcsclite1 pcscd >/dev/null 2>&1 \
    || sudo dnf install -y pcsc-lite pcsc-lite-libs >/dev/null 2>&1 || true
fi

echo "== build vpcd-stub =="
cargo build -p nfc-desktop --bin vpcd-stub --release
# Lo stub in esecuzione tiene il binario aperto: fermalo prima del cp, altrimenti
# fallisce con ETXTBSY ("File di testo occupato"); la unit riparte in fondo.
systemctl --user stop nfc-vpcd.service 2>/dev/null || true
mkdir -p ~/.local/bin ~/.config/systemd/user
cp "$ROOT/target/release/vpcd-stub" ~/.local/bin/vpcd-stub

cat > ~/.config/systemd/user/nfc-vpcd.service <<'UNIT'
[Unit]
Description=NFC Remote vpcd-stub (adapter v1, loopback)
After=network.target
[Service]
ExecStart=%h/.local/bin/vpcd-stub --host 127.0.0.1 --port 35963
Restart=always
[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable --now nfc-vpcd.service
echo "[OK] vpcd-stub attivo su 127.0.0.1:35963 (card presente: off)"