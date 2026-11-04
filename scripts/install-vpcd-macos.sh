#!/usr/bin/env bash
# macOS: installa il compagno dell'engine `vpcd-stub` (adapter v1) come
# LaunchDaemon, solo loopback 127.0.0.1:35963. Da eseguire dalla radice repo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="/usr/local/bin"
PLIST="/Library/LaunchDaemons/it.nfcremote.vpcd.plist"

command -v cargo >/dev/null || { echo "cargo non trovato: installa Rust (rustup)" >&2; exit 1; }
echo "== build vpcd-stub =="
cargo build -p nfc-desktop --bin vpcd-stub --release
sudo cp "$ROOT/target/release/vpcd-stub" "$PREFIX/vpcd-stub"

sudo tee "$PLIST" >/dev/null <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>it.nfcremote.vpcd</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/vpcd-stub</string>
    <string>--host</string><string>127.0.0.1</string>
    <string>--port</string><string>35963</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
XML
sudo launchctl load -w "$PLIST"
echo "[OK] vpcd-stub attivo su 127.0.0.1:35963"