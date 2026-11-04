#!/usr/bin/env bash
# Linux: engine desktop (tray) come systemd user service.
#
# Perché: il vecchio `setsid ... &` da una shell di lancio moriva quando la
# sessione del comando che lo aveva avviato veniva ripulita (log troncato,
# nessun crash — in foreground l'engine è stabile). Come utente systemd il
# processo vive fuori dal ciclo di vita della shell: riavvio automatico,
# dipendenza da nfc-vpcd.service già espressa nella unit.
#
# L'unit gira col binario del workspace (debug se presente, altrimenti release):
# dopo un rebuild basta `systemctl --user restart nfc-engine`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/debug/nfc-desktop"
[[ -x "$BIN" ]] || BIN="$ROOT/target/release/nfc-desktop"
if [[ ! -x "$BIN" ]]; then
  echo "engine non compilato: esegui 'cargo build -p nfc-desktop' prima" >&2
  exit 1
fi

mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/nfc-engine.service <<UNIT
[Unit]
Description=NFC Remote engine desktop (tray; TLS 8443 + WS 8080 loopback)
After=network.target nfc-vpcd.service
Wants=nfc-vpcd.service

[Service]
Type=simple
ExecStart=$BIN
Restart=on-failure
RestartSec=3
# Ambiente grafico della sessione da cui si esegue l'installer: interblocca
# il processo col display Wayland/X corretto (in dev il binario non è in systemd
# globale, resta un servizio utente per sessione).
Environment=WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-wayland-0}
Environment=DISPLAY=${DISPLAY:-:0}
Environment=XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
Environment=XDG_SESSION_TYPE=${XDG_SESSION_TYPE:-wayland}

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable nfc-engine.service >/dev/null
echo "[OK] unit nfc-engine installata (binario: $BIN)"
echo "     avvio/stop/riavvio: systemctl --user start|stop|restart nfc-engine"
echo "     log: journalctl --user -u nfc-engine -f"