#!/usr/bin/env bash
# Avvia l'intero stack NFC Remote in background (engine + dev server UI).
# Uso: scripts/start-all.sh [--daemon]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/.run"
LOG="$ROOT/.logs"
mkdir -p "$RUN" "$LOG"

export PATH="$HOME/.cargo/bin:$HOME/.local/node/bin:$PATH"

ENGINE_BIN="$ROOT/target/debug/nfc-desktop"
[[ -x "$ENGINE_BIN" ]] || ENGINE_BIN="$ROOT/target/release/nfc-desktop"
if [[ ! -x "$ENGINE_BIN" ]]; then
  echo "binario engine non trovato: esegui 'cargo build -p nfc-desktop' prima" >&2
  exit 1
fi

stop() {
  systemctl --user stop nfc-engine.service 2>/dev/null || true
  for name in nfc-desktop vite; do
    pkill -x "$name" 2>/dev/null || true
  done
  pkill -f "vite dev --port 1420" 2>/dev/null || true
  sleep 1
}

ENGINE_SERVICE() { systemctl --user is-enabled nfc-engine.service >/dev/null 2>&1; }

# Path del binario cablato nella unit (ExecStart=): se il repo viene spostato
# il path non esiste più e systemd va in crash-loop (203/EXEC).
engine_unit_bin() {
  systemctl --user show nfc-engine.service -p ExecStart --value 2>/dev/null \
    | sed -n 's/.*path=\([^ ;]*\).*/\1/p'
}

# Fallisce, con le istruzioni di riparazione, se la unit punta a un binario
# inesistente (tipico dopo un cambio di path del repo).
check_engine_unit() {
  local ub
  ub="$(engine_unit_bin)"
  [[ -z "$ub" || -x "$ub" ]] && return 0
  {
    echo "nfc-engine.service punta a un binario inesistente:"
    echo "  $ub"
    echo "rilancia scripts/install-engine-linux.sh (i path sono cablati nella unit)"
  } >&2
  return 1
}

start_engine() {
  if [[ "${1:-}" == "--daemon" ]]; then
    # Headless di test/dev: process-scoped, non systemd (così test-webapp.sh
    # e i test di regressione girano senza alterare lo stato del servizio).
    setsid "$ENGINE_BIN" --daemon >"$LOG/engine.log" 2>&1 < /dev/null &
    echo $! >"$RUN/engine.pid"
  elif ENGINE_SERVICE; then
    systemctl --user start nfc-engine.service
  else
    setsid "$ENGINE_BIN" >"$LOG/engine.log" 2>&1 < /dev/null &
    echo $! >"$RUN/engine.pid"
  fi
}

start_vite() {
  # Vite serve la WebView Tauri in dev (devUrl http://localhost:1420).
  (cd "$ROOT/desktop" && setsid npm run dev >"$LOG/vite.log" 2>&1 < /dev/null & echo $! >"$RUN/vite.pid")
}

wait_http() {
  local url="$1" tries="${2:-100}"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS -o /dev/null --max-time 2 "$url" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  return 1
}

case "${1:-start}" in
  start)
    # Col daemon si usa il binario del repo, non la unit: check solo per il tray.
    if [[ "${2:-}" != "--daemon" ]] && ENGINE_SERVICE; then
      check_engine_unit || exit 1
    fi
    stop
    start_engine "${2:-}"
    start_vite
    # if/then esplicito, non `A && B || C`: con `C` contenente `exit 1` la
    # forma compatta può eseguire il ramo d'errore anche se A è vero ma B fallisce.
    if wait_http "http://127.0.0.1:8080/v1/status"; then
      echo "engine   OK  http://127.0.0.1:8080"
    else
      echo "engine   FAIL (vedi $LOG/engine.log)"
      exit 1
    fi
    if wait_http "http://127.0.0.1:1420/"; then
      echo "vite     OK  http://127.0.0.1:1420"
    else
      echo "vite     FAIL (vedi $LOG/vite.log)"
      exit 1
    fi
    CA="$HOME/.config/nfc-remote/ca/nfc-local-root.pem"
    if [[ -f "$CA" ]] && curl -fsS -o /dev/null --max-time 3 --cacert "$CA" \
        --resolve nfc.local:8443:127.0.0.1 https://nfc.local:8443/v1/status 2>/dev/null; then
      echo "https    OK  https://nfc.local:8443"
    else
      echo "https    WARN non verificabile (CA non installata o porta chiusa)"
    fi
    ;;
  stop)
    stop
    echo "fermato"
    ;;
  status)
    if ENGINE_SERVICE; then
      systemctl --user is-active nfc-engine.service >/dev/null 2>&1 \
        && echo "engine   running (systemd user)" || echo "engine   stopped"
      check_engine_unit 2>/dev/null \
        || echo "engine   unit con binario mancante (rilancia scripts/install-engine-linux.sh)"
    else
      pgrep -x nfc-desktop >/dev/null && echo "engine   running" || echo "engine   stopped"
    fi
    curl -fsS --max-time 2 http://127.0.0.1:8080/v1/status || echo "engine   unreachable"
    echo
    curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:1420/ && echo "vite     running" || echo "vite     stopped"
    # vpcd-stub gira come unit systemd utente (adapter v1, loopback 35963).
    # Connessione riuscita => porta aperta (exit 0); eccezione => non in ascolto.
    if python3 -c 'import socket; socket.create_connection(("127.0.0.1",35963),timeout=1).close()' 2>/dev/null; then
      echo "vpcd     running (vpcd-stub)"
    else
      echo "vpcd     stopped"
    fi
    ;;
  *)
    echo "uso: $0 {start [--daemon]|stop|status}" >&2
    exit 2
    ;;
esac