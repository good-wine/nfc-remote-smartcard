#!/usr/bin/env bash
# Esegue un comando in un mount namespace dove `nfc.local` risolve a 127.0.0.1,
# senza toccare il sistema e senza root.
#
#   ./scripts/with-nfc-local.sh curl https://nfc.local:8443/v1/status
#   ./scripts/with-nfc-local.sh chromium https://nfc.local:8443/
#
# Perché serve un namespace e non basta modificare `/etc/hosts`: su systemd con
# `nsswitch` = `hosts: ... resolve [!UNAVAIL=return] files ...` il modulo
# `nss-resolve` interroga systemd-resolved PRIMA di `files`. resolved risolve
# `.local` via DNS e risponde con un indirizzo sintetico (172.0.0.1), quindi
# `files` non viene mai consultato: la riga in `/etc/hosts` è irrilevante, anche
# se la scrivi con sudo. Servono due override, entrambi possibili solo in un
# namespace privato:
#   1. `/etc/nsswitch.conf` senza il modulo `resolve` → `files` diventa attivo
#   2. `/etc/hosts` con la riga di split-horizon locale
#
# `unshare --map-root-user --mount` non richiede privilegi: l'utente resta
# non-root nel sistema, ma dentro il namespace può montare. Le modifiche muoiono
# col comando, quindi niente da ripulire.
#
# Limite: vale solo per i processi avviati da qui dentro. Per un browser già
# aperto serve la variante con root (`./scripts/setup-local-domain.sh`).
set -euo pipefail

if [ $# -eq 0 ]; then
  echo "uso: $0 <comando> [argomenti...]" >&2
  echo "es. $0 curl https://nfc.local:8443/v1/status" >&2
  exit 2
fi

command -v unshare >/dev/null 2>&1 || {
  echo "unshare mancante (pacchetto util-linux)" >&2
  exit 1
}

HOSTS_FILE="$(mktemp)"
NSS_FILE="$(mktemp)"
trap 'rm -f "$HOSTS_FILE" "$NSS_FILE"' EXIT

# Split-horizon locale: il traffico resta sul loopback, non esce in LAN.
printf '127.0.0.1 nfc.local api.nfc.local app.nfc.local pair.nfc.local\n' >"$HOSTS_FILE"
# `files` davanti a tutto: azzera l'anticipo di nss-resolve.
printf 'hosts: files myhostname dns\n' >"$NSS_FILE"

# `sh -c script _ arg...` mette gli argomenti in $1..$N, quindi il comando
# utente viene passato come argv reale: niente shell injection, path con spazi
# intatti.
# SC2016 è un falso positivo: le variabili $1/$2/$@ NON devono espandersi nella
# shell esterna (sono posizionali della shell interna), per questo è single-quoted.
# shellcheck disable=SC2016
exec unshare --map-root-user --mount /bin/sh -c '
  set -e
  mount --bind "$1" /etc/hosts
  mount --bind "$2" /etc/nsswitch.conf
  shift 2
  exec "$@"
' _ "$HOSTS_FILE" "$NSS_FILE" "$@"