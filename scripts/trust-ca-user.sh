#!/usr/bin/env bash
# Installa la CA locale di nfc.local nel negozio di fiducia **dell'utente**,
# senza root. Copre i browser che non usano lo store di sistema:
#
#   - Firefox, Chromium/Chrome/Edge su Linux (NSS DB in ~/.pki/nssdb)
#   - ogni altra app che usa `certutil`/NSS
#
# Le app basate su OpenSSL (curl, git, rustls) usano invece lo store di sistema:
# su Linux quello richiede root (`update-ca-certificates`), quindi per queste
# basta `CURL_CA_BUNDLE` o `SSL_CERT_FILE` puntato alla CA.
#
# Idempotente: rimuove un'eventuale copia precedente prima di installare, così
# una rotazione della CA non lascia trust scaduti nel DB.
set -euo pipefail

CA="${NFC_REMOTE_HOME:-$HOME/.config/nfc-remote}/ca/nfc-local-root.pem"
NICKNAME="nfc-local-root"
NSSDB="sql:$HOME/.pki/nssdb"

if [ ! -f "$CA" ]; then
  echo "CA non trovata in $CA" >&2
  echo "generala con: ./target/debug/nfc-desktop --setup-local-domain" >&2
  exit 1
fi

if ! command -v certutil >/dev/null 2>&1; then
  echo "certutil mancante (pacchetto libnss3-tools)" >&2
  exit 1
fi

# `-f` va fatto sul file, non su "sql:$DIR": rilanciare `-N` su un DB già
# esistente fa chiedere la password e abortisce con `set -e`.
mkdir -p "${NSSDB#sql:}"
[ -f "${NSSDB#sql:}/cert9.db" ] || certutil -d "$NSSDB" -N --empty-password

# Rotazione: rimuove la voce precedente, se c'è.
certutil -d "$NSSDB" -D -n "$NICKNAME" >/dev/null 2>&1 || true
certutil -d "$NSSDB" -A -t C -n "$NICKNAME" -i "$CA"

echo "✔ CA installata per l'utente: $CA"
echo "  negozio: $NSSDB"
echo
echo "Verifica con un browser (nessun flag, nessuna eccezione):"
echo "  ./scripts/with-nfc-local.sh chromium https://nfc.local:8443/"
echo
echo "Per le app OpenSSL (senza root):"
echo "  export SSL_CERT_FILE=$CA"