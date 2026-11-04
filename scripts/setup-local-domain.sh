#!/usr/bin/env bash
# Rende `nfc.local` risolvibile e verifica che funzioni davvero.
#
#   ./scripts/setup-local-domain.sh          # dice cosa manca, non tocca nulla
#   sudo ./scripts/setup-local-domain.sh     # applica /etc/hosts + mDNS routing
#
# Perché esiste: su systemd con `nsswitch.conf` impostato su
# `hosts: ... resolve [!UNAVAIL=return] files ...`, il modulo `nss-resolve`
# interroga systemd-resolved **prima** di `files`. Quindi scrivere in
# `/etc/hosts` non basta e spesso non funziona: resolved risolve `.local`
# via DNS verso un resolver che risponde con un indirizzo segnaposto
# (es. 172.0.0.1), e il traffico non arriva mai all'engine. Servono entrambe
# le cose: la riga in hosts E il routing di `.local` verso mDNS.
set -euo pipefail

CA="${NFC_REMOTE_HOME:-$HOME/.config/nfc-remote}/ca/nfc-local-root.pem"
HOSTS_LINE="127.0.0.1	nfc.local api.nfc.local app.nfc.local pair.nfc.local"
HOSTS=/etc/hosts
ROUTED_CONF=/etc/systemd/resolved.conf.d/nfc-local.conf

have_resolved_nss=0
if grep -qE '^hosts:.*\bresolve\b' /etc/nsswitch.conf 2>/dev/null; then
  have_resolved_nss=1
fi

echo "== Situazione =="
getent hosts nfc.local 2>/dev/null | sed 's/^/  getent: /' || echo "  getent: nfc.local non risolve"
grep -qF 'nfc.local' "$HOSTS" 2>/dev/null \
  && echo "  hosts: riga nfc.local presente" \
  || echo "  hosts: riga nfc.local ASSENTE"
if [ "$have_resolved_nss" = 1 ]; then
  echo "  nsswitch: 'resolve' sta prima di 'files' -> /etc/hosts viene bypassato"
  echo "             (serve anche il routing mDNS sotto)"
fi

# ---------------------------------------------------------------------------
# Applicazione
# ---------------------------------------------------------------------------
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  cat <<EOF

== Cosa serve (una tantum, root) ==

1) Riga in /etc/hosts:
   sudo sh -c 'grep -q nfc.local $HOSTS || printf "%s\\n" "$HOSTS_LINE" >> $HOSTS'

2) Routing di .local verso mDNS (senza questo, systemd-resolved risolve
   nfc.local via DNS verso un indirizzo segnaposto e la connessione non arriva):
   sudo mkdir -p /etc/systemd/resolved.conf.d
   sudo tee $ROUTED_CONF >/dev/null <<'CONF'
[Resolve]
# nfc.local e tutti i *.local.devices.dev vanno risolti in multicast,
# non via DNS (RFC 6762). Senza questo resolved li chiede al resolver
# upstream che risponde con un sinkhole.
MulticastDNS=yes
Domains=nfc.local
CONF
   sudo systemctl restart systemd-resolved

3) Verifica: ./scripts/setup-local-domain.sh deve stampare l'IP reale
   dell'engine, non 172.0.0.1.

== Alternativa senza root (solo desktop) ==

Il certificato di nfc.local include i SAN 127.0.0.1 e ::1, quindi da questa
macchina puoi usare direttamente:
  https://127.0.0.1:8443/    oppure    https://localhost:8443/
I device in LAN non hanno bisogno di niente di tutto questo: risolvono
nfc.local via mDNS grazie all'annuncio dell'engine.
EOF
  exit 0
fi

# Da qui in avanti servono root.
if ! grep -qF 'nfc.local' "$HOSTS"; then
  printf '%s\n' "$HOSTS_LINE" >>"$HOSTS"
  echo "== applicato: riga in $HOSTS =="
else
  echo "== $HOSTS già ok =="
fi

if [ "$have_resolved_nss" = 1 ]; then
  mkdir -p "$(dirname "$ROUTED_CONF")"
  cat >"$ROUTED_CONF" <<'CONF'
[Resolve]
# nfc.local è un dominio mDNS (RFC 6762): risolverlo via DNS upstream
# restituisce un indirizzo segnaposto e la connessione non arriva all'engine.
# Con questa riga resolved lo risolve in multicast sull'interfaccia LAN,
# che è anche ciò che gli serve per rintracciare l'IP del desktop.
MulticastDNS=yes
Domains=nfc.local
CONF
  systemctl restart systemd-resolved 2>/dev/null || true
  echo "== applicato: $ROUTED_CONF + restart resolved =="
fi

# ---------------------------------------------------------------------------
# Verifica
# ---------------------------------------------------------------------------
sleep 1
echo
echo "== Verifica =="
resolved_ip="$(getent hosts nfc.local 2>/dev/null | awk '{print $1}' | head -1)"
if [ -z "$resolved_ip" ]; then
  echo "  ✘ nfc.local non risolve"
  exit 1
fi
echo "  nfc.local -> $resolved_ip"
case "$resolved_ip" in
  127.0.0.1|::1) echo "  ✔ split-horizon locale attivo" ;;
  172.0.0.1)     echo "  ✘ sinkhole del resolver: .local non è instradato su mDNS" ; exit 1 ;;
  *)             echo "  ✔ risolto via mDNS all'IP LAN" ;;
esac

if [ -f "$CA" ]; then
  code="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" \
          --connect-timeout 5 https://nfc.local:8443/v1/status || echo 000)"
  echo "  https://nfc.local:8443/v1/status -> $code"
  [ "$code" = 200 ] || echo "  (l'engine deve essere in esecuzione)"
else
  echo "  CA non trovata in $CA (genera con: nfc-desktop --setup-local-domain)"
fi