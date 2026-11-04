#!/usr/bin/env bash
# Apre al traffico LAN il solo canale TLS dell'engine (default :8443), lasciando
# il vecchio WS :8080 legato a 127.0.0.1 (nessuna regola inbound: è loopback per
# design, non deve MAI essere raggiungibile dai device).
#
#   ./scripts/autoconfigure-firewall.sh           # non-root → dry-run (stampa)
#   sudo ./scripts/autoconfigure-firewall.sh      # applica davvero
#
# Cosa apre (e niente altro):
#   - TCP 8443  da RFC1918 (10/8, 172.16/12, 192.168/16) + ULA fc00::/7
#     e link-local fe80::/10 (IPv6): il pairing E2EE e i transmit della webapp.
#     Il certificato serve il pin TLS nel QR: anche un host LAN ostile non può
#     fare MITM, perché la app nativa valida pin+certificato.
#   - UDP 5353  da LAN (IPv4+IPv6): mDNS, solo discovery `_smartcard-nfc`.
#     Il trasporto E2EE non passa MAI da mDNS.
# Cosa NON tocca: 8080, SSH, e qualsiasi altra regola esistente. Idempotente:
# rileggi le regole e aggiunge solo quelle mancanti.
set -euo pipefail

PORT="${NFC_REMOTE_PORT:-8443}"
IFACE="${NFC_REMOTE_IFACE:-}"            # p.es. "enp10s0": restringe alla iface
LAN4="${NFC_REMOTE_LAN:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16}"
LAN6="${NFC_REMOTE_LAN6:-fc00::/7 fe80::/10}"
MDNS=5353

APPLY=1
[[ $EUID -ne 0 ]] && APPLY=0 && echo "== non-root: sola DRY-RUN (esegui con sudo per applicare) =="
[[ "${1:-}" == "--apply" ]] && APPLY=1

ufw_loaded() { command -v ufw >/dev/null && [[ -f /etc/ufw/ufw.conf ]]; }
firewalld_on() { command -v firewall-cmd >/dev/null && systemctl -q is-active firewalld 2>/dev/null; }
nft_on() { command -v nft >/dev/null; }

echo "== backend firewall =="
if [[ $APPLY -eq 1 ]]; then
  if ufw_loaded && systemctl -q is-enabled ufw 2>/dev/null; then
    echo "  backend: ufw (sistema)"
    ufw_rule() { # $1=cidr $2=port $3=proto ; iface opzionale in $IFACE
      local args=()
      [[ -n "$IFACE" ]] && args+=("on" "$IFACE")
      ufw allow "${args[@]}" from "$1" to any port "$2" proto "$3" >/dev/null
    }
    # IPv4
    for cidr in $LAN4; do
      if ! ufw status | grep -qE "^${PORT}/tcp.*ALLOW.*${cidr}"; then
        ufw_rule "$cidr" "$PORT" tcp
        echo "  + TCP $PORT from $cidr"
      else
        echo "  = TCP $PORT from $cidr (già presente)"
      fi
      if ! ufw status | grep -qE "^${MDNS}/udp.*ALLOW.*${cidr}"; then
        ufw_rule "$cidr" "$MDNS" udp
        echo "  + UDP $MDNS (mDNS) from $cidr"
      else
        echo "  = UDP $MDNS from $cidr (già presente)"
      fi
    done
    # IPv6
    for cidr6 in $LAN6; do
      if ! ufw status | grep -qE "^${PORT}/tcp.*ALLOW.*${cidr6}"; then
        ufw allow from "$cidr6" to any port "$PORT" proto tcp >/dev/null
        echo "  + TCP $PORT (v6) from $cidr6"
      else
        echo "  = TCP $PORT (v6) from $cidr6 (già presente)"
      fi
      if ! ufw status | grep -qE "^${MDNS}/udp.*ALLOW.*${cidr6}"; then
        ufw allow from "$cidr6" to any port "$MDNS" proto udp >/dev/null
        echo "  + UDP $MDNS (v6/mDNS) from $cidr6"
      else
        echo "  = UDP $MDNS (v6) from $cidr6 (già presente)"
      fi
    done
    echo "== stato finale (solo righe rilevanti) =="
    ufw status | grep -E "^${PORT}|^${MDNS}" || echo "  (nessuna riga per $PORT/$MDNS)"
  elif firewalld_on; then
    echo "  backend: firewalld"
    for cidr in $LAN4; do
      firewall-cmd --permanent --add-rich-rule \
        "rule family=ipv4 source address=$cidr port port=$PORT protocol=tcp accept" >/dev/null
      firewall-cmd --permanent --add-rich-rule \
        "rule family=ipv4 source address=$cidr port port=$MDNS protocol=udp accept" >/dev/null
    done
    for cidr6 in $LAN6; do
      firewall-cmd --permanent --add-rich-rule \
        "rule family=ipv6 source address=$cidr6 port port=$PORT protocol=tcp accept" >/dev/null
      firewall-cmd --permanent --add-rich-rule \
        "rule family=ipv6 source address=$cidr6 port port=$MDNS protocol=udp accept" >/dev/null
    done
    firewall-cmd --reload >/dev/null
    echo "  regole applicate (firewalld, ricche su $PORT/$MDNS)."
  elif nft_on; then
    echo "  backend: nftables (tabella dedicata nfc-remote, solo ACCEPT+return)"
    nft create table inet nfc-remote 2>/dev/null || true
    nft create chain inet nfc-remote input '{ type filter hook input priority -10; policy accept; }' 2>/dev/null || true
    for cidr in $LAN4; do
      nft add rule inet nfc-remote input ip saddr "$cidr" tcp dport "$PORT" accept
      nft add rule inet nfc-remote input ip saddr "$cidr" udp dport "$MDNS" accept
    done
    for cidr6 in $LAN6; do
      nft add rule inet nfc-remote input ip6 saddr "$cidr6" tcp dport "$PORT" accept
      nft add rule inet nfc-remote input ip6 saddr "$cidr6" udp dport "$MDNS" accept
    done
    echo "  regole applicate (nft, v4+v6)."
  else
    echo "ERRORE: nessun backend supportato (ufw/firewalld/nft)."
    exit 1
  fi
else
  echo "  (dry-run) verresti applicato su:"
  for cidr in $LAN4 $LAN6; do
    echo "    - TCP $PORT   da $cidr"
    echo "    - UDP $MDNS (mDNS) da $cidr"
  done
  echo "  8080 resta invariato: bound loopback, nessuna regola inbound."
  echo "  Per applicare: sudo ./scripts/autoconfigure-firewall.sh"
fi

echo
echo "== verifica (porta in ascolto, senza engine) =="
if command -v ss >/dev/null; then
  ss -tln 2>/dev/null | grep -E ":${PORT}\b|:8080\b" || echo "  nessuna bind al momento (engine spento: normale)"
fi
echo "OK"