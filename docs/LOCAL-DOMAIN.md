# Dominio locale `nfc.local` + HTTPS (guida operativa)

## Perché
- Le pagine PA (`https://*.gov.it`) che chiamano `http://127.0.0.1:8080` vivono in
  zona grigia mixed-content/SecureContext. Con `https://nfc.local:8443` + cert
  valido l'engine è un **SecureContext a pieno titolo**: `crypto.subtle`,
  `crypto.randomUUID`, cookie `Secure`, nessun warning.
- Un solo nome per **tutti i servizi**: REST, WSS extension/mobile, landing `/`,
  pagina `/pair`, UI `app.` — stesso cert wildcard, stessa allowlist.

## Mappa servizi (primario: HTTPS + sottodomino)
Ogni servizio ha un sottodomino dedicato su `nfc.local`, tutti in HTTPS sulla
stessa porta `8443`, serviti dallo stesso Router e dallo stesso certificato.

| Sottodomino / URL | Cosa |
|---|---|
| `https://nfc.local:8443/` | landing JSON servizi (contratto API, intatto) |
| `https://app.nfc.local:8443/` | webapp / PWA installabile (Pair, Console, Status) |
| `https://pair.nfc.local:8443/` | pagina pairing + `nfc://pair` |
| `https://api.nfc.local:8443/v1/status` | health |
| `POST https://api.nfc.local:8443/v1/transmit` | REST APDU (stesso schema WS) |
| `wss://nfc.local:8443/v1/extension` | WS extension/webapp (primario) |
| `wss://nfc.local:8443/v1/mobile` | WS mobile E2EE |
| `wss://api.nfc.local:8443/v1/mobile` | idem, esplicito |

Tutti i sottodomini condividono lo stesso certificato: il suo è
`nfc.local, *.nfc.local, api/app/pair.nfc.local, localhost, 127.0.0.1, ::1`,
quindi il TLS valida senza eccezioni su ciascun nome.

## Fallback loopback/localhost (solo se `nfc.local` non funziona)
Il fallback non è una scelta di progetto: è il ripiego quando la risoluzione
del nome fallisce (nessun mount namespace, nessuna riga hosts, VPN che
intercetta `.local`).

| Primario | Fallback |
|---|---|
| `https://nfc.local:8443/` | `https://127.0.0.1:8443/` o `https://localhost:8443/` |
| `https://app.nfc.local:8443/` | `https://127.0.0.1:8443/app` |
| `wss://nfc.local:8443/v1/extension` | `ws://127.0.0.1:8080/v1/extension` |
| `wss://nfc.local:8443/v1/mobile` | `ws://<ip-lan>:8080/v1/mobile` (solo se il QR non ha pin) |

I due IP-SAN (`127.0.0.1`, `::1`) nel certificato servono esattamente a questo:
il fallback loopback valida **senza eccezioni**, senza `--ignore-certificate-errors`
e senza `--host-resolver-rules`.

> Il fallback mobile in chiaro **non funziona più** per costruzione: 8080 è
> solo loopback. È un ripiego solo per un engine senza TLS, non per un
> telefono legittimo. Vedi sotto.

## Perché 8080 è solo loopback
8080 è il fallback dell'**estensione sullo stesso desktop**, quando il browser
non si fida della CA locale. Non serve in LAN: il mobile ci parla solo con
`wss://` su 8443.

Il mobile usa TLS con **pin del certificato foglia** invece che con la CA
installata sul device, che sarebbe impraticabile (su Android serve un
certificato utente installato a mano; su iOS un profilo di configurazione).
Il QR pubblica `SHA-256(DER foglia)` — 43 caratteri, letti dallo stesso canale
out-of-band davanti al desktop che già trasporta nonce e chiavi.

```
QR: { "ip": "192.168.188.47", "port": 8080,
      "host": "nfc.local", "tls_port": 8443, "tls_pin_b64": "…43 char…",
      "exp_unix": 1799999999 }
```

`exp_unix` è la scadenza del QR (epoch secondi, TTL dell'engine = 5 minuti).
Non autorizza nulla: serve a una cosa sola, **il messaggio d'errore**. Senza di
esso, un QR fotografato ieri e un certificato rotato produrrebbero lo stesso
errore — che è anche quello che mostrerebbe un intercettatore — e le due
situazioni richiedono reazioni opposte. Chi ne modifica il valore può solo
convincere il telefono a *tentare* un handshake che l'engine rifiuterà comunque.

Il telefono lo confronta con il proprio orologio, con un margine di 90 secondi
sulla deriva: senza, un device con l'orologio indietro di un minuto respingerebbe
un QR appena emesso e riceverebbe "rigenera" — un rimedio che non cambia nulla.

Da lì il telefono apre `wss://nfc.local:8443/v1/mobile` con verifica
dell'impronta in tempo costante.

**Il ripiego in chiaro esiste solo per gli errori di rete** (mDNS bloccata,
connessione rifiutata, timeout): è il caso legittimo, e il canale resta E2EE.
Un **certificato non pinnato, invece, interrompe la connessione**: ripiegare
in quel caso darebbe a chiunque — basta rifiutare il TLS o presentare un
certificato qualsiasi — la possibilità di scegliere se la sessione viaggia
cifrata.

Il campo `host` è validato contro il dominio locale: un QR malevolo non può
dirottare il telefono verso un dominio esterno.

Il ripiego su `ws://` è ammesso **solo se l'engine è sul loopback** dello stesso
host (sviluppo e test): con 8080 bindato su `127.0.0.1`, un device in LAN non
può usarlo, e il mobile lo dice esplicitamente invece di aspettare un timeout.

**Cosa il pin non fa.** Non autentica il peer: quello lo fa l'handshake E2EE
X25519 + ML-KEM-768, che vincola la chiave del desktop a quella del QR con la
SAS anti-MITM. Il pin serve a non dover fidarsi di una CA installata sul
telefono, e a coprire il tratto LAN da chi sniffa ma non sa la chiave privata.

**Perché l'host e non l'IP.** Con mDNS, `nfc.local` risolve sul telefono e il
nome è coperto dal SAN del certificato. Un `wss://192.168.188.47:8443` non
validerebbe: la CA è locale e non emette IP-SAN per gli indirizzi di LAN.

## Split-horizon DNS (importante)
- **Mobile/LAN**: `nfc.local` via **mDNS** (RFC 6762) → IP LAN del desktop.
  Non serve configurare nulla sul telefono: l'engine annuncia
  `nfc.local.` con l'IP LAN (`_smartcard-nfc._tcp.local`, porta TLS in TXT).
  **8080 non viene annunciata**: è bindata sul loopback, quindi non è un
  servizio della LAN, e pubblicarla in un record mDNS sarebbe un'affermazione
  falsa — un client che leggesse `plain=8080` tenterebbe una porta chiusa.
  Il QR contiene comunque l'IP esplicito se il multicast è filtrato
  (guest-WiFi, VPN).
  > **Non verificato end-to-end in ambiente container/VPN.** La registrazione
  > è corretta (`nfc.local. announces [192.168.x.x]`) ma un processo separato
  > non vede il servizio: con molta probabilità è un filtro multicast di rete,
  > non un bug del codice. Serve una prova su un dispositivo reale in LAN.
  > Fino ad allora il QR con IP esplicito è il percorso affidabile.
- **Desktop/estensione**: traffico mai in LAN. Tre vie, in ordine di preferenza:
  1. **senza root, senza eccezioni** — `nfc.local` vero grazie a
     `./scripts/with-nfc-local.sh <comando>`: esegue il comando in un mount
     namespace dove `nfc.local` → `127.0.0.1`. Certificato validato, nessun
     `--ignore-certificate-errors`, nessun `--host-resolver-rules`. Copre
     desktop, webapp e test.
  2. **senza root, URL loopback** — `https://127.0.0.1:8443/` o
     `https://localhost:8443/`: il certificato ha i SAN `127.0.0.1` e `::1`,
     quindi valida senza eccezioni. Zero setup, ma il nome non è `nfc.local`.
  3. **con root, per tutto il desktop** — `./scripts/setup-local-domain.sh`:
     scrive `/etc/hosts` **e** instrada `.local` su mDNS. Vale per i processi
     già aperti (un browser già lanciato non entra nel namespace).

> **Attenzione, trappola di systemd-resolved.** Su sistemi con
> `nsswitch.conf` = `hosts: ... resolve [!UNAVAIL=return] files ...`, il modulo
> `nss-resolve` interroga `systemd-resolved` **prima** di `files`. Scrivere la
> riga in `/etc/hosts` e basta **non funziona**: resolved risolve `.local` via
> DNS e restituisce un indirizzo segnaposto (es. `172.0.0.1`), e `nss-resolve`
> cortocircuita `files`. Anche con `sudo` la riga in `/etc/hosts` resta
> irrilevante. Servono entrambe le modifiche:
> `/etc/hosts` **e** `/etc/systemd/resolved.conf.d/nfc-local.conf` con
> `MulticastDNS=yes` + `Domains=nfc.local`, poi `systemctl restart systemd-resolved`.
> Senza root l'unica strada è il namespace, perché *le due* modifiche sono
> necessarie e nessuna delle due è possibile altrove.
>
> Sintomo del problema: `getent hosts nfc.local` restituisce `172.0.0.1`
> invece di `127.0.0.1` o dell'IP LAN.

## Setup (una tantum)
```bash
# 1. PKI: CA + foglia (niente root)
./target/debug/nfc-desktop --setup-local-domain

# 2. Fiducia browser senza root: NSS DB utente (~/.pki/nssdb).
#    Idempotente, ruota la voce se la CA cambia.
./scripts/trust-ca-user.sh

# 3. Usare nfc.local senza root (solo per i comandi lanciati da qui)
./scripts/with-nfc-local.sh chromium https://nfc.local:8443/
./scripts/with-nfc-local.sh curl https://nfc.local:8443/v1/status

# Oppure, per tutto il desktop, con root
sudo ./scripts/setup-local-domain.sh
```

**Windows**: niente `nsswitch`, quindi il trappola di resolved non esiste e
basta il percorso hosts + store CurrentUser:
```powershell
.\scripts\setup-nfc-local.ps1   # Amministratore per hosts, il trust è CurrentUser
```
Dettaglio PKI: CA in `~/.config/nfc-remote/ca/` (0600), foglia 90gg in
`~/.config/nfc-remote/tls/` con SAN `nfc.local, *.nfc.local (+api/app/pair),
localhost, 127.0.0.1, ::1`; rinnovo auto a 60gg all'avvio. La chiave CA non
lascia l'host.

## Fiducia CA per browser
- **Chrome/Chromium/Edge/Firefox su Linux** usano il NSS DB dell'utente
  (`~/.pki/nssdb`) e **ignorano** `SSL_CERT_FILE` / `CURL_CA_BUNDLE`: passa da
  `./scripts/trust-ca-user.sh`. Idempotente: elimina la voce precedente prima di
  installare, così una rotazione della CA non lascia trust scaduti.
- **Windows/macOS**: store di sistema, coperto da `setup-local-domain.sh`.
- **App OpenSSL** (curl, git, rustls): store di sistema su Linux → serve root
  (`update-ca-certificates`). Senza root: `export SSL_CERT_FILE=<ca.pem>` oppure
  `--cacert <ca.pem>`.
- **Firefox** con profilo gestito: in alternativa `about:config` →
  `security.enterprise_roots.enabled=true` (ereditata OS) o importare la CA in
  Impostazioni → Certificati → Autorità.
- **App mobile: nessuna di queste righe la riguarda.** Il telefono non usa il
  trust store di sistema: valida l'impronta del certificato letta dal QR.
  L'installazione della CA su Android/iOS non serve e non va fatta.
- Senza trust, l'estensione passa **automaticamente** al fallback
  `ws://127.0.0.1:8080` e riprova il primario ogni ~10min (vedi popup "Engine
  connesso (fallback)"); `curl --cacert <ca.pem> https://nfc.local:8443/v1/status`
  per diagnosticare.

## IT/GPO-MDM
- Distribuire via GPO la CA (`certutil -addstore Root`) + hosts via GPP, oppure
  record DNS interno `nfc.local -> 127.0.0.1`? **No**: il DNS interno non deve
  risolvere `.local` (conflitto mDNS). Usare hosts/GPP o mDNS responder.
- **Mobile MDM non serve più per il TLS.** Non c'è da distribuire né CA né
  hostname: il pin del certificato viaggia nel QR e l'host è risolto dal
  telefono stesso con mDNS. Basta distribuire l'app.

## Troubleshooting
- `getent hosts nfc.local` → `172.0.0.1`: trappola nss-resolve, vedi sopra.
  `nfc.local` **non risolve** fuori dal namespace: è atteso, non è un bug.
- `ERR_CERT_AUTHORITY_INVALID`: CA non fidata → `./scripts/trust-ca-user.sh`
  (Linux) o store di sistema. Se usi un profilo Chromium/Firefox separato,
  reinstalla: il NSS DB è per utente.
- `DNS_PROBE_FINISHED_NXDOMAIN`: hosts mancante (admin) o search-domain che
  appende suffissi → usa FQDN con punto finale o disabilita search per `.local`.
- `ERR_CONNECTION_REFUSED :8443`: engine vecchio (<0.3) o TLS non partito →
  fallback 8080 attivo, aggiorna la tray app.
- Il telefono si connette ma resta in chiaro: il QR è stato generato **prima**
  che la PKI esistesse (il pin è facoltativo per non far fallire la rotazione),
  quindi rigenera il QR dalla tray. Controlla con `GET /v1/qr` se `tls_pin_b64`
  è presente.
- `pin TLS non corrisponde`: il QR è vecchio rispetto al certificato corrente,
  oppure qualcuno ha rigenerato la PKI. Rigenera il QR e ri-scansiona.
  La versione **localizzata** di questo caso arriva come `qrExpired` ("QR
  scaduto"), che è distinto: se leggi quello, il QR è semplicemente vecchio e non
  c'è nulla da verificare. `pinRejected` arriva solo quando il QR **non** è
  scaduto, cioè quando il certificato presentato è diverso senza spiegazione —
  e lì la rete va verificata davvero.
- Porta 8443 occupata: singola istanza Tauri la detiene; chiudi duplicati.
- `certutil` chiede la password e `trust-ca-user.sh` muore: stai su un NSS DB
  creato con password. Ricrealo vuoto
  (`rm -r ~/.pki/nssdb && certutil -d sql:$HOME/.pki/nssdb -N --empty-password`)
  e ripeti.
