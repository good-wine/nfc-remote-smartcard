# Deployment — B2C / B2B / IT

## B2C / B2Pro (zero-friction)
1. Utente installa tray app (MSI/DMG/AppImage) -> post-install avvia `vpcd` silenzioso.
2. Apre tray -> mostra QR -> scansiona da mobile -> E2EE attiva.
3. Installa estensione da store -> auto-connessa a localhost:8080 -> login PA/CIE.
- mDNS riconnette senza ri-scansionare (stesso Wi-Fi).

## B2B / Dev (webapp e gestionali)
- Webapp/PWA (`web/`) servita dall'engine: console APDU, scanner QR da fotocamera,
  canale locale con token + consenso (vedi `web/README.md` e `API_SPEC`).
- Estensione: localhost WS (:8080, loopback-only) con lo stesso token/consenso.

## IT aziendali (headless, GPO/MDM)
- Flag `nfc-desktop --daemon` (no tray, no QR UI).
- Rotazione CA: `nfc-desktop --rotate-ca` **a engine fermo**, poi ridistribuire
  la fiducia (GPO `certutil -addstore Root`, MDM macOS, `update-ca-certificates`).
  Le sessioni E2EE esistenti non si interrompono (chiavi indipendenti dai cert).
  Il comando **rifiuta** se l'engine è in esecuzione: l'engine tiene in memoria il
  certificato con cui serve il TLS, mentre il pin dei QR lo rileggerebbe da disco.
  Ruotando sotto un engine attivo ogni QR nuovo porterebbe l'impronta del
  certificato nuovo e il server presenterebbe quello vecchio — ogni pairing
  fallirebbe con "pin non corrisponde", che è anche l'errore di un attacco, e
  rigenerare il QR non aiuterebbe. L'engine prende `engine.lock` nel profilo
  all'avvio e lo rilascia all'uscita; se il file resta dopo un crash, il
  messaggio del rifiuto lo nomina ed è sufficiente cancellarlo.
- Lettore fisico: build con `--features physical` (serve libpcsclite) per
  pubblicare anche reader USB/NFC diretti quando `vpcd` è assente.
- Distribuzione massa:
  - Windows: `msiexec /i nfc-desktop.msi /quiet VPCD_AUTOSTART=1` + GPO Registry `HKLM\Software\NFCRemote\Daemon=1`.
  - macOS: `nfc-desktop.dmg` + profilo MDM (launchd `it.nfcremote.daemon.plist`).
  - Linux: `.deb`/AppImage + systemd user unit `nfc-desktop.service`.
- VPN: se LAN bloccata, abilitare WebRTC fallback (`--webrtc`, solo host candidate) o split-tunnel per 8080.
- Log centralizzati: `RUST_LOG=info` -> syslog/journald.

## Firewall — accesso dal telefono in LAN
Se il firewall di sistema blocca l'ingresso (es. `ufw` attivo con default
`deny incoming`), l'engine ascolta su `*:8443` ma i device LAN non lo
raggiungono. Aprire **solo** il canale TLS, mai il legacy:

```bash
sudo ./scripts/autoconfigure-firewall.sh     # idempotente, multi-backend
# ./scripts/autoconfigure-firewall.sh        # senza sudo: dry-run
```

Cosa applica (e niente altro):
- TCP **8443** da RFC1918 (`10/8`, `172.16/12`, `192.168/16`) + ULA/link-local (IPv6):
  pairing E2EE e console. Il QR porta il **pin TLS**: anche un host LAN ostile
  non può fare MITM (la app valida pin+certificato).
- UDP **5353** da LAN: mDNS, solo discovery `_smartcard-nfc`; il trasporto E2EE
  non usa mai mDNS.
- **8080 resta bound a 127.0.0.1** e non viene mai aperto; SSH/altre regole
  intatte.
Sintonia fine: `NFC_REMOTE_LAN="192.168.188.0/24"` per restringere, 
`NFC_REMOTE_IFACE="enp10s0"` per vincolare a una interfaccia.

## Deep-link `nfc://pair`
Il listener è nel codice (`on_open_url`); la registrazione OS dello scheme
è compito dell'installer (Tauri non la deduce dal codice):
- Linux: `MimeType=x-scheme-handler/nfc;` nel `.desktop` + `xdg-mime default`.
- Windows: chiave `HKCU\Software\Classes\nfc\shell\open\command` (MSI/WiX).
- macOS: `CFBundleURLTypes` nel bundle (solo con `tauri build`, non `cargo run`).

## vpcd — lettore virtuale (adapter v1)
L'engine parla su `127.0.0.1:35963` un protocollo **definito dal progetto**
(adapter v1: `len BE32 || cmd || payload`, comandi PowerOn/Off/Transmit/
GetStatus in `desktop/src-tauri/src/vpcd.rs`). Il demone `vpcd` di
vsmartcard usa un protocollo diverso e **non** può rispondere: il server
compagno è il binario `vpcd-stub` nel crate desktop (stessa crate = stessa
fonte di verità via `decode_request`).
- Linux: `scripts/install-vpcd-linux.sh` compila e installa `vpcd-stub` come
  systemd user service (nessun root per lo stub, loopback puro). `pcscd` resta
  solo per il probe `physical` sui reader USB.
- Windows: `scripts/install-vpcd-windows.ps1` (Amministratore, da radice repo):
  build dello stub e registrazione come Scheduled Task di sistema all'avvio
  (è una console app, non un servizio nativo); firewall invariato, solo
  loopback.
- macOS: `scripts/install-vpcd-macos.sh`: build dello stub, copia in
  `/usr/local/bin/vpcd-stub`, LaunchDaemon con `--host 127.0.0.1 --port 35963`.
