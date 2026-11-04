# NFC Remote Smartcard — Monorepo Open-Core
# Trasforma lo smartphone in lettore NFC remoto universale per PC.

## Struttura
- `shared-core-rust/` — engine crittografico, protocollo, pairing QRv2, mDNS, transport (Rust puro, riusato da desktop/mobile).
- `shared-core-wasm/` — lo stesso core compilato in WASM (`wasm-bindgen`) per la webapp: validazione QR + APDU nel browser, niente CDN.
- `desktop/` — Tauri 2.0 desktop (tray + engine + vpcd adapter + WS :8080/8443 + QR/mDNS).
- `mobile/` — Tauri 2.0 mobile (Svelte/TS + bridge Kotlin IsoDep + Swift CoreNFC).
- `web/` — webapp/PWA WASM-first: console APDU, scanner QR da fotocamera, token+consenso (canale locale).
- `browser-extension/` — WebExtension Manifest V3 (SW + content + popup).
- `shared-ui-ts/` — tipi TS condivisi + client WS (token/consenso) + helper APDU.
- `scripts/` — build end-to-end, servizi systemd user (engine + vpcd-stub), guard di sicurezza 2026, test webapp.
- `docs/` — API spec, sicurezza, deployment, architettura (`ARCHITECTURE.md`).

## Stack sicurezza (2026)
- E2EE ibrido post-quantum: X25519 + **ML-KEM-768**, HKDF-SHA256 → AES-256-GCM; TLS 1.3-only con KEX PQ (`aws-lc-rs`).
- QR pairing v2: `{ip, host, tls_pin, port, nonce, pubkey, pq, exp}`. Nessuna chiave statica.
- Canale locale (estensione/webapp): token per-client con **consenso esplicito** nella tray, store solo SHA-256 (`clients.json` 0600), close `4406` al rifiuto, niente downgrade.
- mDNS `_smartcard-nfc._tcp.local` solo per discovery, mai per scambio chiavi.

## Sviluppo rapido
```bash
./scripts/build-all.sh
cargo test -p nfc-core -p nfc-desktop -p nfc-core-wasm --all-features
bash scripts/guard-security-2026.sh     # postura TLS13/PQ + invarianti auth/WASM
cd web && npm install && npm run build  # build:wasm + Vite -> dist
cd browser-extension && npm install && npm run build
```

## Requisiti
- Rust stable >= 1.85 (edition 2024), Node >= 20, Tauri CLI v2, Android Studio (SDK 34), Xcode 15+.
- Linux: `libpcsclite-dev`, `libgtk-3-dev`, `webkit2gtk-4.1`.
