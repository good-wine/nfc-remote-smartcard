# UPGRADE 2026 — cosa è cambiato e perché

## Crypto: ibrida post-quantum negoziata
- `SessionKeys::derive` classico + `derive_hybrid(x25519||mlkem768)` (ml-kem 0.3,
  FIPS 203) con domain separation `v1/v2`, `rekey()`, `sas_confirm()` a 6 cifre.
- QRv2 `NFC://2/` (`pairing.rs`): `pq`, `mlkem_b64` (1184B), accetta legacy v1.
- **Negoziazione reale**: `HandshakeInit{mlkem_ct, proto_v}` -> desktop decapsula
  e deriva ibrido (v2) o classico (v1); `HandshakeResp{proto_v}` con eco; entrambi
  verificano pubkey==QR + SAS. Mobile incapsula via `pq::encapsulate` (mobile).
- Motivo 2026: protezione harvest-now-decrypt-later. Il "classico" è il QR senza
  PQ (`v1` ancora letto in lettura), non un client con materiale chiavi vecchio.
- **Una chiave per direzione** (`Direction`): `derive`/`derive_hybrid` espandono
  64 byte e li dividono in `k_m2d`/`k_d2m`. Prima le due chiavi erano identiche
  e, con `nonce_for(seq)` senza componente di direzione e contatori che partono
  da 1, **ogni seq veniva usato due volte sotto la stessa chiave** in entrambe
  le direzioni. Rottura dell'autenticità AES-GCM, non un dettaglio: vedi
  `docs/SECURITY.md` §3. Il formato del nonce non cambia, il materiale chiavi sì.
- **`HandshakeInit.keys_v`**: l'init dichiara la versione del materiale chiavi e
  l'engine rifiuta gli init senza. Rifiutare invece di negoziare è deliberato —
  il campo viaggia in chiaro e un attaccante può rimuoverlo, ma con la
  negoziazione ciò avrebbe prodotto un downgrade silenzioso verso proprio la
  chiave unica. Con il rifiuto il risultato è un errore percepibile (4404).
- **Rifiuti con codice**: l'engine chiude con un codice WebSocket stabile
  (4400-4405, `nfc_core::protocol::close`) invece di tacere; il telefono lo
  traduce in un codice di pairing localizzato. Prima vedeva solo `Close` e il
  suo testo di default indovinava il motivo.

## Rete: Axum 0.8 + rustls, niente parser HTTP manuale
- Prima: `TcpListener` + parser header artigianale + `from_raw_socket` (fragile).
- Ora (`ws_server.rs`): `Router` Axum (`/v1/status`, `/v1/transmit` REST reale,
  `/v1/mobile`, `/v1/extension` via `WebSocketUpgrade`), `CorsLayer`, guard loopback
  su `ConnectInfo`, `MobileHub` che recapita davvero i job (fix 502 cieco).
- TLS: `native-tls` -> `rustls-tls-webpki-roots` (build riproducibili, niente OpenSSL).
- Edition Rust `2021 -> 2024`, lints workspace (`unsafe_code=forbid`, clippy pedantic),
  `thiserror 2`, `tokio 1.47`, `prost 0.14`, `mdns-sd 0.14`, `rand 0.9`.

## Desktop Tauri: updater + deep-link + JSON log
- Plugin `updater` (artefatti firmati, `createUpdaterArtifacts`), `deep-link`
  (`nfc://pair`), `os`, `single-instance` con focus; macOS min `13.0`;
  log `tracing-subscriber::fmt().json()` OTel-ready; backoff+jitter su vpcd/WS.

## Extension MV3 moderna (Chrome 131+)
- Manifest: `world: MAIN/ISOLATED` dichiarativi (niente `<script>` dinamico né
  `web_accessible_resources` per inject), `alarms` + `sidePanel`, host `127.0.0.1`.
- SW: keepalive via `chrome.alarms` (sopravvive alla sospensione), fail-fast pending
  su kill, badge stato. Bridge: solo relay + allowlist reattiva.

## Canale locale: token + consenso (2026)
- Il primo frame di `/v1/extension` è l'autenticazione: `hello` + token già
  emesso, `hello` senza token o `enroll` aprono il **consenso esplicito** nella
  tray desktop (banner Consenti/Rifiuta, TTL 120s). Prima l'accesso di un
  processo locale era una questione di sola rete (loopback + Origin).
- Il token è casuale a 32 byte, salvato dall'engine **solo come SHA-256** in
  `clients.json` (`0600`), confronto in tempo costante; l'estensione lo tiene in
  `storage.local` (mai esposto alle pagine) e lo cancella a `4406`.
- `POST /v1/transmit` e l'upgrade `/v1/extension` senza token valido -> `401` /
  close `4406 LOCAL_NON_AUTENTICATO` (nuovo codice in `nfc_core`).
- Token revocato ≠ accesso: un `hello` con token invalido **non** degrada al
  consenso; la riautorizzazione deve essere esplicita.
- `requireHttps` dell'estensione ora è **on di default**: il fallback in chiaro
  8080 resta disponibile ma va sottomesso espressamente, e anche lì il token è
  richiesto.
- UI desktop: pannello "Accessi locali" (banner richieste + lista client
  autorizzati con Revoca), comandato da `approve_consent` / `reject_consent` /
  `list_consents` / `list_clients` / `revoke_client`.

## Mobile nativo
- Android: `NfcIsoDepHandler` a coroutine + `SharedFlow<CardEvent>`,
  `EXTRA_READER_PRESENCE_CHECK_DELAY`, targetSdk 36-ready.
- iOS: `NfcBridge` Swift 6 `Sendable`, `async/await`, extended-APDU ready,
  Privacy manifest/App Attest note. QR parser accetta v1+v2.

## Webapp: WASM-first + fotocamera (2026)
- Il core `shared-core-wasm` (`wasm-bindgen`) porta nel browser la **stessa**
  validazione del telefono nativo: `parse_pairing_qr` (decodifica + check
  completo del QR v2: prefisso, base64, JSON, IP, dominio locale del `host`,
  pin TLS, scadenza) e `validate_apdu` (normalizzazione APDU client-side).
  Nessuna logica crittografica propria nel browser; asset serviti dallo stesso
  engine, **niente CDN**.
- Tab **Scanner**: fotocamera del telefono (getUserMedia + jsQR locale) per
  inquadrare il QR della tray del desktop. Il testo scansionato passa *sempre*
  dal core WASM prima di essere mostrato: un QR malformato o scaduto non viene
  mai presentato come "engine valido".
- La console pilota il lettore dal browser sul **canale locale token + consenso**
  (SECURITY.md §7): hello senza token apre il banner della tray; approvato, il
  token vive in `localStorage`; REST `/v1/transmit` lo porta come Bearer.
- Il `.wasm` è servito con MIME `application/wasm` (riga in
  `ws_server::content_type_for`, testata) e la CSP della webapp ammette la
  compilazione WASM con `'wasm-unsafe-eval'` **scoped** (niente `unsafe-eval`:
  senza quell'eccezione Chromium blocca `WebAssembly.instantiate` e il core
  non si carica — un bug che i soli unit test non vedono, servito l'e2e=engine).
- Limitazione dichiarata: il browser non può pinnare il TLS self-signed locale,
  quindi il pairing remoto (QR di un altro host) resta un caso per l'app
  nativa; la webapp fa console + scanner sull'engine che la serve.

## Supply-chain e CI
- `rust-toolchain.toml`, `deny.toml` (cargo-deny), `audit-check`, `clippy -D warnings`,
  `fmt --check`, cache sccache, `tauri-action` con firma su tag.
- Frontend: Vite 6, TS 5.9, `@tauri-apps/* ^2.5`, Node 22.

## Migrazione
1. `cargo update -p nfc-core` (prost richiede `protoc` >= 5).
1b. **Aggiorna telefono e desktop insieme**: il materiale chiavi è cambiato e
    non è negoziabile. Un mobile vecchio su engine nuovo viene rifiutato con
    4404; un mobile nuovo su engine vecchio non decifra la risposta. In entrambi
    i casi il fallimento è immediato e esplicito, non una sessione che "funziona"
    in modo peggiore.
2. Rigenera QR (v1 non più emessi, ma ancora accettati in lettura).
3. Estensione: ricarica unpacked (nuovi permessi `alarms`/`sidePanel`). Alla
   prima connessione parte il **consenso**: rispondi al banner della tray. Il
   nuovo default `requireHttps=on` vale anche per gli install esistenti che non
   avevano mai scelto (nessuna chiave salvata).
3b. Webapp: ricompila con `npm run build` (o riparti da `web/dist`). Alla prima
   apertura della console parte il **consenso**: rispondi dal desktop; il
   token viene memorizzato in `localStorage` e riconsentito solo alla revoca.
4. Sostituisci `TAURI_SIGNING_PRIVATE_KEY` + `updater.pubkey` (`TODO-BASE64...`).
