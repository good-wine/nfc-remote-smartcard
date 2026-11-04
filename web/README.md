# Webapp / PWA — WASM-first, mobile-browser-only

Una sola webapp installabile (PWA) che fa da **client desktop** e da **console
mobile**, servita dall'engine stesso: nessun server extra, nessun deploy,
**nessun CDN** (asset WASM/JS/CSS serviti dallo stesso dominio).

## Ruoli

| Ruolo | Come si usa |
|---|---|
| Desktop web | apri `https://nfc.local:8443/app` in un browser |
| Mobile web / PWA | stesso URL `/app` dal telefono + "Installa" (fotocamera per il QR) |
| Nativo (Tauri) | tray app — resta il canale E2EE `/v1/mobile` |

La webapp **non sostituisce** le app native per la smartcard: il canale E2EE
`/v1/mobile` (X25519 + ML-KEM-768) resta sulle app native (Kotlin/Swift hanno
l'NFC hardware, il browser no, e soprattutto il browser non può **pinnare** il
TLS locale). La webapp parla col motore sul canale JSON `/v1/extension`, con il
**token + consenso** del canale locale 2026 (`docs/SECURITY.md` §7).

## Core in WASM (`shared-core-wasm`)

Il modulo `nfc-core-wasm` (crate `wasm-bindgen`) espone al browser la **stessa**
validazione del telefono nativo:

- `parse_pairing_qr(text)` — decodifica + validazione completa del QR di pairing
  (prefisso, base64, JSON, versioni, lunghezze, IP, dominio locale del `host`,
  pin TLS, scadenza): un QR malformato o ostile viene rifiutato qui, prima che
  la UI lo mostri come "engine valido";
- `validate_apdu(hex)` — decodifica + normalizzazione APDU lato client, così la
  console non spedisce hex invalidi all'engine.

La vignetta "Scanner" inquadra il QR della tray col telefono (fotocamera +
`jsQR`, libreria locale), e il testo passa **sempre** dal core WASM prima di
essere mostrato. Dal test `wasm.core.spec.mjs` gli stessi casi dei test Rust
vengono eseguiti in browser, paro paro.

## Canale locale: token + consenso

- Al primo accesso la webapp manda `hello` senza token: l'engine apre il banner
  **Consenti** nella tray del desktop; approvato, consegna un token che la
  webapp tiene in `localStorage` (`nfcLocalToken`).
- Con un token salvato il `hello` lo presenta: niente consenso finché il token
  è valido. Token revocato = il canale non degrada mai al consenso: riapprova
  esplicitamente.
- `POST /v1/transmit` (fallback REST quando il WS non è disponibile) porta il
  token come `Authorization: Bearer`.

## Sviluppo

```bash
npm install
npm run dev            # http://localhost:5173, API proxata a 127.0.0.1:8080
```

Il core WASM richiede due prerequisiti una tantum:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked  # versione da Cargo.lock
```

## Build

```bash
npm run build          # build:wasm (cargo + wasm-bindgen) + tsc + vite -> web/dist
```

L'engine serve `web/dist` automaticamente (`.wasm` con MIME `application/wasm`).
Percorsi:

- `https://nfc.local:8443/app` — webapp (anche `/app/`)
- `https://nfc.local:8443/` — landing JSON dei servizi
- `https://nfc.local:8443/pair` — pagina QR minimale (no JS)
- override con `NFC_WEB_DIST=/percorso/altro`

Se `web/dist` non esiste, `/app` risponde 503 con le istruzioni di build
invece di un 404 silenzioso.

## Note di sicurezza

- **CSP restrittiva**: `script-src 'self' 'wasm-unsafe-eval'` (la sola eccezione
  è la compilazione del modulo WASM; niente `unsafe-eval`), `img-src` con
  `data:` (serve il PNG del QR inlined), `frame-ancestors 'none'`.
- **Service worker**: cache solo lo shell. `/v1/*` e `/pair` sono sempre
  rete — stato carta e risposte APDU non devono mai essere servite da cache.
- **`index.html` e `sw.js`** hanno `Cache-Control: no-store`, gli asset in
  `assets/` sono `immutable` (il nome contiene l'hash del contenuto).
- **Fotocamera**: il QR scansionato è validato dal core WASM; un QR di un altro
  host non abilita la console (il browser non può pinnare il TLS locale — per
  il pairing remoto resta l'app nativa).

## Test

```bash
../scripts/test-webapp.sh          # end-to-end contro l'engine (Playwright)
node tests/wasm.core.spec.mjs      # core WASM nel browser, senza engine
```

- `wasm.core.spec.mjs` serve `web/dist` con un mini server `application/wasm` e
  verifica che il modulo si carichi davvero, i casi `parse_pairing_qr` /
  `validate_apdu` e il flusso Scanner via UI — **non richiede l'engine**.
- `webapp.spec.mjs` (dello script e2e) ora copre anche il **consenso locale**:
  la console rifiuta la transazione con "consenso in attesa" finché il banner
  della tray non viene approvato.

## Struttura

```
web/
  index.html              shell unico, quattro tab (Accoppa / Scanner / Console / Stato)
  src/main.ts             logica: QR, scanner, console APDU, token/consenso, PWA
  src/scanner.ts          fotocamera: getUserMedia + jsQR, feed al core WASM
  src/wasm/               glue generato da wasm-bindgen (via scripts/build-wasm.sh)
  src/style.css           mobile-first, due colonne da 900px
  src/env.d.ts            BeforeInstallPromptEvent (non è in lib.dom.d.ts)
  scripts/build-wasm.sh   cargo + wasm-bindgen -> src/wasm
  public/                 manifest, sw.js, icone PWA
  tests/webapp.spec.mjs   smoke test Playwright (engine e2e)
  tests/wasm.core.spec.mjs test del core WASM (senza engine)
```

Il client WS/token è inline in `src/main.ts`: la webapp non importa
`shared-ui-ts`, che resta la fonte di tipi e codici per l'app mobile (import
per path) ed è specchiata a mano dall'estensione.