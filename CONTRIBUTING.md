# Contribuire a NFC Remote

Grazie per l'interesse. Questa pagina copre il minimo per contribuire con una
PR accettabile: setup, workflow, test e requisiti.

I **dettagli operativi** (mappa del monorepo, comandi per ogni sottoprogetto,
gotcha su WASM/systemd/`nfc.local`, invarianti del guard) stanno in
[`AGENTS.md`](AGENTS.md): leggilo prima di toccare più di un componente.
Il **perché** delle scelte architetturali sta in [`docs/`](docs/).

## Prima di iniziare

- **Bug?** Apri una [issue](https://github.com/nfc-remote/nfc-remote/issues/new/choose) con il template *Bug report*.
- **Vulnerabilità?** **Non** aprire issue o PR pubbliche: segui [`SECURITY.md`](SECURITY.md).
- **Funzionalità nuova?** Apri una *Feature request* e discutiamola prima di scrivere codice: evita PR lunghe da rifare.

## Prerequisiti

- Rust **stable ≥ 1.85** (edition 2024). La toolchain è pinnata in `rust-toolchain.toml`.
- Node **≥ 20** (la CI usa 22), `npm` in ogni sottoprogetto frontend.
- Tauri CLI v2 (solo se lavori su `desktop/`/`mobile/`).
- Android Studio (SDK 34) e/o Xcode 15+ solo per `mobile/`.

Linux, pacchetti di sistema:

```bash
sudo apt-get install -y protobuf-compiler libpcsclite-dev libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev librsvg2-dev patchelf
```

`libpcsclite-dev` serve per `--all-features` (abilita la feature `physical` del
desktop). Per la webapp servono in più il target WASM e `wasm-bindgen-cli`
pinnato alla versione di `Cargo.lock`:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
```

In alternativa c'è il container dev: `.devcontainer/`.

## Setup e primo test verde

```bash
git clone <repo> && cd nfc
cargo build -p nfc-desktop          # engine: è il binario che usano test ed e2e

# il primo test verde, il più veloce
cargo test -p nfc-core --all-features
```

Per lo stack completo in sviluppo: `bash scripts/start-all.sh` (engine + Vite su
1420); `bash scripts/start-all.sh stop|status` per fermarlo o ispezionarlo.

## Comandi di verifica

Esegui i comandi dell'area che tocchi. La **CI è autorevole**: se un comando
passa in locale ma non in CI (o viceversa), vale la CI
(`.github/workflows/ci.yml`).

Rust — obbligatori su ogni PR che tocca codice Rust:

```bash
cargo fmt --all --check
cargo test -p nfc-core -p nfc-desktop -p nfc-core-wasm --all-features
cargo clippy --workspace --all-features -- -D warnings
```

I tre crate si testano **separatamente** di proposito: `--workspace` include
anche il mobile e non è quello che gira in CI. Il crate WASM ha test host
(`parse_pairing_qr`, `validate_apdu`) che vanno eseguiti anche nativamente.
Test singoli: `cargo test -p nfc-desktop --lib local_auth::tests`; gli
integrativi vivono in `desktop/src-tauri/tests/` (`--test extension_auth`,
`--test vpcd_stub_roundtrip`).

Guard di sicurezza e contratto dei codici di pairing:

```bash
bash scripts/guard-security-2026.sh        # SKIP_CLIPPY=1 se hai già girato clippy
node scripts/check-pairing-codes.mjs
```

`guard-security-2026.sh` verifica (via grep) invarianti cross-crate che nessun
compilatore protegge: TLS 1.3-only, PQ, token/consenso, close `4406`, loopback
del canale 8080, MIME `application/wasm`, validazione QR in WASM. **Non**
"aggiustare" il guard per far passare una modifica: se un'invariante va cambiata,
cambia il guard nella stessa PR e motivalo.

Frontend (dentro ogni sottoprogetto: ognuno ha il proprio `package-lock.json`):

```bash
cd web              && npm ci && npm run build          # build:wasm + tsc + Vite
cd browser-extension && npm ci && npm run lint && npm run build
cd browser-extension && npm run test:e2e                # richiede la build sopra
cd mobile           && npm ci && npm run build
```

Webapp contro l'engine reale (serve il binario `target/debug/nfc-desktop`):

```bash
bash scripts/test-webapp.sh                 # headless: xvfb-run -a bash scripts/test-webapp.sh
cd web && node tests/wasm.core.spec.mjs     # solo core WASM, senza engine
```

## Workflow Git

- Il branch di integrazione è `main`. Lavora su un branch dedicato, mai su `main`.
- Convenzione branch: `feat/<slug>`, `fix/<slug>`, `docs/<slug>`, `chore/<slug>`.
- Commit piccoli e con un solo intento; rebase invece di merge dal branch remoto.
- **Conventional Commits obbligatori** — il changelog delle release è generato
  da questi (`cliff.toml`): `feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
  `chore:`, `ci:`.
- Niente `git push --force` sui branch condivisi; niente segreti, `.env` o
  credenziali nel diff (il push non è protetto da questo).

## Requisiti di una pull request

Usa il template: la checklist è la definizione di "pronta per la review".

- descrizione con il **perché** del cambiamento (non solo il cosa);
- comandi eseguiti e **esito reale**; una PR senza i test pertinenti non entra;
- impatto sulla sicurezza dichiarato (guard e `check-pairing-codes.mjs`);
- documentazione aggiornata se cambia un contratto o un comportamento visibile;
- titolo in Conventional Commits, coerente con i commit;
- una PR = una cosa: niente refactor misti a fix.

### Aree ad alto rischio

Cambi in queste aree richiedono review più scrupolosa e, se non sei maintainer,
una discussione preventiva:

- `shared-core-rust/` — crittografia, wire protocol, pairing, APDU;
- `shared-ui-ts/` — contratti TS condivisi col mobile;
- `mobile/gen/` — bridge nativi (`NfcIsoDepHandler.kt`, `NfcBridge.swift`):
  **sorgente**, mai rigenerati o puliti;
- `scripts/guard-security-2026.sh` e `deny.toml`/`Cargo.toml` — postura di
  sicurezza e supply-chain.

Il file [`.github/CODEOWNERS`](.github/CODEOWNERS) assegna i revisori per area.

### Modifiche che cambiano il protocollo

Un cambiamento a E2EE, formato del QR di pairing o canale locale è un
**cambiamento di contratto**: aggiorna `docs/ARCHITECTURE.md` e
`docs/SECURITY.md`, e motivalo (idealmente con un ADR). I client vecchi non
devono mai degradare in silenzio: il progetto preferisce rifiutare con un codice
stabile, come documentato in `docs/SECURITY.md` §6.

## Estendere i test

La suite standard deve restare **veloce e deterministica**: fuzz e mutation
testing girano fuori dalla pipeline di PR.

Fuzz (`fuzz/` è un crate separato, escluso dal workspace; richiede nightly e
`cargo-fuzz`) — target esistenti: `vpcd_frame`, `wire_frame`, `pairing_qr`.

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run wire_frame -- -max_total_time=120   # dalla root del repo
```

Un nuovo target va aggiunto in `fuzz/fuzz_targets/` + `fuzz/Cargo.toml` e alla
matrice di `.github/workflows/fuzz.yml`. Un crash di fuzz si riproduce sempre
dall'input salvato in `fuzz/artifacts/`: allega l'input alla PR di fix.

Mutation testing (`cargo-mutants`, mirato su `nfc-core`): i mutanti sopravvissuti
sono un finding — un'assert troppo debole — non un fallimento da ignorare. Vedi
`.github/workflows/mutants.yml`.

Mutation testing e fuzz sono gli unici controlli che dicono *quale* proprietà una
modifica indebolisce: se aggiungi logica di confronto o di parsing, aggiungi il
test che **fallirebbe** se la si rompesse.

## Stile

- Segui stile e pattern del codice circostante; modifiche minime e mirate.
- Rust: `unsafe_code` è vietato a livello di workspace e clippy pedantic è attivo;
  `cargo fmt` non è negoziabile.
- Non aggiungere dipendenze senza necessità: preferisci la libreria standard.
  Una nuova dipendenza passa da `cargo-deny` e dal review della supply-chain.
- Non modificare a mano file generati o vendor (`web/src/wasm/`, `*/dist*`,
  `Cargo.lock` a mano).
- Documentazione, commenti e **stringhe d'errore rivolte all'utente sono in
  italiano**; identificatori, branch e commit in inglese.

## Rilascio (solo maintainer)

Le release nascono da un tag `v*`: la pipeline costruisce e firma i bundle, poi
genera changelog, SBOM e attestazioni (`.github/workflows/release.yml`). Non si
edita il changelog a mano: se manca una voce, si correggono i commit.

## Riferimenti

- [`AGENTS.md`](AGENTS.md) — mappa del monorepo e comandi operativi
- [`README.md`](README.md) — panoramica e stack di sicurezza
- [`docs/SECURITY.md`](docs/SECURITY.md) — modello tecnico di sicurezza
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architettura di sistema
- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — la verifica che conta
