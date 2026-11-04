<!--
Grazie per la PR. Tieni la descrizione breve e concreta: il "perché" conta più
del "cosa". Compila la checklist qui sotto e cancella le righe non applicabili
(es. quelle frontend se tocchi solo Rust).
-->

## Descrizione

<!-- Cosa cambia e perché. Se chiude una issue: "Closes #123". -->

## Tipo di cambiamento

- [ ] `feat` — nuova funzionalità
- [ ] `fix` — correzione di un bug
- [ ] `refactor` — modifica senza cambi di comportamento
- [ ] `docs` — sola documentazione
- [ ] `test` — test nuovi o aggiornati
- [ ] `chore` / `ci` — build, tooling, dipendenze
- [ ] **breaking change** (descrivi l'impatto e la migrazione qui sotto)

## Test eseguiti

Indica i comandi eseguiti e l'esito reale (non "dovrebbe funzionare"). Quelli
sotto sono i comandi del repo, da `AGENTS.md`/`.github/workflows/ci.yml`.

Rust:

- [ ] `cargo fmt --all --check`
- [ ] `cargo test -p nfc-core -p nfc-desktop -p nfc-core-wasm --all-features`
- [ ] `cargo clippy --workspace --all-features -- -D warnings`

Frontend (solo se tocchi `web/`, `browser-extension/`, `mobile/`, `shared-ui-ts/`):

- [ ] `cd web && npm ci && npm run build`
- [ ] `cd browser-extension && npm ci && npm run lint && npm run build`
- [ ] `cd browser-extension && npm run test:e2e`
- [ ] `bash scripts/test-webapp.sh` (oppure `cd web && node tests/wasm.core.spec.mjs` senza engine)

## Impatto sulla sicurezza

- [ ] **Nessun impatto** sui confini di sicurezza.
- [ ] Ho eseguito `bash scripts/guard-security-2026.sh` (con `SKIP_CLIPPY=1` se hai già girato clippy sopra): **guard verde**.
- [ ] Ho eseguito `node scripts/check-pairing-codes.mjs`: **contratto Rust↔TS allineato**.
- [ ] Ho modificato una proprietà coperta dal guard (TLS 1.3-only, PQ, token/consenso, `4406`, loopback 8080, MIME `application/wasm`, `parsePairingQr`): i guard aggiornati sono in questa PR.
- [ ] Ho modificato i codici di errore di pairing su **un solo lato**: la PR aggiorna anche l'altro.

> Se qualcosa qui non è chiaro, parti da [`docs/SECURITY.md`](docs/SECURITY.md).
> Per una vulnerabilità **non aprire una PR**: segui [`SECURITY.md`](SECURITY.md).

## Documentazione

- [ ] README/guide aggiornati se il comportamento visibile all'utente è cambiato.
- [ ] `docs/` aggiornato se è cambiato un contratto o un'invariante.
- [ ] ADR aggiunto se la PR introduce una decisione architetturale.
- [ ] Non serve documentazione (modifica interna senza impatto osservabile).

## Convenzioni

- [ ] Titolo della PR in **Conventional Commits** (`feat:`, `fix:`, `docs:`, …).
- [ ] Commit conformi a Conventional Commits (il changelog è generato da questi).
- [ ] Niente segreti, token, file `.env` o chiavi private nel diff.
- [ ] Ho letto [`CONTRIBUTING.md`](CONTRIBUTING.md).
