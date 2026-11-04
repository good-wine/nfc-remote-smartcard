# AGENTS.md

NFC Remote Smartcard — open-core monorepo: a smartphone acts as a remote NFC smartcard reader for the PC. Docs, code comments and user-facing error strings are Italian; keep that convention when editing.

## Architecture

- Rust workspace (`Cargo.toml`): `nfc-core` (`shared-core-rust/` — PQ crypto, wire protocol, QRv2 pairing, mDNS), `nfc-desktop` (`desktop/src-tauri/` — tray engine, WS/HTTPS server, vpcd adapter), `nfc-mobile` (`mobile/src-tauri/` — E2EE client + native NFC bridge), `nfc-core-wasm` (`shared-core-wasm/` — QR/APDU validation for the browser). `fuzz/` is a separate nightly-only crate: excluded from the workspace and from CI.
- Engine binary: `nfc-desktop` (tray) / `nfc-desktop --daemon` (headless — what tests and CI use). More CLI flags: `--setup-local-domain`, `--rotate-ca` (`main.rs`). Ports: plain HTTP 8080 loopback-only, HTTPS/WSS 8443 on `nfc.local` + subdomains (PKI auto-generated on first start under `~/.config/nfc-remote/`), vpcd-stub 127.0.0.1:35963. The engine also serves `web/dist` at `/app` (`/` is a JSON services landing).
- Two local channels: mobile uses E2EE `/v1/mobile` (X25519+ML-KEM-768, cert pinned from QR); extension/webapp use JSON `/v1/extension` with per-client token + explicit tray consent (close `4406` on refusal; a revoked token never silently re-consents). Contract: `docs/API_SPEC.md`, `docs/SECURITY.md` §7, TLS/domain details in `docs/LOCAL-DOMAIN.md`.
- `shared-ui-ts` is consumed by relative path (`mobile/src` imports `../../shared-ui-ts/src/*.js`), not as a package. `browser-extension` mirrors i18n/types by hand (`src/shared/i18n.ts`). `web/` has its own inline client and does not import shared-ui-ts.
- Pairing error codes are a hand-written Rust↔TS contract: `mobile/src-tauri/src/lib.rs` (`pub mod code`) ↔ `shared-ui-ts/src/i18n.ts` + `pairing-errors.ts`. Check with `node scripts/check-pairing-codes.mjs` (repo root).

## Commands

Rust — CI is authoritative (`.github/workflows/ci.yml`):
- `cargo fmt --all --check`
- `cargo test -p nfc-core --all-features` — `cargo test -p nfc-desktop --all-features` — `cargo test -p nfc-core-wasm` (host tests of the wasm crate)
- `cargo clippy --workspace --all-features -- -D warnings`
- Single test: `cargo test -p nfc-desktop --lib local_auth::tests`, integration tests live in `desktop/src-tauri/tests/` (e.g. `--test extension_auth`, `--test vpcd_stub_roundtrip`)
- Linux prereqs: `protobuf-compiler libpcsclite-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf` (`--all-features` enables `physical`, which needs libpcsclite).
- Prefer these targeted suites over the README's `cargo test --workspace` (which also builds the mobile crate; CI never runs it).

Security guard (grep-enforced cross-crate invariants + targeted tests): `bash scripts/guard-security-2026.sh`. `SKIP_CLIPPY=1` skips the heavy lint step (CI runs clippy separately first).

Frontend (each subproject is its own npm project with its own `package-lock.json`; use npm inside each dir, CI uses `npm ci`):
- Web: `cd web && npm install && npm run build` = `build:wasm` + `tsc --noEmit` + vite. One-time: `rustup target add wasm32-unknown-unknown` and `cargo install wasm-bindgen-cli --version 0.2.129 --locked` (must match `Cargo.lock`; CI pins 0.2.129). `web/src/wasm/` is generated glue — never edit by hand.
- Web E2E: `bash scripts/test-webapp.sh` starts `target/debug/nfc-desktop --daemon` and runs Playwright against it (needs the engine CA; env: `NFC_CA`, `NFC_BASE`, `NFC_SKIP_NAMESPACE=1`). Headless environments need `xvfb-run`. Without engine: `cd web && node tests/wasm.core.spec.mjs`.
- Extension: `cd browser-extension && npm run build` must precede `npm run test:e2e` (Playwright loads `dist/` unpacked). `npm run lint` = `tsc --noEmit`; `npm run zip` packages the store bundle.
- Dev stack: `bash scripts/start-all.sh [--daemon]` (engine + vite on 1420), plus `start-all.sh stop|status`. `--daemon` deliberately avoids the `nfc-engine.service` systemd user unit so dev/tests don't disturb an installed service.
- Full build: `bash scripts/build-all.sh`; `NFC_SKIP_E2E=1` skips the e2e step.

## Gotchas

- Workspace lints forbid `unsafe_code` and enable clippy pedantic; keep both green, including the WASM glue path.
- `nfc-core` gates `mdns`/`net` behind feature `net`: they must not be enabled/imported for wasm32 (mio/socket2 don't compile there).
- `guard-security-2026.sh` greps exact strings that no compiler protects: TLS13-only clauses in `local_tls.rs`/`tls_pin.rs`, `aws_lc_rs` + `prefer-post-quantum` in both Cargo.toml, SHA-256 + constant-time + 0600 in `local_auth.rs`, close code 4406, loopback-only bind of the plaintext 8080 channel (`plain_bind_addr`/`is_loopback` in `ws_server.rs`), MIME `application/wasm` + CSP `wasm-unsafe-eval`, extension `requireHttps: true` + hello-token flow, `parsePairingQr` in the webapp. It also runs `node scripts/check-pairing-codes.mjs` for the Rust↔TS pairing-code contract. Renaming/removing any of these fails the guard even when everything compiles.
- The webapp must validate QR/APDU through the WASM core (`parse_pairing_qr`, `validate_apdu`); a JS-side check is a regression.
- `mobile/gen/{android,ios}` holds the hand-written native bridges (`NfcIsoDepHandler.kt`, `NfcBridge.swift`); it is tracked on purpose — treat it as source, never regenerate or clean over it. Integration into the generated native projects (manifest/tech-filter fragments, `Info.ios.plist`, event/reply contract) is documented in `mobile/gen/README.md`.
- `nfc.local` resolution trap: `getent hosts nfc.local` → `172.0.0.1` means systemd-resolved is intercepting; use `scripts/with-nfc-local.sh <cmd>` (rootless mount namespace) or the `https://localhost:8443` fallback. Tests use Chromium `--host-resolver-rules` + `ignoreHTTPSErrors`, not root.
- Systemd user units hardcode install-time paths: after moving the repo, re-run `scripts/install-engine-linux.sh` (and/or `scripts/install-vpcd-linux.sh`) — `nfc-engine.service` otherwise crash-loops with `203/EXEC`. `scripts/start-all.sh` now warns when the unit points to a missing binary.
- Ignored/runtime output: `target/`, `web/dist/`, `web/src/wasm/`, `browser-extension/dist/`, `browser-extension/dist-tmp/`, `.logs/`, `.run/`, `desktop/src-tauri/gen/`, `mobile/src-tauri/gen/`.
