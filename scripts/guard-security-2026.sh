#!/usr/bin/env bash
# Guard di sicurezza 2026: la postura TLS13+PQ e l'autenticazione del canale
# locale (token + consenso) sono proprietà cross-crate incarnate da stringhe,
# testerò che nessuna modifica le smonti in silenzio.
#
# Perché un guard e non solo i test:
# - la clausola runtime `with_protocol_versions(&[TLS13])` esiste in entrambi i
#   grafi, ma nel grafo mobile `tls12` è spento a Cargo: una mutazione lì non
#   è osservabile dai test (nessuna suite può fallire su un percorso morto);
# - una rinomina cancellerebbe ora la differenza fra un client autorizzato e
#   uno estraneo SENZA un errore di compilazione lato TypeScript (estensione)
#   né lato wire (i JSON sono stringhe).
#
# Verifica (fail-fast, grep testuali + i test mirati):
#   1. clippy -D warnings e fmt --check
#   2. pin runtime TLS13-only in mobile e desktop
#   3. `prefer-post-quantum` + `aws-lc-rs` nei Cargo di entrambi i grafi
#   4. auth: SHA-256 + tempo costante + file 0600 nel registro locale
#   5. close code 4406 presente in `protocol` e usato da `ws_server`
#   6. default `requireHttps=true` + token/consenso nel SW dell'estensione
#   7. i test mirati (local_auth, extension_auth, TLS server/client, REST 401)
#   8. webapp WASM: MIME `application/wasm`, build:wasm cablata, QR validato dal
#      core Rust nel browser (mai fidato a stringa), client TS hello+token.
#   9. vpcd: adapter v1 con compagno server (framing + round-trip client<->stub
#      e installers Win/macOS/Linux allineati: nessuna dipendenza da demone esterno).
#  10. engine: systemd user service (nfc-engine) così il processo NON muore
#      quando il reaper della shell/comando di lancio termina.
#  11. engine: bind del piano in chiaro solo su 127.0.0.1 (strutturale) e
#      contratto codici pairing Rust<->TS (scripts/check-pairing-codes.mjs).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$HOME/.local/node/bin:$PATH"

# Convenzione: il guard gira coi test ma si può invitare a saltare il lungo
# `cargo clippy --all-targets` (CI lo esegue comunque) con SKIP_CLIPPY=1.
SKIP_CLIPPY="${SKIP_CLIPPY:-0}"
fail() { echo "GUARD-FAIL: $*" >&2; exit 1; }
check_grep() { # check_grep <desc> <pattern> <file>
  local desc="$1" pat="$2" file="$3"
  if ! grep -qE "$pat" "$file"; then
    fail "$desc — atteso '$pat' in $file"
  fi
  echo "  ✓ $desc"
}

check_nogrep() { # check_nogrep <desc> <pattern> <file>
  local desc="$1" pat="$2" file="$3"
  if grep -qE "$pat" "$file"; then
    fail "$desc — NON atteso '$pat' in $file"
  fi
  echo "  ✓ $desc"
}

echo "== Guard sicurezza 2026 =="

echo "-- [1] lints --"
if [ "$SKIP_CLIPPY" = "0" ]; then
  (cd "$ROOT" && cargo fmt --all --check) || fail "fmt --check"
  (cd "$ROOT" && cargo clippy -p nfc-desktop -p nfc-core -p nfc-mobile --all-targets \
    -- -D warnings) || fail "clippy -D warnings"
  echo "  ✓ fmt + clippy"
else
  echo "  (SKIP_CLIPPY=1: lints saltati)"
fi

echo "-- [2] TLS runtime: solo TLS 1.3 nei due grafi --"
check_grep "mobile: clausola TLS13-only" \
  'with_protocol_versions\(&\[&rustls::version::TLS13\]\)' \
  "$ROOT/mobile/src-tauri/src/tls_pin.rs"
check_grep "desktop: clausola TLS13-only" \
  'with_protocol_versions\(&\[&rustls::version::TLS13\]\)' \
  "$ROOT/desktop/src-tauri/src/local_tls.rs"

echo "-- [3] KEX ibrido post-quantum nei Cargo --"
check_grep "mobile: prefer-post-quantum" 'prefer-post-quantum' \
  "$ROOT/mobile/src-tauri/Cargo.toml"
check_grep "mobile: aws-lc-rs (provider rustls)" 'aws_lc_rs' \
  "$ROOT/mobile/src-tauri/Cargo.toml"
check_grep "desktop: prefer-post-quantum" 'prefer-post-quantum' \
  "$ROOT/desktop/src-tauri/Cargo.toml"
check_grep "desktop: aws-lc-rs (provider rustls)" 'aws_lc_rs' \
  "$ROOT/desktop/src-tauri/Cargo.toml"

echo "-- [4] registro locale: hash + tempo costante + 0600 --"
check_grep "SHA-256 del token" 'Sha256' \
  "$ROOT/desktop/src-tauri/src/local_auth.rs"
check_grep "confronto a tempo costante" 'constant_eq' \
  "$ROOT/desktop/src-tauri/src/local_auth.rs"
check_grep "constant_eq è XOR-fold (niente early-exit)" 'acc \| \(x \^ y\)' \
  "$ROOT/desktop/src-tauri/src/local_auth.rs"
check_grep "clients.json a 0600" 'mode\(0o600\)' \
  "$ROOT/desktop/src-tauri/src/local_auth.rs"
check_grep "consenso esplicito non tacito" 'request_consent' \
  "$ROOT/desktop/src-tauri/src/local_auth.rs"

echo "-- [5] close 4406 stabile e usato --"
check_grep "4406 in protocol (shared)" 'LOCAL_NON_AUTENTICATO' \
  "$ROOT/shared-core-rust/src/protocol.rs"
check_grep "4406=4406 alfanumerico nel modulo" '[^0-9]4406' \
  "$ROOT/shared-core-rust/src/protocol.rs"
check_grep "ws_server usa local_unauthorized (4406)" 'close::LOCAL_NON_AUTENTICATO' \
  "$ROOT/desktop/src-tauri/src/ws_server.rs"
check_grep "REST transmit chiede Bearer token" 'Bearer' \
  "$ROOT/desktop/src-tauri/src/ws_server.rs"

echo "-- [5b] engine: il piano in chiaro resta su loopback --"
check_grep "bind HTTP in chiaro risolto su 127.0.0.1" 'SocketAddr::from\(\(\[127, 0, 0, 1\], port\)\)' \
  "$ROOT/desktop/src-tauri/src/ws_server.rs"
check_grep "handler rifiutano indirizzi non-loopback" 'if !is_loopback\(addr\)' \
  "$ROOT/desktop/src-tauri/src/ws_server.rs"

echo "-- [6] estensione: default HTTPS + flusso consenso --"
check_grep "requireHttps default on" \
  'requireHttps: true' \
  "$ROOT/browser-extension/src/background/service-worker.ts"
check_grep "hello con token come primo frame" 'type: "hello"' \
  "$ROOT/browser-extension/src/background/service-worker.ts"
check_grep "gestisce consent_status (approved -> token)" 'consent_status' \
  "$ROOT/browser-extension/src/background/service-worker.ts"
check_grep "pulisce il token a 4406" '4406' \
  "$ROOT/browser-extension/src/background/service-worker.ts"
check_grep "i18n mirror: consent.pending" '"consent.pending"' \
  "$ROOT/browser-extension/src/shared/i18n.ts"

echo "-- [7] test mirati --"
(cd "$ROOT" && cargo test -p nfc-desktop --lib local_auth::tests) \
  || fail "unit test local_auth"
(cd "$ROOT" && cargo test -p nfc-desktop --test extension_auth) \
  || fail "WS /v1/extension (consenso/4406) su socket reale"
(cd "$ROOT" && cargo test -p nfc-desktop --test api) \
  || fail "REST api (401 senza token)"
(cd "$ROOT" && cargo test -p nfc-desktop --lib local_tls) \
  || fail "server TLS13/PQ"
(cd "$ROOT" && cargo test -p nfc-mobile --lib tls_pin) \
  || fail "client TLS13/PQ"
(cd "$ROOT" && node scripts/check-pairing-codes.mjs) \
  || fail "contratto codici pairing Rust<->TS"

echo "-- [8] webapp: core WASM, MIME e canale client --"
check_grep "MIME application/wasm per i .wasm" '"wasm" => "application/wasm"' \
  "$ROOT/desktop/src-tauri/src/ws_server.rs"
check_grep "CSP ammette il WASM (wasm-unsafe-eval scoped)" 'wasm-unsafe-eval' \
  "$ROOT/desktop/src-tauri/src/ws_server.rs"
check_grep "unit test del MIME/CSP wasm" 'csp_ammette_il_wasm' \
  "$ROOT/desktop/src-tauri/src/ws_server.rs"
check_grep "build:wasm cablata nella build webapp" 'build:wasm' \
  "$ROOT/web/package.json"
check_grep "crate WASM sotto i workspace lints (unsafe_code=forbid)" '^\[lints\]' \
  "$ROOT/shared-core-wasm/Cargo.toml"
check_grep "webapp: il QR passa sempre dal core WASM" 'parsePairingQr' \
  "$ROOT/web/src/main.ts"
check_grep "client TS: hello con token come primo frame" 'type: "hello", token' \
  "$ROOT/shared-ui-ts/src/client.ts"
(cd "$ROOT" && cargo test -p nfc-desktop --lib ws_server::tests) \
  || fail "unit test MIME wasm"
(cd "$ROOT" && cargo test -p nfc-core-wasm) \
  || fail "parser/validazione WASM su host (parse_pairing_qr/validate_apdu)"

echo "-- [9] vpcd: adapter v1 e compagno server nel repo --"
check_grep "decodifica richiesta adapter v1 (lato server)" 'pub fn decode_request' \
  "$ROOT/desktop/src-tauri/src/vpcd.rs"
check_grep "server compagno vpcd-stub (bin nel crate desktop)" 'vpcd-stub' \
  "$ROOT/desktop/src-tauri/src/bin/vpcd-stub.rs"
check_grep "install Linux installa vpcd-stub, non vsmartcard" 'vpcd-stub' \
  "$ROOT/scripts/install-vpcd-linux.sh"
check_nogrep "installer Windows non dipende da demone esterno" 'vsmartcard' \
  "$ROOT/scripts/install-vpcd-windows.ps1"
check_nogrep "installer macOS non dipende da demone esterno" 'vsmartcard' \
  "$ROOT/scripts/install-vpcd-macos.sh"
check_grep "installer Windows installa vpcd-stub.exe" 'vpcd-stub.exe' \
  "$ROOT/scripts/install-vpcd-windows.ps1"
check_grep "installer macOS installa vpcd-stub" 'vpcd-stub' \
  "$ROOT/scripts/install-vpcd-macos.sh"
(cd "$ROOT" && cargo test -p nfc-desktop --lib vpcd) \
  || fail "adapter vpcd: unit (decode/encode framing)"
(cd "$ROOT" && cargo test -p nfc-desktop --test vpcd_stub_roundtrip) \
  || fail "adapter vpcd: round-trip reale client<->stub"

echo "-- [10] engine: systemd user service (sopravvive al reaper della shell) --"
check_grep "installer engine definisce nfc-engine.service" 'nfc-engine.service' \
  "$ROOT/scripts/install-engine-linux.sh"
check_grep "start-all usa il servizio engine (ENGINE_SERVICE)" 'ENGINE_SERVICE' \
  "$ROOT/scripts/start-all.sh"
check_grep "start-all ferma anche il servizio engine" 'stop nfc-engine.service' \
  "$ROOT/scripts/start-all.sh"

echo "Guard sicurezza 2026: OK"