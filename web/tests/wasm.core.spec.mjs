// Test autonomo del core WASM della webapp — **nessun engine richiesto**.
//
// Serve `web/dist` (già buildata: `npm run build`) con un mini server HTTP che
// dichiara `application/wasm` — il MIME che l'engine ha in `content_type_for` e
// senza il quale `instantiateStreaming` fallirebbe. Verifica:
//   1. `window.nfcCore` esiste e il modulo WASM si è caricato davvero;
//   2. `parsePairingQr` accetta un QR v2 ibrido (PQ) e lo classifica `valid`;
//   3. `parsePairingQr` rifiuta QR malformati e QR scaduti;
//   4. `validateApdu` normalizza un APDU e rifiuta hex invalidi;
//   5. il flusso Scanner (unica vista) usa il core: analisi manuale di un
//      testo di pairing valido (= validazione Rust) e di uno invalido.
// Gli stessi casi vivono come unit test Rust (`shared-core-wasm`): questo test
// dimostra che il *browser* li esegue paro paro.
import { chromium } from "playwright";
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { strict as assert } from "node:assert";

const DIST = resolve(fileURLToPath(new URL("..", import.meta.url)), "dist");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/manifest+json",
  ".webmanifest": "application/manifest+json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

const server = createServer(async (req, res) => {
  try {
    const urlPath = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname);
    let file = join(DIST, urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, ""));
    try {
      await stat(file);
    } catch {
      file = join(DIST, "index.html"); // SPA fallback
    }
    if (!file.startsWith(DIST)) throw new Error("path traversal");
    const body = await readFile(file);
    res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
    res.end(body);
  } catch (e) {
    res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    res.end(String(e));
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

// --- QR di pairing costruiti in JS (stessi campi di `PairingPayload`) ---------
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
/** QR v2 ibrido PQ con scadenza nell'anno 2039: resta "valido" per sempre. */
const qrHybrid = () => {
  const p = {
    v: 2,
    ip: "192.168.1.10",
    port: 8080,
    nonce_b64: b64url(new Uint8Array(32).fill(1)),
    pubkey_b64: b64url(new Uint8Array(32).fill(2)),
    pq: 1,
    mlkem_b64: b64url(new Uint8Array(1184).fill(7)),
    exp_unix: 2_200_000_300,
  };
  return `NFC://2/${Buffer.from(JSON.stringify(p)).toString("base64url")}`;
};
/** QR v2 con scadenza nel passato (ma dentro la finestra "sana" 2020..2099):
 * l'engine lo considera scaduto, non corrotto. */
const qrExpired = () => {
  const p = {
    v: 2,
    ip: "192.168.1.10",
    port: 8080,
    nonce_b64: b64url(new Uint8Array(32).fill(1)),
    pubkey_b64: b64url(new Uint8Array(32).fill(2)),
    exp_unix: 1_650_000_000,
  };
  return `NFC://2/${Buffer.from(JSON.stringify(p)).toString("base64url")}`;
};

const browser = await chromium.launch({ args: ["--no-sandbox"] });
const page = await browser.newPage();

await page.goto(base, { waitUntil: "networkidle" });

// --- 1. il core WASM esiste e carica ------------------------------------------
await page.waitForFunction(() => window.nfcCore !== undefined, { timeout: 15000 });
await page.evaluate(() => window.nfcCore.ready);

// --- 2. parsePairingQr: QR ibrido valido --------------------------------------
const out = await page.evaluate((text) => window.nfcCore.parsePairingQr(text), qrHybrid());
const parsed = JSON.parse(out);
assert.equal(parsed.v, 2);
assert.equal(parsed.ip, "192.168.1.10");
assert.equal(parsed.port, 8080);
assert.equal(parsed.wants_pq, true, "QR ibrido non riconosciuto PQ");
assert.equal(parsed.has_tls_pin, false);
assert.equal(parsed.expiry.kind, "valid");
assert.ok(parsed.qr_len > 100);

// --- 3. parsePairingQr: rifiuto di malformati e scaduti -----------------------
const badMessage = await page.evaluate((text) => {
  try {
    window.nfcCore.parsePairingQr(text);
    return "ACCETTATO";
  } catch (e) {
    // wasm-bindgen lancia il valore grezzo (spesso una stringa), non Error.
    return typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
  }
}, "CIAO");
assert.notEqual(badMessage, "ACCETTATO", "QR malformato accettato");
assert.match(badMessage, /prefisso|base64|json/i, `motivo non chiaro: ${badMessage}`);
const expired = JSON.parse(await page.evaluate((text) => window.nfcCore.parsePairingQr(text), qrExpired()));
assert.equal(expired.expiry.kind, "expired", "QR scaduto non classificato come expired");

// --- 4. validateApdu: normalizza, e rifiuta l'invalido ------------------------
const apduGood = JSON.parse(
  await page.evaluate((hex) => window.nfcCore.validateApdu(hex), "00a4040007a000000247100100"),
);
assert.deepEqual(apduGood, { len: 13, hex: "00A4040007A000000247100100" });
const apduBad = await page.evaluate((hex) => {
  try {
    window.nfcCore.validateApdu(hex);
    return "ACCETTATO";
  } catch (e) {
    return typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
  }
}, "ZZ");
assert.notEqual(apduBad, "ACCETTATO", "APDU invalida accettata");

// --- 5. flusso Scanner (unica vista) via UI, alimentato dal core WASM --------
await page.fill("#scan-manual", qrHybrid());
await page.click("#scan-analyse");
await page.waitForFunction(() => document.getElementById("scan-result").hidden === false, { timeout: 5000 });
const resultText = await page.locator("#scan-result").innerText();
assert.match(resultText, /v2/, `versione QR assente: ${resultText}`);
assert.match(resultText, /ML-KEM-768/, `PQ non annunciato: ${resultText}`);
// La webapp è solo scanner: niente console da connettere.
assert.equal(await page.locator("#scan-connect").count(), 0, "console rimasta nella webapp");
assert.equal(await page.locator(".tab").count(), 0, "tab residui presenti");

await page.fill("#scan-manual", "CIAO");
await page.click("#scan-analyse");
await page.waitForFunction(() => document.getElementById("scan-error").hidden === false, { timeout: 5000 });
assert.match(await page.locator("#scan-error").innerText(), /non valido/i);

await browser.close();
await new Promise((r) => server.close(() => r()));
console.log("wasm core ok · pairing PQ valido · apdu ok · scanner ui ok");