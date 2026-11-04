// Smoke test della webapp servita dall'engine: apre `https://nfc.local:8443/app`
// in Chromium, verifica che sia SOLO scanner (nessun tab Accoppa/Console/Stato,
// nessuna superficie di consenso nella webapp), che il QR reale dell'engine
// venga validato dal core WASM (stessa validazione del telefono nativo), che il
// marcatore di build sia presente e che il manifest sia installabile come PWA.
import { chromium } from "playwright";
import { readFileSync } from "node:fs";
import { strict as assert } from "node:assert";

const CA = process.env.NFC_CA ?? `${process.env.HOME}/.config/nfc-remote/ca/nfc-local-root.pem`;
const BASE = process.env.NFC_BASE ?? "https://localhost:8443";

// `nfc.local` è risolto dal resolver di Chromium (`--host-resolver-rules`)
// invece che da `/etc/hosts`: lo split-horizon locale senza toccare il system,
// quindi il test non richiede root. Su un desktop con la riga in `/etc/hosts`
// già presente la regola è redundante e innocua.
const HOST_RULES = ["--host-resolver-rules=MAP nfc.local 127.0.0.1"];
const browser = await chromium.launch({
  args: ["--no-sandbox", ...HOST_RULES],
});
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: `${BASE}/` });
const page = await ctx.newPage();

const errors = [];
page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
page.on("console", (m) => {
  if (m.type() === "error") errors.push(`console: ${m.text()}`);
});

await page.goto("/app", { waitUntil: "networkidle" });

// --- 1. struttura della pagina: SOLO scanner --------------------------------
assert.equal(await page.title(), "NFC Remote");
assert.equal(await page.locator("header h1").innerText(), "NFC Remote");
assert.equal(await page.locator("#view-scanner").count(), 1, "vista Scanner mancante");
assert.ok(await page.locator("#view-scanner").isVisible(), "vista Scanner non attiva");
// Nessun residuo della vecchia app: niente tab, niente console, niente QR view.
assert.equal(await page.locator(".tab").count(), 0, "tab residui presenti");
assert.equal(await page.locator("#become-reader").count(), 0, "surfaccia consenso rimasta");
assert.equal(await page.locator("#scan-connect").count(), 0, "collegamento console rimasto");
assert.equal(await page.locator("#qr").count(), 0, "vista Accoppa rimasta");

// --- 2. marcatore di build ---------------------------------------------------
const meta = await page.$eval("#build-meta", (e) => e.textContent ?? "");
assert.match(meta, /build .{10,}/, `marcatore di build assente: ${meta}`);

// --- 3. stato engine raggiungibile ------------------------------------------
await page.waitForFunction(() => document.getElementById("net-badge").dataset.state === "online");

// --- 4. il QR reale dell'engine passa dal core WASM --------------------------
await page.waitForFunction(() => window.nfcCore !== undefined, { timeout: 15000 });
const qrText = await page.evaluate(async () => {
  // QR fresco: il TTL è 5 minuti e la rigenerazione avviene su POST /v1/qr.
  await fetch("/v1/qr", { method: "POST" });
  return (await (await fetch("/v1/qr")).json()).qr_text;
});
assert.ok(qrText.startsWith("NFC://2/"), `pairing: ${qrText.slice(0, 20)}`);
// È davvero ibrido PQ: ML-KEM-768 = chiave pubblica da 1184 byte.
const payload = JSON.parse(Buffer.from(qrText.slice("NFC://2/".length), "base64url").toString());
assert.equal(payload.v, 2);
assert.ok(payload.mlkem_b64, "manca la chiave ML-KEM nel pairing: non è ibrido PQ");
assert.equal(Buffer.from(payload.mlkem_b64, "base64url").length, 1184);

await page.fill("#scan-manual", qrText);
await page.click("#scan-analyse");
await page.waitForFunction(() => document.getElementById("scan-result").hidden === false, {
  timeout: 10000,
});
const resultText = await page.locator("#scan-result").innerText();
assert.match(resultText, /ibrido X25519 \+ ML-KEM-768/, `PQ non annunciato: ${resultText}`);
assert.match(resultText, /nfc\.local/, `host non dichiarato: ${resultText}`);
assert.match(resultText, /valido/, `QR non marcato valido: ${resultText}`);
assert.ok(await page.locator("#scan-next").isVisible(), "guida post-scansione assente");

// Un QR invalido viene rifiutato (mai "engine valido").
await page.fill("#scan-manual", "CIAO");
await page.click("#scan-analyse");
await page.waitForFunction(() => document.getElementById("scan-error").hidden === false, {
  timeout: 5000,
});
assert.match(await page.locator("#scan-error").innerText(), /non valido/i);

// --- 5. PWA installabile -----------------------------------------------------
const manifest = await page.evaluate(async () => {
  const href = document.querySelector('link[rel="manifest"]').href;
  return (await fetch(href)).json();
});
assert.equal(manifest.name, "NFC Remote");
assert.equal(manifest.display, "standalone");
assert.ok(manifest.icons.length >= 2, "servono icone 192 e 512 per l'installazione");
assert.ok(manifest.icons.some((i) => i.sizes === "512x512" && i.purpose === "maskable"));

const sw = await page.evaluate(async () => {
  const r = await fetch("./sw.js");
  return { status: r.status, cache: r.headers.get("cache-control"), len: (await r.text()).length };
});
assert.equal(sw.status, 200);
assert.equal(sw.cache, "no-store", "sw.js in cache: l'aggiornamento PWA non arriverebbe mai");

// --- 6. nessun errore JS -----------------------------------------------------
assert.deepEqual(errors, [], `errori in pagina: ${errors.join(" | ")}`);

// Screenshot per ispezione visiva.
await page.screenshot({ path: "webapp-scanner.png", fullPage: true });

await browser.close();
console.log(`webapp ok · solo scanner · QR PQ valido · PWA · build ${meta.trim()}`);