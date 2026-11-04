// Verifica che `nfc.local` si risolva e che il TLS validi *senza* eccezioni,
// dentro il namespace di `scripts/with-nfc-local.sh`: niente --ignore-certificate-errors,
// niente --host-resolver-rules. È la prova che la soluzione rootless sia
// completa, non un workaround che sposta il problema altrove.
// La webapp è SOLO scanner: niente tab, niente console, niente QR view.
import { chromium } from "playwright";
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";

const CA = `${process.env.HOME}/.config/nfc-remote/ca/nfc-local-root.pem`;

const browser = await chromium.launch({ args: ["--no-sandbox"] });
// `ignoreHTTPSErrors: false` di proposito: se il trust non è a posto, fallisce.
const ctx = await browser.newContext({ baseURL: "https://nfc.local:8443/" });
const page = await ctx.newPage();

await page.goto("/app", { waitUntil: "networkidle" });
assert.equal(await page.title(), "NFC Remote");

// Il WSS è sullo stesso host: se la risoluzione o il TLS fallissero, il badge
// resterebbe "offline".
await page.waitForFunction(() => document.getElementById("net-badge").dataset.state === "online", {
  timeout: 15000,
});

// Solo scanner: nessuna superficie di consenso/console legacy e vista Scanner
// attiva di default.
assert.equal(await page.locator(".tab").count(), 0, "tab residui presenti");
assert.equal(await page.locator("#become-reader").count(), 0, "consenso rimasto nella webapp");
assert.equal(await page.locator("#qr").count(), 0, "vista Accoppa rimasta");
assert.equal(await page.locator("#scan-start").count(), 1, "scanner assente");
assert.ok(await page.locator("#scan-start").isVisible(), "scanner non visibile");

await browser.close();
console.log("namespace ok · nfc.local risolto · TLS validato · webapp solo scanner");
// La CA deve esistere: il test fallirebbe con un errore TLS poco leggibile.
readFileSync(CA);