// Smoke test estensione (richiede `npm run build` prima).
// Senza engine attivo: il popup si apre e `test-select` mostra ERR di
// connessione (prova il cablaggio popup -> SW -> WS). Su origine non matchata
// dai content_scripts, window.SmartCardReader resta undefined.
import { test, expect, chromium } from "@playwright/test";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist");

// Le estensioni si caricano solo in un contesto persistente (profilo reale):
// con `launch` + `newContext()` il flag --load-extension viene ignorato in ogni
// modalità. `channel: "chromium"` = build completa (non l'headless-shell), così
// le MV3 caricano anche in headless; E2E_HEADFUL=1 resta come fallback headful
// sotto xvfb. Il profilo è usa-e-getta e viene rimosso a fine test.
async function launchWithExtension() {
  const headless = process.env.E2E_HEADFUL !== "1";
  const profile = mkdtempSync(path.join(os.tmpdir(), "nfc-ext-e2e-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    headless,
    channel: "chromium",
    // Necessario nei container CI (utente root): solo ambiente di test.
    args: ["--no-sandbox", `--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`],
  });
  // Il SW MV3 è già registrato al boot; l'id si ricava dal suo URL.
  const worker = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent("serviceworker"));
  const extensionId = worker.url().split("/")[2];
  expect(extensionId).toMatch(/^[a-p]{32}$/);
  return { ctx, extensionId, profile };
}

test("popup si apre e il giro transmit fallisce senza engine (ERR)", async () => {
  const { ctx, extensionId, profile } = await launchWithExtension();
  const page = await ctx.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/popup/popup.html`);
  await expect(page.locator("h1")).toContainText("NFC Remote");
  await expect(page.locator("#conn")).toBeVisible();
  await page.click("#test-select");
  await expect(page.locator("#out")).toContainText(/ERR|timeout|non raggiungibile/i);
  await ctx.close();
  rmSync(profile, { recursive: true, force: true });
});

test("nessuna API su origine non coperta dai content_scripts", async () => {
  const { ctx, profile } = await launchWithExtension();
  const page = await ctx.newPage();
  await page.goto("https://example.com/");
  const hasApi = await page.evaluate(
    () => typeof (window as unknown as { SmartCardReader?: unknown }).SmartCardReader,
  );
  expect(hasApi).toBe("undefined");
  await ctx.close();
  rmSync(profile, { recursive: true, force: true });
});
