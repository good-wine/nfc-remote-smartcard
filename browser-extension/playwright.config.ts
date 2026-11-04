import { defineConfig, devices } from "@playwright/test";

// Smoke MV3: estensione caricata unpacked da dist/ (prima `npm run build`).
// Non richiede engine: verifica popup, badge logic e assenza API su origini
// non allowlist. Con engine attivo, `test-select` fa il giro completo.
export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: { ...devices["Desktop Chrome"], channel: "chromium" },
});
