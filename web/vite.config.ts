import { defineConfig } from "vite";

// `process.env` in fase di config: dichiarato qui per evitare di aggiungere
// `@types/node` solo per due righe di build.
declare const process: { env: Record<string, string | undefined> };

// La webapp viene servita dall'engine Rust, non da un dev server: `base`
// assoluto così gli asset (`/assets/…`) risolvono da qualsiasi prefisso di
// servizio — `/`, `/app` e `/app/` incluso. Con un `base` relativo l'URL
// con la barra finale (`/app/`) faceva risolvere gli asset sotto
// `/app/assets/…`, dove il fallback SPA risponde 200 text/html e il browser
// li rifiuta per MIME mismatch: pagina senza CSS/JS (il sintomo "caratteri
// strani" su Firefox mobile). Il dev server Vite espone `NFC_ENGINE` per
// proxare l'API del motore durante lo sviluppo.
const ENGINE = process.env.NFC_ENGINE ?? "http://127.0.0.1:8080";

export default defineConfig({
  base: "/",
  clearScreen: false,
  define: {
    // Marcatore di build visibile a piè di pagina: rende inequivocabile
    // quale versione della webapp si sta servendo (cache/SW a parte).
    __BUILD_TS__: JSON.stringify(new Date().toISOString()),
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    sourcemap: true,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/v1": { target: ENGINE, changeOrigin: true, ws: true },
    },
  },
});