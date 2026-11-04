import { defineConfig } from "vite";
export default defineConfig({
  clearScreen: false,
  // host esplicito su IPv4: la webview GTK di Tauri risolve `localhost` su
  // 127.0.0.1, mentre il default di Vite (localhost) può bindare solo [::1].
  server: { host: "127.0.0.1", port: 1420, strictPort: true },
  build: { outDir: "dist" },
});
