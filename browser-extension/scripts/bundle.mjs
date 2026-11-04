// Bundler minimale senza dipendenze: copia TS->JS (tsc) in dist/ mantenendo
// la struttura attesa da manifest.json. Eseguire dopo `tsc -p tsconfig.json`.
import { copyFileSync, mkdirSync, readdirSync, rmSync } from "node:fs";

// Build pulita: dist/ rigenerato da zero a ogni bundle.
rmSync("dist", { recursive: true, force: true });

// Copia l'intero output di tsc (dist-tmp/** -> dist/src/**): niente liste
// hardcoded, così i moduli src/shared aggiunti in futuro restano inclusi.
function copiaAlbero(from, to) {
  mkdirSync(to, { recursive: true });
  for (const e of readdirSync(from, { withFileTypes: true })) {
    if (e.isDirectory()) copiaAlbero(`${from}/${e.name}`, `${to}/${e.name}`);
    else copyFileSync(`${from}/${e.name}`, `${to}/${e.name}`);
  }
}
copiaAlbero("dist-tmp", "dist/src");

mkdirSync("dist/icons", { recursive: true });
copyFileSync("src/content/injected.js", "dist/src/content/injected.js");
copyFileSync("src/popup/popup.html", "dist/src/popup/popup.html");
copyFileSync("src/popup/popup.css", "dist/src/popup/popup.css");
for (const s of ["16", "48", "128"]) {
  copyFileSync(`icons/${s}.png`, `dist/icons/${s}.png`);
}
copyFileSync("manifest.json", "dist/manifest.json");
console.log("bundle ok -> dist/");
