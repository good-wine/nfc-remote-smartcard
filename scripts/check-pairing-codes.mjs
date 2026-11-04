#!/usr/bin/env node
// Coerenza dei codici di errore di pairing fra Rust e TypeScript.
//
// I due lati sono in linguaggi diversi e non condividono un tipo: i codici sono
// un contratto scritto a mano, e una rinomina romperebbe la traduzione **senza
// alcun errore di compilazione** né di esecuzione — l'errore comparirebbe solo
// sul device, nel caso in cui l'utente si trova esattamente in quel percorso di
// errore. Questo controllo è l'unico posto in cui il divario è visibile in CI.
//
// Verifica tre cose:
//   1. ogni codice emesso dal plugin Rust ha una chiave in `i18n.ts`;
//   2. ogni chiave di pairing in `i18n.ts` è emessa dal plugin (nessun testo
//      morto, che suggerirebbe un percorso d'errore rimosso senza pulizia);
//   3. i due insiemi sono davvero identici, non soltanto sovrapposti.
//
// Non usa un parser TS: le costanti sono letterali in un modulo Rust e chiavi in
// un oggetto, quindi un confronto testuale è sufficiente e non aggiunge una
// dipendenza di build a un controllo che deve restare banale.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const leggi = (p) => readFileSync(join(root, p), "utf8");

const RUST_CODICI = "mobile/src-tauri/src/lib.rs";
const I18N = "shared-ui-ts/src/i18n.ts";

const rust = leggi(RUST_CODICI);
const modulo = rust.match(/pub mod code \{([\s\S]*?)\n\}/);
if (!modulo) {
  console.error(`FAIL: modulo 'code' non trovato in ${RUST_CODICI}`);
  process.exit(1);
}
const emessi = new Set(
  [...modulo[1].matchAll(/pub const ([A-Z0-9_]+): &str = "([^"]+)";/g)].map((m) => m[2]),
);
if (emessi.size === 0) {
  console.error(`FAIL: nessun codice estratto da ${RUST_CODICI}`);
  process.exit(1);
}

const i18n = leggi(I18N);
const chiavi = new Set(
  [...i18n.matchAll(/^ {2}"([A-Za-z]+)": \{\n {4}it: /gm)].map((m) => m[1]),
);

// Le chiavi di errore sono quelle presenti nel dizionario `PairingCode` del
// frontend: si prende l'insieme dichiarato lì, non tutte le chiavi dell'i18n
// (che includono `status.*`, `btn.*` e altre stringhe normali).
const ERRORI = "shared-ui-ts/src/pairing-errors.ts";
const dichiarati = new Set(
  [...leggi(ERRORI).matchAll(/^\s+\w+:\s*"([A-Za-z]+)",$/gm)].map((m) => m[1]),
);
if (dichiarati.size === 0) {
  console.error(`FAIL: nessun codice estratto da ${ERRORI}`);
  process.exit(1);
}

const problemi = [];
for (const c of emessi) {
  if (!dichiarati.has(c)) problemi.push(`Rust emette '${c}' ma il frontend non lo dichiara`);
  if (!chiavi.has(c)) problemi.push(`Rust emette '${c}' ma i18n.ts non ha la chiave '${c}'`);
}
for (const c of dichiarati) {
  if (!emessi.has(c)) problemi.push(`il frontend dichiara '${c}' ma il plugin non lo emette mai`);
}

if (problemi.length) {
  console.error(`FAIL: ${problemi.length} incoerenze fra ${RUST_CODICI} e ${I18N}`);
  for (const p of problemi) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`codici di pairing ok · ${emessi.size} codici allineati su entrambi i lati`);
