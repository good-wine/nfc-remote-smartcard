// UI mobile: SOLO scanner QR + lettura NFC.
// La scansione avvia la sessione E2EE col desktop (plugin Rust). La carta
// viene letta dal bridge nativo (Kotlin/Swift) quando il desktop invia una
// `ApduRequest`; gli eventi del bridge aggiornano lo stato carta qui sotto.
import { listen } from "@tauri-apps/api/event";
import { applyI18n, detectLang, t } from "../../shared-ui-ts/src/i18n.js";
import { describePairingError } from "../../shared-ui-ts/src/pairing-errors.js";
import { scanAndPair } from "./lib/secure-channel";
import "./style.css";

const lang = detectLang();
applyI18n(lang);

/** Una carta è sotto lettura: lo stato "reading" è provvisorio e torna qui. */
let cardPresent = false;
let readingTimer: ReturnType<typeof setTimeout> | undefined;

const btn = document.getElementById("scan") as HTMLButtonElement;
const hint = document.getElementById("hint")!;
const statusEl = document.getElementById("status")!;
const cardEl = document.getElementById("card")!;
const cardText = document.getElementById("card-text")!;
const atrEl = document.getElementById("card-atr")!;

/** Stato visivo della sessione: testo + chip colorato (`data-state`). */
function setStatus(text: string, state: "idle" | "scanning" | "ok" | "error"): void {
  statusEl.textContent = text;
  statusEl.dataset["state"] = state;
}

/** Stato carta: `none` | `reading` | `inserted` (con ATR quando disponibile). */
function setCard(state: "none" | "reading" | "inserted", atrHex?: string): void {
  if (state === "inserted") {
    cardPresent = true;
    cardText.textContent = t("card.inserted", lang);
    atrEl.textContent = atrHex ?? "";
    atrEl.hidden = !atrHex;
  } else if (state === "reading") {
    cardText.textContent = t("card.reading", lang);
  } else {
    cardPresent = false;
    cardText.textContent = t("card.none", lang);
    atrEl.hidden = true;
    atrEl.textContent = "";
  }
  cardEl.dataset["state"] = state;
}

/** Lampeggio "lettura in corso" su richiesta APDU, poi stato reale della carta. */
function blinkReading(): void {
  setCard("reading");
  window.clearTimeout(readingTimer);
  readingTimer = window.setTimeout(() => {
    setCard(cardPresent ? "inserted" : "none");
  }, 1200);
}

btn.onclick = async () => {
  try {
    setStatus(t("status.scanning", lang), "scanning");
    await scanAndPair();
    setStatus(t("status.session", lang), "ok");
    // Il pulsante diventa "Nuova sessione": riavvia il flusso in quale punto serve.
    btn.textContent = t("btn.newSession", lang);
    hint.textContent = t("mobile.holdCard", lang);
    setCard("none");
  } catch (e) {
    // Il plugin restituisce `{code, detail}`: il testo lo mette `describePairingError`
    // in base alla lingua, con l'azione da fare dentro. Mostrare `e.message`
    // darebbe all'utente la prosa italiana del Rust — non tradotta, e senza
    // azione: l'errore di sicurezza più importante sarebbe anche il meno
    // comprensibile.
    const testo = describePairingError(e, lang);
    setStatus(`${t("status.error", lang)}: ${testo}`, "error");
  }
};

// Eventi nativi: nessuna APDU in chiaro qui, solo feedback di stato.
async function main(): Promise<void> {
  // Richiesta APDU dal desktop: il bridge nativo la inoltra alla carta e risponde.
  await listen<{ request_id: string; apdu_hex: string }>("mobile-apdu-request", () => {
    blinkReading();
  });
  // Stato carta segnalato dal bridge nativo (Kotlin/Swift).
  await listen<{ status: string; atr_hex?: string | null }>("nfc-card-status", (e) => {
    if (e.payload.status === "inserted") setCard("inserted", e.payload.atr_hex ?? undefined);
    else setCard("none");
  });
}

void main();