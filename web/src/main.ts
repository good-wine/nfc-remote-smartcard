// Webapp NFC Remote 2026 — SOLO scanner del QR di pairing del desktop.
// - Il QR lo genera l'app desktop (tray) e lì avviene l'approvazione: la
//   webapp scansiona e basta.
// - Core Rust in WASM (`wasm-bindgen`, asset servito dallo stesso engine,
//   **niente CDN**): parsing/validazione del QR di pairing con la **stessa**
//   validazione dell'app nativa.
// - Fotocamera (getUserMedia + jsQR) per inquadrare il QR della tray; il testo
//   passa sempre dal core WASM prima di essere mostrato.
import "./style.css";

import init, {
  parse_pairing_qr,
  validate_apdu,
} from "./wasm/nfc_core_wasm.js";
import { QrScanner } from "./scanner.js";

/** Esposto per i test Playwright: il core WASM è una dipendenza del flusso
 * (parse/validate), non un ornamento. */
declare global {
  interface Window {
    nfcCore: {
      ready: Promise<void>;
      parsePairingQr(text: string): string;
      validateApdu(hex: string): string;
    };
  }
}

// ---------------------------------------------------------------------------
// DOM
// ---------------------------------------------------------------------------

const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`elemento #${id} mancante in index.html`);
  return el as T;
};

const netBadge = $<HTMLElement>("net-badge");
const installBtn = $<HTMLButtonElement>("install");
const scanVideo = $<HTMLVideoElement>("scan-video");
const scanStartBtn = $<HTMLButtonElement>("scan-start");
const scanStopBtn = $<HTMLButtonElement>("scan-stop");
const scanManual = $<HTMLTextAreaElement>("scan-manual");
const scanAnalyseBtn = $<HTMLButtonElement>("scan-analyse");
const scanResult = $<HTMLElement>("scan-result");
const scanError = $<HTMLElement>("scan-error");
const scanNext = $<HTMLElement>("scan-next");
const offlineBanner = $<HTMLElement>("offline-banner");
const retryBtn = $<HTMLButtonElement>("retry");

// ---------------------------------------------------------------------------
// Stato
// ---------------------------------------------------------------------------

let scanner: QrScanner | null = null;
let installedPrompt: BeforeInstallPromptEvent | null = null;

/** Messaggio da un errore JS: `wasm-bindgen` con `Result<T, JsValue>` lancia
 * il valore grezzo (spesso una stringa), non un `Error`. */
function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

// ---------------------------------------------------------------------------
// Core WASM
// ---------------------------------------------------------------------------

async function loadCore(): Promise<void> {
  await init();
  window.nfcCore = {
    ready: Promise.resolve(),
    parsePairingQr: (text: string) =>
      parse_pairing_qr(text, BigInt(Math.floor(Date.now() / 1000))),
    validateApdu: (hex: string) => validate_apdu(hex),
  };
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

interface ScannedQr {
  v: number;
  ip: string;
  port: number;
  host: string | null;
  tls_port: number | null;
  has_tls_pin: boolean;
  pq: number;
  wants_pq: boolean;
  expiry: { kind: string; secs: number | null };
  qr_len: number;
  /** Scadenza grezza nel testo QR (`NFC://`): assente se il vettore è senza TTL. */
  exp_unix?: number | null;
}

function showScanResult(parsed: string): void {
  const info = JSON.parse(parsed) as ScannedQr;
  scanError.textContent = "";
  const rows: Array<[string, string]> = [
    ["versione QR", `v${info.v}`],
    ["protocollo", info.wants_pq ? "ibrido X25519 + ML-KEM-768" : "classico X25519"],
    ["host", info.host ?? info.ip],
    ["porta canale", info.tls_port ? String(info.tls_port) : String(info.port)],
    ["pin TLS", info.has_tls_pin ? "sì (SHA-256 foglia)" : "no"],
    ["scadenza", info.expiry.kind === "expired" ? "SCADUTO" : info.expiry.kind === "valid" ? `valido (${info.expiry.secs}s)` : "non indicata"],
  ];
  scanResult.replaceChildren(
    ...[...rows.flatMap(([k, v]) => {
      const dt = document.createElement("dt");
      dt.textContent = k;
      const dd = document.createElement("dd");
      dd.textContent = v;
      return [dt, dd];
    })],
  );
  scanResult.hidden = false;
  scanNext.textContent =
    "QR valido. Sul desktop compare la notifica di scansione; completa l'accoppiamento con l'app NFC Remote nativa, dove riceverai la SAS da confrontare su entrambi gli schermi. Questa webapp è solo lo scanner.";
  scanNext.hidden = false;
  if (info.expiry.kind === "expired") {
    scanError.textContent = "QR scaduto: rigenera il QR dalla tray del desktop.";
    scanError.hidden = false;
  } else {
    // Beacon informativo: dice al desktop che un browser ha inquadrato il QR
    // (notifica "QR scansionato"). NON è l'associazione — quella richiede
    // l'handshake dell'app nativa. Best-effort e silenzioso: se il POST non
    // passa (es. origine non autorizzata) la scansione resta comunque valida.
    void fetch("/v1/scan", { method: "POST", keepalive: true }).catch(() => undefined);
  }
}

function analyseQrText(text: string): void {
  const t = text.trim();
  if (!t) return;
  try {
    const parsed = window.nfcCore.parsePairingQr(t);
    showScanResult(parsed);
  } catch (e) {
    scanResult.hidden = true;
    scanError.textContent = `QR non valido: ${errMsg(e)}`;
    scanError.hidden = false;
  }
}

/** Nome dell'errore DOM (permesso, camera assente…) con la causa reale. */
function fotocameraHint(e: unknown): string {
  const nome = e instanceof DOMException ? e.name : "";
  switch (nome) {
    case "NotAllowedError":
      return "autorizzazione negata. Su Firefox mobile la fotocamera richiede un certificato fidato: installa la CA locale sul telefono (o usa Chrome), autorizza la fotocamera e riprova";
    case "NotFoundError":
      return "nessuna fotocamera trovata su questo dispositivo";
    case "NotReadableError":
      return "fotocamera già usata da un'altra app: chiudila e riprova";
    case "NotSupportedError":
    case "OverconstrainedError":
      return "la fotocamera non supporta la risoluzione richiesta";
    default:
      return errMsg(e);
  }
}

scanStartBtn.addEventListener("click", async () => {
  scanStartBtn.disabled = true;
  scanStartBtn.hidden = true;
  scanError.textContent = "";
  try {
    scanner = new QrScanner(scanVideo);
    await scanner.start((text) => {
      analyseQrText(text);
      scanVideo.hidden = true;
      scanStopBtn.hidden = true;
      scanStartBtn.hidden = false;
      scanStartBtn.disabled = false;
      return "stop";
    });
    scanVideo.hidden = false;
    scanStopBtn.hidden = false;
  } catch (e) {
    scanStartBtn.disabled = false;
    scanStartBtn.hidden = false;
    scanError.textContent = `fotocamera non disponibile (${fotocameraHint(e)}). In alternativa: incolla il testo qui sotto.`;
    scanError.hidden = false;
  }
});

scanStopBtn.addEventListener("click", () => {
  scanner?.stop();
  scanVideo.hidden = true;
  scanStopBtn.hidden = true;
  scanStartBtn.disabled = false;
  scanStartBtn.hidden = false;
});

scanAnalyseBtn.addEventListener("click", () => analyseQrText(scanManual.value));

// ---------------------------------------------------------------------------
// Stato engine (solo l'indicatore di raggiungibilità)
// ---------------------------------------------------------------------------

interface EngineStatus {
  ok: boolean;
}

async function refreshStatus(): Promise<void> {
  try {
    const res = await fetch("/v1/status", { headers: { accept: "application/json" } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const s = (await res.json()) as EngineStatus;
    if (!s.ok) throw new Error("engine non ok");
    netBadge.dataset["state"] = "online";
    netBadge.textContent = "online";
    offlineBanner.hidden = true;
  } catch {
    netBadge.dataset["state"] = "offline";
    netBadge.textContent = "offline";
    offlineBanner.hidden = false;
  }
}

// ---------------------------------------------------------------------------
// PWA
// ---------------------------------------------------------------------------

function setupPwa(): void {
  window.addEventListener("beforeinstallprompt", (e) => {
    const prompt = e as BeforeInstallPromptEvent;
    prompt.preventDefault();
    installedPrompt = prompt;
    installBtn.hidden = false;
  });
  installBtn.addEventListener("click", () => {
    void installedPrompt?.prompt();
    installedPrompt = null;
    installBtn.hidden = true;
  });
  if ("serviceWorker" in navigator) {
    // Solo se l'app è servita da nfc.local: in dev (5173) non deve cacheare.
    if (location.protocol === "https:") {
      void navigator.serviceWorker.register("/sw.js").catch(() => undefined);
    }
    // Quando un SW nuovo prende il controllo (skipWaiting dopo un deploy) la
    // pagina in scheda è ancora quella vecchia: si ricarica una volta sola, così
    // l'utente non resta mai sulla versione servita dalla cache precedente.
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (!sessionStorage.getItem("nfc-sw-reloaded")) {
        sessionStorage.setItem("nfc-sw-reloaded", "1");
        location.reload();
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Avvio
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // Marcatore di build: identifica senza ambiguità la versione servita.
  document.getElementById("build-meta")!.textContent = `NFC Remote · build ${__BUILD_TS__}`;
  setupPwa();

  try {
    await loadCore();
  } catch (e) {
    // Senza `application/wasm` dall'engine il modulo non si carica: il resto
    // della webapp resta usabile, lo segnaliamo nel log.
    scanError.textContent = `core WASM non caricato (${errMsg(e)}): impossibile validare i QR.`;
    scanError.hidden = false;
  }

  retryBtn.addEventListener("click", () => void refreshStatus());

  try {
    await refreshStatus();
  } catch {
    /* il banner offline sta già correggendo lo stato */
  }
  window.setInterval(() => void refreshStatus(), 5000);
}

void main();