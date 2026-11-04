// UI desktop: mostra QR, stato vpcd/WS/TLS, log eventi (EN/IT).
// Comunica solo via IPC Tauri (`invoke`), mai fetch diretto al core.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { applyI18n, detectLang, t } from "../../shared-ui-ts/src/i18n.js";
import "./style.css";

const lang = detectLang();
applyI18n(lang);

const qrImg = document.getElementById("qr") as HTMLImageElement;
const qrText = document.getElementById("qrtext")!;
const qrExpiryEl = document.getElementById("qr-expiry") as HTMLSpanElement;
const statusEl = document.getElementById("status")!;
const statusMetaEl = document.getElementById("status-meta")!;
const logEl = document.getElementById("log")!;
const regenBtn = document.getElementById("regen") as HTMLButtonElement;
const pendingCountEl = document.getElementById("pending-count")!;

/**
 * La UI desktop parla **solo** via IPC Tauri (`invoke`), mai via rete. Quindi
 * non funziona in un browser normale: senza `__TAURI_INTERNALS__` ogni
 * `invoke`/`listen` solleva `TypeError: window.__TAURI_INTERNALS__ is
 * undefined`, un errore che non dice nulla all'utente. Qui lo intercettiamo
 * una volta sola e spieghiamo cosa aprire invece.
 */
const hasIpc = "__TAURI_INTERNALS__" in window;

function showStandaloneNotice(): void {
  document.body.innerHTML = "";
  const box = document.createElement("div");
  box.className = "card";
  box.style.lineHeight = "1.5";

  const h = document.createElement("h2");
  h.textContent = "Questa UI va aperta nell'app desktop";
  const p = document.createElement("p");
  p.textContent =
    "Il pannello usa l'IPC interno di Tauri, che esiste solo dentro la finestra dell'app. In un browser non può funzionare.";
  const p2 = document.createElement("p");
  p2.innerHTML =
    "Per la stessa funzionalità nel browser usa la <strong>webapp</strong>: " +
    '<a href="https://nfc.local:8443/app">https://nfc.local:8443/app</a>';
  const hint = document.createElement("p");
  hint.style.fontSize = "12px";
  hint.textContent = "Oppure avvia l'app: cargo run -p nfc-desktop";

  box.append(h, p, p2, hint);
  document.body.append(box);
}

function log(msg: string) {
  const div = document.createElement("div");
  div.textContent = `${new Date().toLocaleTimeString()} ${msg}`;
  logEl.prepend(div);
}

async function refreshQr() {
  const v = (await invoke("get_qr")) as {
    qr_text: string;
    qr_png: string;
    sas: string;
    expires_in_ms: number;
  };
  qrImg.src = v.qr_png;
  qrText.textContent = v.qr_text;
  // Scadenza sincronizzata col clock che l'engine verifica all'handshake
  // (`issued_at` + QR_TTL): allo zero la tray rigenera da sola, così il QR
  // mostrato non è mai scaduto per chi lo fotografa. Default 5 minuti se il
  // campo manca: un `0` farebbe rigenerare in loop.
  qrDeadline = Date.now() + (v.expires_in_ms ?? 300_000);
  tickQrExpiry();
  // SAS visibile solo dopo handshake: se presente mostrala per la conferma
  // anti-MITM con lo schermo del telefono.
  const sasEl = document.getElementById("sas");
  if (sasEl) sasEl.textContent = v.sas ? `${t("sas.verify", lang)}: ${v.sas}` : "";
}

/** Epoch ms in cui il QR corrente scade (0 = sconosciuto, si rigenera subito). */
let qrDeadline = 0;
/** Evita doppie rigenerazioni mentre una è già in volo (intervallo + click). */
let regenerating = false;

function tickQrExpiry(): void {
  if (!hasIpc || regenerating) return;
  const remaining = qrDeadline - Date.now();
  if (remaining <= 0) {
    void autoRegenQr();
    return;
  }
  const secs = Math.max(1, Math.ceil(remaining / 1000));
  const mm = String(Math.floor(secs / 60)).padStart(2, "0");
  const ss = String(secs % 60).padStart(2, "0");
  qrExpiryEl.textContent = `${t("qr.validFor", lang)} ${mm}:${ss}`;
  qrExpiryEl.dataset.state = secs <= 60 ? "expiring" : "ok";
  qrExpiryEl.hidden = false;
}

async function autoRegenQr(): Promise<void> {
  if (!hasIpc || regenerating) return;
  regenerating = true;
  qrExpiryEl.dataset.state = "expired";
  qrExpiryEl.textContent = t("qr.expired", lang);
  qrExpiryEl.hidden = false;
  try {
    await invoke("regenerate_qr");
    await refreshQr();
    log(t("log.qrRegen", lang));
  } catch {
    // Engine irraggiungibile: il badge resta "SCADUTO" e il tick riproverà
    // alla prossima rotazione dell'intervallo, senza bombardare di invoke.
    qrExpiryEl.dataset.state = "expired";
    qrExpiryEl.textContent = t("qr.expired", lang);
    qrExpiryEl.hidden = false;
  } finally {
    regenerating = false;
  }
}

async function refreshStatus() {
  const s = (await invoke("get_status")) as {
    vpcd_up: boolean;
    mobile_online: boolean;
    https: string;
    wss_extension: string;
    crypto: string;
  };
  const up = s.vpcd_up ? t("status.up", lang) : t("status.down", lang);
  const mob = s.mobile_online ? t("status.online", lang) : t("status.offline", lang);
  statusEl.textContent =
    `${t("status.vpcd", lang)}: ${up} · ${t("status.mobile", lang)}: ${mob} · ${s.https} · ${s.crypto}`;
  statusMetaEl.textContent = `${t("status.updated", lang)} ${new Date().toLocaleTimeString()}`;
  statusMetaEl.hidden = false;
}

regenBtn.onclick = async () => {
  if (!hasIpc) return;
  await invoke("regenerate_qr");
  await refreshQr();
  log(t("log.qrRegen", lang));
};

type ConsentRow = { id: string; label: string; created_at_ms: number };
type ClientRow = { id: string; label: string; last_seen_ms: number };

/** Banner per ogni richiesta di consenso pendente, con Consenti/Rifiuta. */
async function renderConsents(): Promise<void> {
  const box = document.getElementById("consents");
  if (!box) return;
  box.innerHTML = "";
  let rows: ConsentRow[];
  try {
    rows = (await invoke("list_consents")) as ConsentRow[];
  } catch {
    return;
  }
  if (rows.length === 0) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = t("consents.empty", lang);
    box.append(p);
    pendingCountEl.hidden = true;
    document.title = "NFC Smartcard Remote";
    return;
  }
  pendingCountEl.textContent = String(rows.length);
  pendingCountEl.hidden = false;
  // La card può stare sotto il bordo (QR di pairing grande, finestra stretta):
  // quando c'è una richiesta la portiamo al centro del viewport.
  box.scrollIntoView({ behavior: "smooth", block: "center" });
  document.title = `⚠ ${rows.length} ${t("consent.pending", lang)} — NFC Smartcard Remote`;

  for (const c of rows) {
    const row = document.createElement("div");
    row.className = "row";
    const label = document.createElement("span");
    label.className = "row-label";
    const when = new Date(c.created_at_ms).toLocaleTimeString();
    label.textContent = `${c.label} — ${t("consent.pending", lang)} · ${when}`;
    const actions = document.createElement("span");
    actions.style.display = "flex";
    actions.style.gap = "6px";
    const ok = document.createElement("button");
    ok.className = "btn-approve";
    ok.textContent = t("consent.approve", lang);
    ok.onclick = async () => {
      await invoke("approve_consent", { id: c.id });
      await renderConsents();
      await renderClients();
      log(`${c.label}: ${t("consent.approved", lang)}`);
    };
    const no = document.createElement("button");
    no.className = "btn-reject";
    no.textContent = t("consent.reject", lang);
    no.onclick = async () => {
      await invoke("reject_consent", { id: c.id });
      await renderConsents();
      log(`${c.label}: ${t("consent.rejected", lang)}`);
    };
    actions.append(ok, no);
    row.append(label, actions);
    box.append(row);
  }
}

/** Elenco dei client autorizzati, con revoca. */
async function renderClients(): Promise<void> {
  const box = document.getElementById("clients");
  if (!box) return;
  box.innerHTML = "";
  let rows: ClientRow[];
  try {
    rows = (await invoke("list_clients")) as ClientRow[];
  } catch {
    return;
  }
  if (rows.length === 0) {
    const p = document.createElement("p");
    p.style.fontSize = "12px";
    p.textContent = t("clients.empty", lang);
    box.append(p);
    return;
  }
  for (const c of rows) {
    const row = document.createElement("div");
    row.className = "row";
    const label = document.createElement("span");
    label.className = "row-label";
    const last = new Date(c.last_seen_ms).toLocaleTimeString();
    label.textContent = `${c.label} (${t("clients.lastSeen", lang)}: ${last})`;
    const revoke = document.createElement("button");
    revoke.className = "btn-revoke";
    revoke.textContent = t("clients.revoke", lang);
    revoke.onclick = async () => {
      await invoke("revoke_client", { id: c.id });
      await renderClients();
      log(`${c.label}: ${t("clients.title", lang)} revocato`);
    };
    row.append(label, revoke);
    box.append(row);
  }
}

// Eventi engine -> UI (SAS post-handshake, carta, reader, consensi).
async function main(): Promise<void> {
  if (!hasIpc) {
    showStandaloneNotice();
    return;
  }
  await listen<string | Record<string, unknown>>("engine-event", (e) => {
    const payload = e.payload;
    if (payload && typeof payload === "object" && payload.kind === "consent") {
      const action = payload.action;
      if (action === "requested" || action === "resolved") {
        void renderConsents();
        void renderClients();
        if (action === "resolved") {
          const ok = payload.ok === true;
          log(ok ? t("consent.approved", lang) : t("consent.rejected", lang));
        }
      }
      return;
    }
    if (payload && typeof payload === "object" && payload.kind === "mobile") {
      // Telefono associato: la SAS va confrontata su entrambi gli schermi
      // (anti-MITM). La mostriamo subito, non al prossimo refresh del QR.
      const sas = typeof payload.sas === "string" ? payload.sas : "";
      const sasEl = document.getElementById("sas");
      if (sasEl) sasEl.textContent = sas ? `${t("sas.verify", lang)}: ${sas}` : "";
      log(`${t("log.mobileConnected", lang)}${sas ? ` · ${sas}` : ""}`);
      return;
    }
    if (payload && typeof payload === "object" && payload.kind === "scanned") {
      // Beacon: la webapp ha scansionato un QR valido (informativo, non è
      // un'autorizzazione: quella arriva con l'associazione dell'app nativa).
      log(t("log.qrScanned", lang));
      return;
    }
    log(String(payload ?? ""));
  });
  await refreshQr();
  await refreshStatus();
  await renderConsents();
  await renderClients();
  setInterval(refreshStatus, 5000);
  setInterval(() => void renderConsents(), 5000);
  setInterval(tickQrExpiry, 1000);
}

void main();
