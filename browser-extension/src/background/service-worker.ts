// Service Worker MV3 2026: WSS persistente verso wss://nfc.local:8443/v1/extension
// con fallback a ws://127.0.0.1:8080 (CA non ancora fidata o hosts mancante).
// Stato dell'arte:
// - `chrome.alarms` come keepalive anti-sospensione SW.
// - Selezione endpoint: primario HTTPS; dopo 2 chiusure consecutive senza mai
//   aver aperto (tipico: ERR_CERT_AUTHORITY_INVALID / DNS), passa al fallback;
//   ogni 20 alarm (~10min) riprova il primario (auto-upgrade dopo trust CA).
// - RICHIEDE HTTPS per default: il fallback in chiaro resta ma è opt-in
//   (`requireHttps=false`), perché è il confine d'autenticazione del READER:
//   un processo locale senza il token non ci passa comunque.
// - Autenticazione del canale: il primo frame è `hello` + token emesso
//   dall'engine **con consenso dell'utente** (banner nella tray). Senza token
//   l'engine apre il consenso; approvato, il token arriva su `consent_status`
//   e vive in `storage.local` (mai esposto a pagine: solo il SW lo usa).
// - `storage.session` per l'endpoint scelto (effimero), `storage.local` log.

import type { ApduReply, ExtEvent } from "../shared/types.js";

const ENGINE_PRIMARY = "wss://nfc.local:8443/v1/extension";
const ENGINE_FALLBACK = "ws://127.0.0.1:8080/v1/extension";
let engineUrl = ENGINE_PRIMARY;
let fallbackArmed = false;
// Pin HTTPS (postazioni sensibili): se true, MAI fallback in chiaro.
let requireHttps = true;
// Token locale emesso dall'engine col consenso: vive solo nel SW.
let localToken = "";
let consentPending = false;
// L'hello del primo frame deve usare il token già letto: se `connect()`
// corresse prima che `storage.local` risponda, l'engine aprirebbe un consenso
// e poi riceverebbe un hello col token giusto — un falso banner "pending".
// Si gata quindi l'invio sul promise di lettura (non sul valore).
const tokenRead = chrome.storage.local.get({ token: "" });
void tokenRead.then((v) => {
  localToken = (v as { token?: string }).token ?? "";
});
void chrome.storage.sync.get({ requireHttps: true }).then((v) => {
  requireHttps = (v as { requireHttps?: boolean }).requireHttps !== false;
});
chrome.storage.onChanged.addListener((chg, area) => {
  if (area === "sync" && chg.requireHttps) requireHttps = chg.requireHttps.newValue !== false;
});
const ALARM_KEEPALIVE = "nfc-keepalive";
let ws: WebSocket | null = null;
let retries = 0;
let lastStatus: ExtEvent | null = null;
const pending = new Map<string, { res: (v: ApduReply) => void; rej: (e: Error) => void }>();

function backoffMs(): number {
  const exp = Math.min(10_000, 500 * 2 ** retries);
  return exp + Math.random() * 250;
}

function connect(): void {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
  let sock: WebSocket;
  try {
    sock = new WebSocket(engineUrl);
  } catch {
    schedule();
    return;
  }
  ws = sock;
  sock.onopen = () => {
    retries = 0;
    if (engineUrl === ENGINE_FALLBACK) {
      // Fallback attivo: riprova il primario tra ~10min (auto-upgrade post-trust).
      void chrome.storage.session.set({ engineUrl, reprobeAt: Date.now() + 10 * 60_000 });
    } else {
      fallbackArmed = false;
      void chrome.storage.session.set({ engineUrl });
    }
    // Primo frame = autenticazione del canale locale. Con token valido si
    // passa subito; senza, l'engine apre il consenso (banner sulla tray).
    // Mai inviare altro prima di questo frame: il guard dell'engine chiude.
    // L'invio è gated su `tokenRead`: mai aprire il consenso per un token
    // che esiste ma non è ancora arrivato da `storage.local`.
    const sendHello = (): void => {
      try {
        sock.send(
          JSON.stringify(localToken ? { type: "hello", token: localToken } : { type: "hello" }),
        );
      } catch {
        /* onclose/onerror seguirà */
      }
    };
    void tokenRead.then(sendHello);
  };
  sock.onmessage = (ev) => {
    let msg: { type?: string };
    try {
      msg = JSON.parse(ev.data as string);
    } catch {
      return;
    }
    if (msg.type === "apdu_reply") {
      const r = msg as unknown as ApduReply;
      pending.get(r.request_id)?.res(r);
      pending.delete(r.request_id);
      void appendLog(`APDU ok ${r.request_id.slice(0, 8)} SW=${r.sw1.toString(16)}${r.sw2.toString(16)}`);
      return;
    }
    if (msg.type === "error") {
      const e = msg as unknown as { request_id?: string; message: string };
      if (e.request_id) {
        pending.get(e.request_id)?.rej(new Error(e.message));
        pending.delete(e.request_id!);
      }
      if (String(e.message).includes("non autorizzato")) {
        // 4406 handshake: il token non è valido/revocato. Il close a seguire
        // ripulisce `localToken`; qui si aggiorna subito la UI.
        consentPending = true;
        void chrome.action.setBadgeText({ text: "?" });
        void chrome.runtime
          .sendMessage({ kind: "consent-status", consentPending: true })
          .catch(() => {});
      }
      return;
    }
    if (msg.type === "consent_status") {
      const m = msg as unknown as { status: string; token?: string };
      if (m.status === "pending") {
        consentPending = true;
        void chrome.action.setBadgeText({ text: "?" });
        void appendLog("consenso richiesto: approva dal desktop");
      } else if (m.status === "approved" && m.token) {
        consentPending = false;
        localToken = m.token;
        void chrome.storage.local.set({ token: m.token });
        void chrome.action.setBadgeText({ text: "✓" });
        void appendLog("accesso autorizzato dal desktop");
        void chrome.runtime
          .sendMessage({ kind: "consent-status", consentPending: false, authorized: true })
          .catch(() => {});
      } else if (m.status === "rejected") {
        consentPending = false;
        void chrome.action.setBadgeText({ text: "!" });
        void appendLog("consenso rifiutato dal desktop");
        void chrome.runtime
          .sendMessage({ kind: "consent-status", consentPending: false })
          .catch(() => {});
      }
      if (m.status !== "approved") return;
      // Il token è stato consegnato: `onclose` (l'engine chiude dopo
      // `consent_status`) riconnetterà con il nuovo token.
      return;
    }
    lastStatus = msg as ExtEvent;
    void chrome.runtime.sendMessage({ kind: "engine-event", event: msg }).catch(() => {});
    if ((msg as { type?: string }).type === "card_status") {
      const s = (msg as { status: string }).status;
      void chrome.action.setBadgeText({ text: s === "inserted" ? "●" : "" });
      void chrome.action.setBadgeBackgroundColor({ color: "#0a84ff" });
    }
  };
  const onDead = (ev?: CloseEvent) => {
    ws = null;
    retries++;
    if (ev?.code === 4406) {
      // Canale locale rifiutato: token revocato o mai emesso. Si cancella il
      // token (l'engine non degrada mai al consenso da un token invalido) e si
      // riparte dal flusso di consenso esplicito alla prossima connessione.
      localToken = "";
      void chrome.storage.local.remove("token");
      consentPending = true;
      void chrome.action.setBadgeText({ text: "?" });
      void appendLog("accesso non autorizzato (4406): riapro il desktop e approva il banner");
    }
    // Mai aperto sul primario per 2 volte di fila -> probabile CA/hosts:
    // passa al fallback loopback, SALVO pin HTTPS (postazioni sensibili).
    if (engineUrl === ENGINE_PRIMARY && retries >= 2 && !fallbackArmed && !requireHttps) {
      fallbackArmed = true;
      engineUrl = ENGINE_FALLBACK;
      void appendLog("nfc.local non raggiungibile (CA/hosts?) -> fallback 127.0.0.1:8080");
    }
    if (engineUrl === ENGINE_PRIMARY && retries >= 2 && requireHttps) {
      void chrome.action.setBadgeText({ text: "TLS" });
      void appendLog("nfc.local non raggiungibile, pin HTTPS attivo: niente fallback");
    }
    if (ev?.code !== 4406) void chrome.action.setBadgeText({ text: "!" });
    // Fail-fast sui pending: la pagina riceve errore invece di hang su SW kill.
    for (const [id, p] of pending) {
      pending.delete(id);
      p.rej(new Error("engine disconnesso (SW riavviato)"));
    }
    schedule();
  };
  ws.onclose = (ev) => onDead(ev);
  ws.onerror = () => onDead();
}

function schedule(): void {
  setTimeout(connect, backoffMs());
}

// Keepalive 2026: alarm ogni 30s (minimo Chrome) + ping applicativo.
// Dichiarare `alarms` nei permessi; l'alarm risveglia il SW anche se sospeso.
void chrome.alarms.create(ALARM_KEEPALIVE, { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name !== ALARM_KEEPALIVE) return;
  // Auto-upgrade: se in fallback da >10min, riprova il primario (CA fidata?).
  if (engineUrl === ENGINE_FALLBACK) {
    void chrome.storage.session.get({ reprobeAt: 0 }).then((v) => {
      if (Date.now() >= ((v as { reprobeAt?: number }).reprobeAt ?? 0)) {
        engineUrl = ENGINE_PRIMARY;
        fallbackArmed = false;
        retries = 0;
        void appendLog("riprovo primario wss://nfc.local:8443");
      }
    });
  }
  if (!ws || ws.readyState !== WebSocket.OPEN) connect();
  else {
    try {
      ws.send(JSON.stringify({ type: "ping" }));
    } catch {
      /* riconnessione al prossimo alarm */
    }
  }
});

chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);
// Ripristina endpoint scelto (primario di default dopo install/update).
void chrome.storage.session.get({ engineUrl: ENGINE_PRIMARY }).then((v) => {
  const u = (v as { engineUrl?: string }).engineUrl;
  engineUrl = u === ENGINE_FALLBACK ? ENGINE_FALLBACK : ENGINE_PRIMARY;
  connect();
});
// @ts-expect-error MV3: service worker globale
self.skipWaiting?.();
connect();

// ---- Messaging da popup / side-panel / content-script ----
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.kind === "transmit") {
    transmit(msg.payloadHex as string, msg.timeoutMs as number | undefined)
      .then((r) => sendResponse({ ok: true, reply: r }))
      .catch((e: Error) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
  if (msg?.kind === "get-status") {
    sendResponse({
      ok: true,
      connected: ws?.readyState === WebSocket.OPEN,
      lastStatus,
      via: engineUrl,
      requireHttps,
      authorized: !!localToken,
      consentPending,
    });
    return false;
  }
  if (msg?.kind === "content-transmit") {
    void (async () => {
      const tabUrl = sender.tab?.url ?? "";
      const origin = (() => {
        try {
          const u = new URL(tabUrl);
          return `${u.protocol}//${u.host}`;
        } catch {
          return "";
        }
      })();
      const { origins = [] } = (await chrome.storage.sync.get({ origins: [] })) as { origins: string[] };
      if (!origins.includes(origin)) {
        sendResponse({ ok: false, error: `origin non autorizzata: ${origin}` });
        return;
      }
      try {
        const r = await transmit(msg.payloadHex as string, msg.timeoutMs);
        sendResponse({ ok: true, reply: r });
      } catch (e) {
        sendResponse({ ok: false, error: (e as Error).message });
      }
    })();
    return true;
  }
});

function transmit(payloadHex: string, timeoutMs = 8000): Promise<ApduReply> {
  return new Promise((res, rej) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      rej(new Error("engine desktop non raggiungibile (avvia la tray app 0.2+)"));
      return;
    }
    const request_id = crypto.randomUUID();
    pending.set(request_id, { res, rej });
    ws.send(JSON.stringify({ type: "transmit_apdu", request_id, payload_hex: payloadHex, timeout_ms: timeoutMs }));
    setTimeout(() => {
      if (pending.has(request_id)) {
        pending.delete(request_id);
        rej(new Error("timeout APDU"));
      }
    }, timeoutMs + 2000);
  });
}

async function appendLog(line: string): Promise<void> {
  const { log = [] } = (await chrome.storage.local.get({ log: [] })) as { log: string[] };
  log.unshift(`${new Date().toLocaleTimeString()} ${line}`);
  await chrome.storage.local.set({ log: log.slice(0, 200) });
}
