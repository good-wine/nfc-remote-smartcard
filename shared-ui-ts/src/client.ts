// Client WS 2026: primario `wss://nfc.local:8443` + fallback `ws://127.0.0.1:8080`.
// Riconnessione esponenziale + multiplexing request_id -> Promise.
// Da pagine HTTPS (SecureContext) il primario evita mixed-content; il fallback
// serve se CA/hosts non ancora installati.
//
// **Canale locale autenticato (2026)**: il primo frame è `hello` con il token
// emesso dall'engine con consenso dell'utente (vedi `docs/SECURITY.md` §7).
// - token presente -> `hello+token`; il canale diventa operativo quando
//   l'engine risponde `hello`.
// - token assente  -> `hello` senza token: l'engine apre il consenso (banner
//   sulla tray) e risponde `consent_status:*`; `approved` consegna il token,
//   che il chiamante deve persistere (`onConsent`).
// Il resto del protocollo è invariato.
import type { ApduReply, ErrorReply, ExtEvent, TransmitRequest } from "./types.js";

export type EventHandler = (ev: ExtEvent) => void;

/** Stato dell'autenticazione del canale locale. */
export type AuthState = "untried" | "pending" | "authed";
/** Notifiche del flusso di consenso/revoca per la UI. */
export type ConsentNotice =
  | { status: "pending" }
  | { status: "approved"; token: string }
  | { status: "rejected" }
  | { status: "expired" }
  | { status: "revoked" };

export const ENGINE_PRIMARY = "wss://nfc.local:8443/v1/extension";
export const ENGINE_FALLBACK = "ws://127.0.0.1:8080/v1/extension";

export class EngineClient {
  private ws: WebSocket | null = null;
  private urls: string[];
  private urlIdx = 0;
  /** Cache dell'URL attivo: `urls[idx]` è `string | undefined` con
   * `noUncheckedIndexedAccess`, quindi lo fissiamo al costruttore. */
  private active: string;
  private pending = new Map<string, { res: (v: ApduReply) => void; rej: (e: Error) => void; timer: number }>();
  private handlers = new Set<EventHandler>();
  private retries = 0;
  private closed = false;
  private token = "";
  private auth: AuthState = "untried";
  /** Dopo un rifiuto/scadenza del consenso NON ci si riconnette da soli:
   * ogni retry ricreerebbe un consenso e la tray continuerebbe a saltare su
   * con nuovi banner. Serve un'azione esplicita dell'utente. */
  private stopReconnect = false;

  /** Callback del consenso: `approved` dà il token da mettere in `localStorage`. */
  onConsent: ((n: ConsentNotice) => void) | null = null;

  constructor(url = ENGINE_PRIMARY, fallback = ENGINE_FALLBACK) {
    this.urls = url === fallback ? [fallback] : [url, fallback];
    this.active = this.urls[0] ?? url;
  }

  /** URL attivo (primario o fallback dopo 2 chiusure senza open). */
  get url(): string {
    return this.active;
  }

  get hasToken(): boolean {
    return this.token !== "";
  }

  /** Token locale (da `localStorage`) da presentare al primo frame. */
  setToken(token: string): void {
    this.token = token;
    this.auth = "untried";
  }

  get authState(): AuthState {
    return this.auth;
  }

  onEvent(h: EventHandler): () => void {
    this.handlers.add(h);
    return () => this.handlers.delete(h);
  }

  connect(): void {
    this.closed = false;
    this.stopReconnect = false;
    this.open();
  }

  disconnect(): void {
    this.closed = true;
    this.ws?.close();
  }

  private open(): void {
    const sock = new WebSocket(this.active);
    this.ws = sock;
    this.auth = "untried";
    sock.onopen = () => {
      this.retries = 0;
      // Primo frame = autenticazione. L'engine rifiuta (4406) qualunque altro
      // frame come prima cosa: mai `ping`/`transmit` prima di questo.
      try {
        sock.send(
          JSON.stringify(this.token ? { type: "hello", token: this.token } : { type: "hello" }),
        );
      } catch {
        /* onclose seguirà */
      }
    };
    sock.onmessage = (ev) => {
      let msg: unknown;
      try {
        msg = JSON.parse(ev.data as string);
      } catch {
        return;
      }
      const t = (msg as { type?: string }).type;
      if (t === "consent_status") {
        const m = msg as unknown as { status: string; token?: string };
        if (m.status === "approved" && m.token) {
          this.token = m.token;
          // L'engine chiude dopo aver consegnato il token: il client ricomette
          // con `hello+token`. Finché non arriva l'hello non siamo "authed".
          this.auth = "untried";
          this.stopReconnect = false;
          this.onConsent?.({ status: "approved", token: m.token });
        } else if (m.status === "pending") {
          this.auth = "pending";
          this.stopReconnect = false;
          this.onConsent?.({ status: "pending" });
        } else if (m.status === "rejected") {
          // Niente riconnessione automatica dopo il rifiuto: l'utente deve
          // richiedere esplicitamente (il socket si chiuderà a seguire).
          this.auth = "untried";
          this.stopReconnect = true;
          this.onConsent?.({ status: "rejected" });
        }
        // Inoltra anche come evento generico (log).
        for (const h of this.handlers) {
          try {
            h(msg as ExtEvent);
          } catch {
            /* handler non deve rompere il loop */
          }
        }
        return;
      }
      if (t === "hello") {
        this.auth = "authed";
      }
      if (t === "apdu_reply") {
        const r = msg as ApduReply;
        const p = this.pending.get(r.request_id);
        if (p) {
          clearTimeout(p.timer);
          this.pending.delete(r.request_id);
          p.res(r);
        }
        return;
      }
      if (t === "error") {
        const e = msg as ErrorReply;
        // 401 senza request_id = rifiuto del canale (token revocato/invalido):
        // l'engine chiude a 4406 e non degrada al consenso. Qui si riparte da
        // zero: niente token = consenso esplicito alla prossima connessione.
        if (e.request_id) {
          const p = this.pending.get(e.request_id);
          if (p) {
            clearTimeout(p.timer);
            this.pending.delete(e.request_id);
            p.rej(new Error(`engine ${e.code}: ${e.message}`));
          }
        } else {
          this.token = "";
          this.auth = "untried";
          this.onConsent?.({ status: "revoked" });
        }
        return;
      }
      // Push event (card_status, reader_*, ping/pong, …).
      for (const h of this.handlers) {
        try {
          h(msg as ExtEvent);
        } catch {
          /* handler non deve rompere il loop */
        }
      }
    };
    sock.onclose = () => {
      if (this.closed) return;
      if (this.auth === "pending") {
        // Il consenso è scaduto (o il socket si è chiuso) senza esito: niente
        // riconnessione automatica, altrimenti si ricrea un consenso a ogni
        // retry e la tray salta su all'infinito. Torna allo stato "usual" e
        // lascia all'utente la richiesta esplicita.
        this.auth = "untried";
        this.onConsent?.({ status: "expired" });
        return;
      }
      if (this.stopReconnect) {
        this.stopReconnect = false;
        return;
      }
      // Dopo 2 chiusure senza open sul primario -> fallback (CA non fidata?).
      if (this.urlIdx === 0 && this.retries >= 1 && this.urls.length > 1) {
        this.urlIdx = 1;
        this.active = this.urls[1] ?? this.active;
      }
      // Backoff esponenziale con jitter: 500ms -> max 10s.
      const delay = Math.min(10_000, 500 * 2 ** this.retries) + Math.random() * 250;
      this.retries++;
      window.setTimeout(() => this.open(), delay);
    };
  }

  /** Invia APDU, risolve con ApduReply o rigetta su timeout/errore. */
  transmitApdu(payloadHex: string, timeoutMs = 8000): Promise<ApduReply> {
    const request_id = crypto.randomUUID();
    const req: TransmitRequest = { type: "transmit_apdu", request_id, payload_hex: payloadHex, timeout_ms: timeoutMs };
    return new Promise((res, rej) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        rej(new Error(`engine non connesso (${this.url})`));
        return;
      }
      if (this.auth === "pending") {
        rej(new Error("consenso in attesa: rispondi al banner nella tray del desktop"));
        return;
      }
      if (this.auth !== "authed") {
        rej(new Error("canale non ancora autenticato: attendi l'hello dell'engine"));
        return;
      }
      const timer = window.setTimeout(() => {
        this.pending.delete(request_id);
        rej(new Error("timeout APDU"));
      }, timeoutMs + 1000);
      this.pending.set(request_id, { res, rej, timer });
      this.ws!.send(JSON.stringify(req));
    });
  }
}