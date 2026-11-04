// Secure channel mobile: QR -> X25519 DH -> HKDF -> AES-GCM.
import { invoke } from "@tauri-apps/api/core";
import { Format, scan } from "@tauri-apps/plugin-barcode-scanner";
import { PairingCode, pairingFailure } from "../../../shared-ui-ts/src/pairing-errors.js";

export interface PairingParams {
  ip: string;
  port: number;
  nonceB64: string;
  pubkeyB64: string;
  mlkemB64?: string;
  /** Nome host canonico per `wss://` (es. `nfc.local`).
   *
   * Si preferisce a `ip` perché con mDNS `nfc.local` è risolvibile sul
   * telefono e il nome è coperto dal SAN del certificato. Con l'IP la
   * validazione per nome fallirebbe: la CA è locale e non emette IP-SAN. */
  host?: string;
  /** Porta TLS (8443). */
  tlsPort?: number;
  /** SHA-256(DER certificato foglia), base64url: pin del canale TLS. */
  tlsPinB64?: string;
  /** Scadenza del QR (epoch secondi), se presente.
   *
   * Non è un controllo di sicurezza: serve al plugin a distinguere "QR vecchio,
   * rigenera" da "certificato diverso, non fidarti". Senza, i due casi darebbero
   * lo stesso errore — quello che mostrerebbe anche un intercettatore. */
  expUnix?: number;
}

/** Parsa `NFC://2/<b64url(json)>` (accetta anche legacy `NFC://1/`). */
export function parseQr(text: string): PairingParams {
  for (const prefix of ["NFC://2/", "NFC://1/"]) {
    if (!text.startsWith(prefix)) continue;
    const b64 = text.slice(prefix.length).replace(/-/g, "+").replace(/_/g, "/");
    let o: Record<string, unknown>;
    try {
      const json = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "="));
      o = JSON.parse(json) as Record<string, unknown>;
    } catch (e) {
      // La base64 o il JSON non si decodificano: il codice è lo stesso di un QR
      // con campi mancanti, perché l'azione per l'utente è identica — rigenerare
      // e riscannare. Il dettaglio distingue i due casi nel log.
      throw pairingFailure(PairingCode.QrInvalid, `decodifica: ${(e as Error).message}`);
    }
    if (!o.ip || !o.port || !o.nonce_b64 || !o.pubkey_b64) {
      throw pairingFailure(PairingCode.QrInvalid, "payload incompleto");
    }
    const out: PairingParams = {
      ip: String(o.ip),
      port: Number(o.port),
      nonceB64: String(o.nonce_b64),
      pubkeyB64: String(o.pubkey_b64),
    };
    if (typeof o.mlkem_b64 === "string") out.mlkemB64 = o.mlkem_b64;
    // Canale TLS: si inoltra solo se il QR è completo. Inoltrare un host senza
    // pin farebbe degradare il Rust su `ws://` senza dirlo, mentre qui si
    // accetterebbe un canale in chiaro spacciato per protetto.
    if (typeof o.host === "string" && typeof o.tls_port === "number" && typeof o.tls_pin_b64 === "string") {
      out.host = o.host;
      out.tlsPort = o.tls_port;
      out.tlsPinB64 = o.tls_pin_b64;
    }
    if (typeof o.exp_unix === "number" && Number.isFinite(o.exp_unix)) out.expUnix = o.exp_unix;
    return out;
  }
  throw pairingFailure(PairingCode.QrInvalid, "prefisso non riconosciuto");
}

/** Avvia handshake E2EE via plugin Rust (ritorna session_id).
 *
 * Il materiale viaggia come un unico oggetto `qr`: i nomi dei campi corrispondono
 * a `QrMaterial` in `src-tauri/src/lib.rs` (serde `camelCase`). Scrivere i campi
 * come parametri sciolti qui dentro spezzerebbe la corrispondenza con la struct:
 * ogni aggiunta di campo dovrebbe ricontare due elenchi che possono divergere
 * senza dare alcun errore. */
export async function startSecureSession(p: PairingParams): Promise<string> {
  return (await invoke("mobile_handshake", {
    qr: {
      ip: p.ip,
      port: p.port,
      nonceB64: p.nonceB64,
      peerPubkeyB64: p.pubkeyB64,
      mlkemB64: p.mlkemB64 ?? null,
      host: p.host ?? null,
      tlsPort: p.tlsPort ?? null,
      tlsPinB64: p.tlsPinB64 ?? null,
      expUnix: p.expUnix ?? null,
    },
  })) as string;
}

/** Scan QR via plugin, poi avvia handshake. */
export async function scanAndPair(): Promise<string> {
  // `Format.QRCode`, non la stringa `"qr_code"`: l'enum del plugin vale
  // `"QR_CODE"`. La stringa grezza passava il type-check perché qui non c'era
  // alcun `tsconfig.json` (aggiunto dopo) e a runtime il plugin riceveva un
  // formato sconosciuto.
  const result = await scan({ formats: [Format.QRCode] });
  // `scan` può rifiutare anche per permesso fotocamera negato: non è un
  // problema di QR, quindi non si etichetta come tale. Il messaggio del plugin
  // arriva grezzo e comprensibile.
  if (!result || !result.content) throw new Error("scan fallito");
  const p = parseQr(result.content);
  return await startSecureSession(p);
}

/** Trasmette APDU cifrata via sessione attiva (il plugin cifra con AES-GCM). */
export async function secureTransmit(sessionId: string, apduHex: string, timeoutMs = 8000) {
  return (await invoke("mobile_transmit", { sessionId, apduHex, timeoutMs })) as {
    dataHex: string;
    sw1: number;
    sw2: number;
    latencyMs: number;
  };
}
