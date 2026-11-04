// Localizzazione degli errori di pairing (codici emessi dal plugin Rust mobile).
//
// Il plugin non restituisce prosa: restituisce `{ code, detail }`. Il motivo è
// che una stringa non è localizzabile e non è classificabile — per distinguere
// "certificato rifiutato" da "timeout di rete" il frontend dovrebbe farne
// un'analisi testuale, che è fragile per costruzione perché il testo verrebbe
// toccato dalla traduzione o da un refactor.
//
// I codivi sono un contratto con `code` in `mobile/src-tauri/src/lib.rs`: i due
// lati sono in linguaggi diversi e non condividono un tipo, quindi una
// rinomina romperebbe la traduzione senza alcun errore di compilazione. Il
// fallback esplicito qui sotto è la difesa: un codice sconosciuto mostra un
// testo neutro **più il dettaglio tecnico**, che non si perde.

import { tOr, type Lang } from "./i18n.js";

/** Codici stabili: devono corrispondere a `nfc_mobile::code`. */
export const PairingCode = {
  QrInvalid: "qrInvalid",
  QrExpired: "qrExpired",
  QrUsed: "qrUsed",
  PinRejected: "pinRejected",
  Unreachable: "unreachable",
  NoPlainChannel: "noPlainChannel",
  HandshakeTimeout: "handshakeTimeout",
  PeerClosed: "peerClosed",
  BadFrame: "badFrame",
  PeerMismatch: "peerMismatch",
  ProtoMismatch: "protoMismatch",
  DecryptFailed: "decryptFailed",
  Internal: "internal",
} as const;

export type PairingCodeValue = (typeof PairingCode)[keyof typeof PairingCode];

/** Errore strutturato che attraversa l'IPC Tauri. */
export interface PairingError {
  code: PairingCodeValue | string;
  detail?: string;
}

/**
 * Riconosce l'errore strutturato del plugin.
 *
 * La guardia serve perché `invoke` può rifiutare con un valore qualsiasi: una
 * stringa (errori di Tauri/Daeno, plugin assenti) o un oggetto senza `code`. In
 * quel caso non si deve inventare una localizzazione: si mostra il dettaglio
 * grezzo, che è comunque più utile di "errore sconosciuto".
 */
export function asPairingError(e: unknown): PairingError | null {
  if (e && typeof e === "object" && typeof (e as { code?: unknown }).code === "string") {
    const { code, detail } = e as { code: string; detail?: unknown };
    return { code, detail: typeof detail === "string" ? detail : undefined };
  }
  return null;
}

/**
 * Testo localizzato per un errore di pairing, con il dettaglio tecnico in coda.
 *
 * Il dettaglio non viene tradotto (non ha una traduzione: è output di rete o di
 * confronto) ma non viene neppure perso: è spesso l'unica informazione utile
 * quando il codice è quello giusto ma la causa è inaspettata.
 */
export function pairingErrorText(e: PairingError, lang?: Lang): string {
  const msg = tOr(e.code, `Errore di pairing (${e.code})`, lang);
  return e.detail ? `${msg} (${e.detail})` : msg;
}

/** Estrae il testo localizzato da un errore sparso, di qualunque provenienza. */
export function describePairingError(e: unknown, lang?: Lang): string {
  const strutturato = asPairingError(e);
  if (strutturato) return pairingErrorText(strutturato, lang);
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  return tOr(PairingCode.Internal, "Errore interno", lang);
}

/**
 * Errore con codice di pairing, da lanciare dal frontend.
 *
 * Estende `Error` invece di lanciare un oggetto nudo per non perdere lo stack:
 * `describePairingError` guarda il `code` **prima** di `instanceof Error`, quindi
 * la localizzazione prevale senza che il caso "giusto ma non strutturato" peggiori.
 */
export function pairingFailure(code: PairingCodeValue | string, detail?: string): Error {
  const e = new Error(detail ?? code);
  (e as Error & { code: string }).code = code;
  return e;
}
