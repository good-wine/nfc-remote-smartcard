// Tipi condivisi: unica fonte di verità TS per desktop/extension/webapp.
// Mirror di shared-core-rust/src/protocol.rs (JSON su /v1/extension).
import { decodeApduPayload, hexToBytes } from "./codec.js";

export type CardStatus = "inserted" | "removed" | "reading";

export type ExtEvent =
  | { type: "card_status"; status: CardStatus; atr_hex?: string | null }
  | { type: "reader_connected"; name: string }
  | { type: "reader_disconnected"; name: string }
  | { type: "hello"; engine: string };

export interface TransmitRequest {
  type: "transmit_apdu";
  request_id: string;
  /** Hex maiuscolo oppure `b64:<base64>`. */
  payload_hex: string;
  timeout_ms?: number;
}

export interface ApduReply {
  type: "apdu_reply";
  request_id: string;
  data_hex: string;
  sw1: number;
  sw2: number;
  latency_ms: number;
}

export interface ErrorReply {
  type: "error";
  code: number;
  message: string;
  request_id?: string;
}

/** Valida APDU ISO7816 minima (4B header, max 65535B dopo decode). */
export function assertValidApduHex(payloadHex: string): void {
  decodeApduPayload(payloadHex);
}

/** Helper: compone SELECT AID. */
export function selectAid(aidHex: string): string {
  const aid = hexToBytes(aidHex);
  const lc = aid.length.toString(16).padStart(2, "0");
  return `00A40400${lc}${aidHex.toUpperCase()}00`;
}
