// Tipi wire extension<->engine (mirror di shared-ui-ts, duplicati per
// build senza bundler esterno: l'estensione compila con solo tsc).
export type CardStatus = "inserted" | "removed" | "reading";
export type ExtEvent =
  | { type: "card_status"; status: CardStatus; atr_hex?: string | null }
  | { type: "reader_connected"; name: string }
  | { type: "reader_disconnected"; name: string }
  | { type: "hello"; engine: string };
export interface TransmitRequest {
  type: "transmit_apdu";
  request_id: string;
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
