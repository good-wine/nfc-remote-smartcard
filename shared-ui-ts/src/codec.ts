// Codec esadecimale/base64 senza `Buffer` (browser-safe).
// `shared-ui-ts` gira in estensione e webapp: nessuna dipendenza Node.

const HEX = "0123456789ABCDEF";

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += (HEX[(b >> 4) & 0xf] ?? "0") + (HEX[b & 0xf] ?? "0");
  return out;
}

export function hexToBytes(hexStr: string): Uint8Array {
  const s = hexStr.trim().replace(/^0x/i, "");
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) throw new Error("hex non valido");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Decodifica `payload_hex` (hex oppure `b64:<base64>`) in byte APDU. */
export function decodeApduPayload(payloadHex: string): Uint8Array {
  const raw = payloadHex.startsWith("b64:") ? b64ToBytes(payloadHex.slice(4)) : hexToBytes(payloadHex);
  if (raw.length < 4 || raw.length > 65535) throw new Error("APDU non valida (4..65535B)");
  return raw;
}
