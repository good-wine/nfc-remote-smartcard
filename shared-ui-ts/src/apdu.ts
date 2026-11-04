// Helper APDU ISO7816 / CIE: SELECT, READ BINARY, MSE, PSO.
// Usati da webapp/extension per comporre payload_hex senza conoscere il protocollo.
import { bytesToHex } from "./codec.js";
/** Byte -> HEX maiuscolo. */
export function hex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

/** SELECT FILE by FID (es. 3F00). */
export function selectFile(fidHex: string): string {
  return `00A4000C02${fidHex}`;
}

/** READ BINARY (offset, len; len=0 => Le=256). */
export function readBinary(offset = 0, len = 0): string {
  const p1 = ((offset >> 8) & 0xff).toString(16).padStart(2, "0");
  const p2 = (offset & 0xff).toString(16).padStart(2, "0");
  const le = len.toString(16).padStart(2, "0");
  return `00B0${p1}${p2}${le}`.toUpperCase();
}

/** Verifica SW 9000. */
export function isOk(sw1: number, sw2: number): boolean {
  return sw1 === 0x90 && sw2 === 0x00;
}
