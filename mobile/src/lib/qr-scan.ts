// Scanner QR: wrapper sottile su @tauri-apps/plugin-barcode-scanner.
// Se il plugin non è installato, fallback a input manuale (dev).
import { parseQr, startSecureSession } from "./secure-channel";

export async function scanAndPair(): Promise<string> {
  // Tenta scan camera; su desktop/dev usa prompt.
  let text: string;
  try {
    // Enumeration `Format`: `"QR_CODE"`, non la stringa `"qr_code"` (vedi
    // secure-channel.ts). Qui la stringa grezza reggeva perché mancava un
    // type-check su questa cartella.
    const { Format, scan } = await import("@tauri-apps/plugin-barcode-scanner");
    const res = await scan({ windowed: true, formats: [Format.QRCode] });
    text = (res as { content: string }).content;
  } catch {
    text = prompt("Incolla contenuto QR NFC://2/...") ?? "";
  }
  const params = parseQr(text.trim());
  return startSecureSession(params);
}
