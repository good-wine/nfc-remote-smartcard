/* tslint:disable */
/* eslint-disable */

/**
 * Parsa e **valida** un QR di pairing; ritorna `Ok(json)` con un riassunto
 * sicuro da mostrare, o `Err(messaggio)` con il motivo del rifiuto.
 *
 * `now_unix_secs` separa la diagnostica della scadenza dal test: la UI lo
 * calcola da `Date.now()`.
 *
 * # Errors
 * Messaggio di errore localizzato a monte (lato JS): qui arriva il testo
 * italiano di `nfc_core` (stesso identico che dà il telefono nativo).
 */
export function parse_pairing_qr(text: string, now_unix_secs: bigint): string;

/**
 * Sonda crittografica: se anche solo il DH X25519 non gira su wasm, lo scopro qui.
 */
export function sondina(peer: Uint8Array): Uint8Array;

/**
 * Validazione/normalizzazione APDU per la console.
 *
 * # Errors
 * Messaggio in italiano sul perché l'hex non è un APDU valido.
 */
export function validate_apdu(hex: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly parse_pairing_qr: (a: number, b: number, c: number, d: bigint) => void;
    readonly sondina: (a: number, b: number, c: number) => void;
    readonly validate_apdu: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export2: (a: number, b: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
