//! Webapp WASM 2026 (`webapp-pair`): il core `nfc-core` compilato per
//! `wasm32-unknown-unknown` senza CDN — gli asset girano sul dominio che serve
//! la webapp (engine o dev server).
//!
//! Espone due superfici:
//! - **`parse_pairing_qr`**: decodifica + **validazione completa** di un QR di
//!   pairing (`PairingPayload::decode_qr`: prefisso, base64, JSON, versioni,
//!   lunghezze, IP, dominio locale del `host`, pin TLS, scadenza). È la stessa
//!   validazione del telefono nativo, niente logica crittografica propria nel
//!   browser: se un QR è malformato o ostile lo diciamo qui, prima che la UI lo
//!   mostri come "engine valido".
//! - **`validate_apdu`**: decodifica + normalizza un APDU hex lato client, così
//!   la console non spedisce, e non incassa dal server, hex invalidi.
//!
//! `sondina` resta come sonda di compilazione: se il DH X25519 non gira su
//! wasm, un `cargo check` esplicito lo scopre.
//!
//! `[lints] workspace = true` forza `unsafe_code = forbid`: se l'espansione di
//! `wasm-bindgen` generasse `unsafe` nel nostro codice la build fallirebbe.

use wasm_bindgen::prelude::*;

/// Sonda crittografica: se anche solo il DH X25519 non gira su wasm, lo scopro qui.
#[wasm_bindgen]
#[must_use]
pub fn sondina(peer: &[u8]) -> Vec<u8> {
    let mut b = [0u8; 32];
    if peer.len() != 32 {
        return vec![];
    }
    b.copy_from_slice(peer);
    let eph = nfc_core::crypto::X25519Keypair::generate();
    eph.diffie_hellman(&b).to_vec()
}

/// Parsa e **valida** un QR di pairing; ritorna `Ok(json)` con un riassunto
/// sicuro da mostrare, o `Err(messaggio)` con il motivo del rifiuto.
///
/// `now_unix_secs` separa la diagnostica della scadenza dal test: la UI lo
/// calcola da `Date.now()`.
///
/// # Errors
/// Messaggio di errore localizzato a monte (lato JS): qui arriva il testo
/// italiano di `nfc_core` (stesso identico che dà il telefono nativo).
#[wasm_bindgen]
pub fn parse_pairing_qr(text: &str, now_unix_secs: u64) -> Result<String, JsValue> {
    parse_pairing_qr_inner(text, now_unix_secs).map_err(|e| JsValue::from_str(&e))
}

/// Validazione/normalizzazione APDU per la console.
///
/// # Errors
/// Messaggio in italiano sul perché l'hex non è un APDU valido.
#[wasm_bindgen]
pub fn validate_apdu(hex: &str) -> Result<String, JsValue> {
    validate_apdu_inner(hex).map_err(|e| JsValue::from_str(&e))
}

/// Impl interna, testabile su target nativo senza il bridge JS.
fn parse_pairing_qr_inner(text: &str, now_unix_secs: u64) -> Result<String, String> {
    let p = nfc_core::pairing::PairingPayload::decode_qr(text).map_err(|e| e.to_string())?;
    let expiry = match p.expiry(now_unix_secs) {
        nfc_core::pairing::QrExpiry::Unknown => serde_json::json!({
            "kind": "unknown", "secs": serde_json::Value::Null,
        }),
        nfc_core::pairing::QrExpiry::Valid(s) => {
            serde_json::json!({"kind": "valid", "secs": s})
        }
        nfc_core::pairing::QrExpiry::Expired(s) => {
            serde_json::json!({"kind": "expired", "secs": s})
        }
    };
    Ok(serde_json::json!({
        "v": p.v,
        "ip": p.ip,
        "port": p.port,
        "host": p.host,
        "tls_port": p.tls_port,
        "has_tls_pin": p.tls_pin_b64.is_some(),
        "pq": p.pq,
        "wants_pq": p.wants_pq(),
        "expiry": expiry,
        "qr_len": text.len(),
    })
    .to_string())
}

/// Impl interna, testabile su target nativo.
fn validate_apdu_inner(hex: &str) -> Result<String, String> {
    if hex.trim().is_empty() {
        return Err("APDU vuoto".into());
    }
    // Gli APDU si incollano spesso con spazi tra i byte: si accettano e si
    // normalizzano a hex compatto (digit dispari resta un errore).
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() > 131_070 {
        return Err("APDU troppo lungo oltre il massimo di 65535 byte".into());
    }
    let bytes = hex::decode(&clean).map_err(|e| format!("hex non valido: {e}"))?;
    // 4 byte minimi: CLA INS P1 P2 (header ISO 7816). Sotto, non è un APDU.
    if bytes.len() < 4 {
        return Err(format!(
            "APDU di {} byte: servono almeno 4 (CLA INS P1 P2)",
            bytes.len()
        ));
    }
    if bytes.len() > 65_535 {
        return Err("APDU oltre i 65535 byte (extended APDU max)".into());
    }
    Ok(serde_json::json!({
        "len": bytes.len(),
        "hex": hex::encode_upper(&bytes),
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un QR v2 generato dall'engine (con PQ) deve essere validato e riportare
    /// i campi giusti — stessa classe di test di `pairing.rs`, dal wrapper.
    #[test]
    fn qr_v2_ibrido_valido() {
        let p = nfc_core::pairing::PairingPayload::new_hybrid(
            "192.168.1.10".into(),
            8080,
            [1u8; 32],
            [2u8; 32],
            &[7u8; 1184],
        );
        let s = p.encode_qr().expect("encode");
        let out = parse_pairing_qr_inner(&s, 1_700_000_000).expect("decode");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["v"], 2);
        assert_eq!(v["port"], 8080);
        assert_eq!(v["pq"], 1);
        assert_eq!(v["wants_pq"], true);
        assert_eq!(v["expiry"]["kind"], "unknown");
    }

    /// QR malformato: la webapp deve rifiutarlo come il telefono nativo.
    #[test]
    fn qr_malformato_rifiutato() {
        for cattivo in ["CIAO", "NFC://2/@@@", "NFC://1/abc"] {
            assert!(
                parse_pairing_qr_inner(cattivo, 0).is_err(),
                "QR accettato: {cattivo}"
            );
        }
    }

    /// Scadenza: un QR con `exp_unix` nel passato remoto è classificato come
    /// scaduto, non caricato come valido.
    #[test]
    fn scadenza_classificata() {
        let base = nfc_core::pairing::PairingPayload::new(
            "192.168.1.10".into(),
            8080,
            [1u8; 32],
            [2u8; 32],
        )
        .with_expiry(1_800_000_000, 300);
        let s = base.encode_qr().expect("encode");
        // 400s dopo l'emissione: oltre scadenza e oltre la tolleranza (90s).
        let out = parse_pairing_qr_inner(&s, 1_800_000_400).expect("decode");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["expiry"]["kind"], "expired");
        let fresh = parse_pairing_qr_inner(&s, 1_800_000_100).expect("decode");
        let fresh: serde_json::Value = serde_json::from_str(&fresh).unwrap();
        assert_eq!(fresh["expiry"]["kind"], "valid");
    }

    #[test]
    fn apdu_valido_normalizzato() {
        for (inp, atteso) in [("00a4040007a000000247100100", 13), ("00 A4 04 00", 4)] {
            let out = validate_apdu_inner(inp).expect("apdu valido");
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["len"], atteso, "input {inp}");
            assert_eq!(
                v["hex"],
                hex::encode_upper(hex::decode(inp.replace(' ', "")).unwrap())
            );
        }
    }

    #[test]
    fn apdu_invalido_rifiutato() {
        for cattivo in ["", "ZZ", "00A4"] {
            assert!(
                validate_apdu_inner(cattivo).is_err(),
                "accettato: {cattivo}"
            );
        }
    }
}
