//! Generazione QR di pairing: IP locale + porta + nonce32 + pubkey.
//! Il QR è rigenerato a ogni avvio e su richiesta IPC `regenerate_qr`.

// `STANDARD` (con `+/`) e NON `URL_SAFE`: i data-URL `data:image/png;base64,...`
// sono definiti su base64 standard, i browser rifiutano `-`/`_` e l'immagine
// non viene renderizzata. L'URL-safe serve solo per il testo QR `NFC://2/`.
use base64::{Engine, engine::general_purpose::STANDARD as B64_STD};
use image::Luma;
use nfc_core::{Result, pairing::PairingPayload};
use qrcode::{EcLevel, QrCode};

#[derive(Debug)]
pub struct QrBundle {
    /// Stringa `NFC://2/...` (`QRv2` ibrido-ready) da mostrare come QR.
    pub text: String,
    /// PNG data-URL per la `WebView` Tauri (`<img src=...>`) e la webapp.
    pub png_data_url: String,
}

/// Quiet zone ISO 18004 (4 moduli bianchi per lato) attorno al QR.
///
/// `render` del crate produce l'immagine modulo-per-modulo senz'alcun margine:
/// sui temi scuri il bordo nero si fonde con lo sfondo e i decodificatori non
/// trovano i finder pattern. Il margine è scalato ai pixel già renderizzati
/// (`scale` px/modulo), minimo 16px.
fn with_quiet_zone(img: &image::GrayImage, modules: usize) -> image::GrayImage {
    let modules = u32::try_from(modules.max(1)).unwrap_or(1);
    let scale = (img.width() / modules).max(1);
    let margin = (4 * scale).max(16);
    let size = img.width() + 2 * margin;
    let mut canvas = image::GrayImage::from_pixel(size, size, image::Luma([255u8]));
    image::imageops::overlay(&mut canvas, img, i64::from(margin), i64::from(margin));
    canvas
}

/// Costruisce il QR da un payload già completo (es. ibrido PQ via `new_hybrid`).
///
/// # Errors
/// `CoreError` se il payload non sta in un QR (oltre ~2.9KB con livello L) o
/// se il renderer PNG fallisce.
pub fn build_qr_payload(payload: &PairingPayload) -> Result<QrBundle> {
    let text = payload.encode_qr()?;
    // Livello L: il payload ibrido PQ (~1.7KB) non entrerebbe in M;
    // su schermo pulito scansiona più in fretta ed è più che sufficiente.
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L)
        .map_err(|e| nfc_core::CoreError::Protocol(e.to_string()))?;
    let img = code.render::<Luma<u8>>().min_dimensions(512, 512).build();
    // Quiet zone ISO di 4 moduli: il renderer parte dai moduli edge-to-edge e,
    // su sfondo scuro (tray, tema dark della webapp) senza margine bianco i
    // decodificatori (jsQR nella webapp, e anche buona parte delle fotocamere)
    // non trovano i finder pattern: "la fotocamera si apre ma il QR non si
    // legge". Il margine va cotto nel PNG, non affidato al CSS di chi mostra.
    let img = with_quiet_zone(&img, code.width());
    let mut buf = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
        .map_err(|e| nfc_core::CoreError::Protocol(e.to_string()))?;
    let png_data_url = format!("data:image/png;base64,{}", B64_STD.encode(&buf));
    Ok(QrBundle { text, png_data_url })
}

/// Rigenera il QR di pairing (nuovo nonce + X25519 + ML-KEM-768) e aggiorna
/// tutto il materiale di sessione nel `WsContext`: QR, nonce, chiave desktop
/// e — con feature `pq` — coppia e chiave encapsulata ML-KEM.
///
/// Usata dall'avvio, dal comando IPC `regenerate_qr` e dalla webapp via
/// `POST /v1/qr`: un'unica rotazione, così tray e web non possono divergere.
///
/// # Errors
/// `CoreError` se la codifica del payload o il rendering PNG falliscono; in
/// quel caso il materiale precedente resta intatto.
pub async fn regenerate_into(ctx: &std::sync::Arc<crate::ws_server::WsContext>) -> Result<String> {
    use crate::ws_server::HandshakeMaterial;
    use nfc_core::pairing::PairingPayload;
    use rand::RngCore;

    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    let kp = nfc_core::crypto::X25519Keypair::generate();
    let ip = local_ipv4();
    let host = nfc_core::local_domain::LOCAL_DOMAIN.to_string();
    let tls_port = nfc_core::local_domain::TLS_PORT;
    // Pin TLS del certificato foglia: senza, il telefono non può validare
    // `wss://nfc.local:8443` (la CA locale non è nel suo store) e ripiegherebbe
    // sul canale in chiaro. Se il pin non è calcolabile si degrada senza
    // fallire: il QR resta valido e il mobile userà il fallback.
    let tls_pin = leaf_pin_sha256();
    let scade = crate::ws_server::QR_TTL.as_secs();
    let adesso = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    #[cfg(feature = "pq")]
    let (payload, pq_kp) = {
        let pq = nfc_core::crypto::pq::MlKemKeypair::generate();
        let mut p = PairingPayload::new_hybrid(ip, 8080, nonce, kp.public_bytes(), &pq.ek_bytes())
            .with_expiry(adesso, scade);
        if let Some(pin) = tls_pin {
            p = p.with_tls_pin(&host, tls_port, &pin);
        }
        (p, Some(pq))
    };
    #[cfg(not(feature = "pq"))]
    let payload = {
        let mut p =
            PairingPayload::new(ip, 8080, nonce, kp.public_bytes()).with_expiry(adesso, scade);
        if let Some(pin) = tls_pin {
            p = p.with_tls_pin(&host, tls_port, &pin);
        }
        p
    };

    // Rendering prima di toccare il contesto: se fallisce non invalidiamo
    // le sessioni già aperte con un QR che non esiste.
    let bundle = build_qr_payload(&payload)?;
    *ctx.pair_qr.write().await = (bundle.text.clone(), bundle.png_data_url);
    *ctx.handshake_material.write().await = HandshakeMaterial::fresh(nonce);
    *ctx.desktop_kp.write().await = kp;
    #[cfg(feature = "pq")]
    {
        *ctx.pq_kp.write().await = pq_kp;
        *ctx.mlkem_ek_b64.write().await = payload.mlkem_b64.clone();
    }
    // A ogni rotazione riallinea l'origin LAN della webapp: dopo un cambio di
    // rete l'IP può non essere più quello di avvio.
    ctx.origins.allow_lan_engine_origin().await;
    Ok(bundle.text)
}

/// IP di LAN da mettere nel QR di pairing. Fallback 127.0.0.1.
///
/// Delega a [`nfc_core::net::lan_ipv4_string`] perché QR e mDNS **devono**
/// annunciare lo stesso indirizzo: è la stessa classe di divergenza che aveva
/// reso il pannello desktop e la webapp discordi. In particolare esclude i
/// tunnel VPN: con `local_ip_address::local_ip()` il QR finiva con l'IP di
/// `tun0`, irraggiungibile dal telefono in LAN.
#[must_use]
pub fn local_ipv4() -> String {
    nfc_core::net::lan_ipv4_string()
}

/// SHA-256 del DER del certificato foglia: il pin che il telefono verifica.
///
/// `None` se il PEM non c'è ancora o non contiene un certificato: in quel caso
/// il QR esce senza `host`/`tls_pin_b64` e il mobile usa il fallback in
/// chiaro. Non è un errore fatale, perché la PKI viene generata all'avvio dal
/// TLS server e il primo QR può precedere di poco quel momento.
#[must_use]
pub fn leaf_pin_sha256() -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let pem = std::fs::read(nfc_core::local_domain::leaf_cert_path()).ok()?;
    let der = pem_to_der(&pem)?;
    Some(Sha256::digest(der).into())
}

/// Estrae il primo certificato DER da un PEM (ignora chiavi e altri blocchi).
fn pem_to_der(pem: &[u8]) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    let text = std::str::from_utf8(pem).ok()?;
    let start = text.find(BEGIN)? + BEGIN.len();
    let rest = &text[start..];
    let end = rest.find(END)?;
    // Il PEM autentico è su **più righe** (64 caratteri). `trim()` da solo
    // non basta: i newline interni fanno fallire `decode`, e il fallimento
    // restituiva `None` senza motivo apparente — il QR semplicemente non
    // portava il pin TLS. Si accettano solo i caratteri dell'alfabeto base64
    // standard, così uno smalcitore inatteso non viene ignorato in silenzio.
    let body: String = rest[..end]
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        .collect();
    B64.decode(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Il pin deve essere ricavabile dal certificato foglia realmente installato.
    ///
    /// Il fallimento silenzioso di questa funzione è il caso peggiore: il QR
    /// resta valido (i campi TLS sono opzionali), quindi nulla segnala l'errore
    /// e il telefono ripiega sul canale in chiaro per tutta la sessione. Un test
    /// sul certificato di installazione chiude il varco.
    #[test]
    fn pin_si_calcola_sul_certificato_installato() {
        if !nfc_core::local_domain::leaf_cert_path().exists() {
            // Nessuna PKI su questa macchina: non è un fallimento del codice,
            // ma va detto, altrimenti un test che passa vacuamente sembrerebbe
            // coprire il caso reale.
            eprintln!("PKI assente: test saltato");
            return;
        }
        let pin = leaf_pin_sha256().expect("pin ricavabile da un certificato presente");
        assert_ne!(pin, [0u8; 32], "pin tutto zero: il digest sarebbe sospetto");
    }

    /// La quiet zone deve esistere davvero negli angoli del PNG, non solo nel
    /// commento: senza margine bianco i decodificatori jsQR falliscono sui
    /// temi scuri ("la fotocamera si apre ma il QR non si legge").
    #[test]
    fn quiet_zone_bianca_attorno_al_qr() {
        let nera = image::GrayImage::from_pixel(10, 10, image::Luma([0u8]));
        let padded = with_quiet_zone(&nera, 10);
        // scale = 10/10 = 1 → margine = max(4*1, 16) = 16.
        assert_eq!(padded.width(), 10 + 2 * 16);
        assert_eq!(padded.height(), 10 + 2 * 16);
        let w = padded.width();
        let h = padded.height();
        for (x, y) in [(0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)] {
            assert_eq!(
                padded.get_pixel(x, y).0[0],
                255,
                "l'angolo ({x},{y}) deve essere bianco (quiet zone)"
            );
        }
        // Contenuto originale: spostato di `margin`, ancora nero.
        assert_eq!(padded.get_pixel(16, 16).0[0], 0, "contenuto al centro");
    }

    /// `pem_to_der` deve ignorare tutto ciò che non è un certificato.
    ///
    /// Il PEM di prova è **multiriga a 64 caratteri**, come quello che produce
    /// `rcgen`: un test con base64 su un'unica riga passerebbe senza coprire il
    /// caso reale, ed è esattamente così che il base64 multiriga era rimasto
    /// non gestito e il pin TLS non arrivava nel QR.
    #[test]
    fn pem_to_der_estrae_solo_il_certificato() {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        let der = vec![0xAAu8; 300];
        let b64 = B64.encode(&der);
        let righe: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let chiave = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        let cert = format!(
            "{chiave}-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            righe.join("\n")
        );
        assert_eq!(pem_to_der(cert.as_bytes()).as_deref(), Some(der.as_slice()));
    }

    /// PEM senza alcun certificato: `None`, non un errore.
    #[test]
    fn pem_senza_certificato_da_none() {
        assert!(
            pem_to_der(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n").is_none()
        );
        assert!(pem_to_der(b"non e' un pem").is_none());
        assert!(pem_to_der(&[0xFF, 0xFE]).is_none());
    }

    /// Il pin deve coincidere con SHA-256 del DER: è la definizione del campo
    /// `tls_pin_b64`, e i due lati (engine e mobile) devono concordare.
    #[test]
    fn pin_e_sha256_del_der() {
        use sha2::{Digest, Sha256};
        let der = vec![0x42u8; 300];
        let b64 = B64_STD.encode(&der);
        let righe: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            righe.join("\n")
        );
        let est: [u8; 32] = Sha256::digest(pem_to_der(pem.as_bytes()).unwrap()).into();
        let atteso: [u8; 32] = Sha256::digest(&der).into();
        assert_eq!(est, atteso);
    }
}
