//! Protocollo messaggi: prost (E2EE mobile) + JSON (extension/webapp).
//! Il file .proto è compilato in build.rs -> `OUT_DIR/smartcard.rs`.

/// Tipi prost generati (codice generato: lint disabilitati).
pub mod proto {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery, missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/nfc.smartcard.v1.rs"));
}

use crate::error::{CoreError, Result};
use prost::Message;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Wrapper E2EE: EncryptedFrame <-> bytes WS binari
// ---------------------------------------------------------------------------

/// Codici WebSocket con cui l'engine comunica **perché** ha rifiutato l'handshake.
///
/// Prima erano chiusure mute: il telefono vedeva soltanto `Close` e doveva
/// indovinare — il suo testo di default era "molto probabilmente il QR è già
/// stato usato", cioè un'ipotesi presentata come una diagnosi. Ora il motivo
/// attraversa il canale come codice stabile, e il client lo traduce.
///
/// Sono nella gamma applicativa 4400-4499 (le 3000-3999 sono registrate, le
/// 4000-4999 sono libere all'applicazione).
pub mod close {
    /// Init malformato o di tipo inatteso: bug client o frame corrotto.
    pub const HANDSHAKE_MALFORMATO: u16 = 4400;
    /// Il QR è stato già consumato da un'altra sessione.
    pub const QR_USATO: u16 = 4401;
    /// Il QR ha superato la validità dell'engine.
    pub const QR_SCADUTO: u16 = 4402;
    /// Il nonce del QR non è quello emesso per questo engine.
    pub const QR_NON_CORRISPONDE: u16 = 4403;
    /// `keys_v` assente o diverso: client pre-separazione-delle-chiavi.
    pub const CHIAVI_LEGACY: u16 = 4404;
    /// QR ibrido ma l'engine gira senza la feature `pq`.
    pub const BUILD_SENZA_PQ: u16 = 4405;
    /// Canale locale (`/v1/extension`, `/v1/transmit`) non autenticato: il
    /// token manca, è scaduto o il device è stato revocato. Non è un errore di
    /// pairing: lo vedono estensione e client REST locali.
    pub const LOCAL_NON_AUTENTICATO: u16 = 4406;
}

/// Decodifica un frame binario WS in `EncryptedFrame`.
///
/// # Errors
/// `CoreError::Protocol` se i bytes non sono un `EncryptedFrame` prost valido.
pub fn decode_encrypted(buf: &[u8]) -> Result<proto::EncryptedFrame> {
    proto::EncryptedFrame::decode(buf).map_err(|e| CoreError::Protocol(e.to_string()))
}

/// Codifica `PlainFrame` in bytes pronti per `SessionKeys::seal`.
#[must_use]
pub fn encode_plain(frame: &proto::PlainFrame) -> Vec<u8> {
    frame.encode_to_vec()
}

/// Decodifica `PlainFrame` dopo `SessionKeys::open`.
///
/// # Errors
/// `CoreError::Protocol` se i bytes non sono un `PlainFrame` prost valido.
pub fn decode_plain(buf: &[u8]) -> Result<proto::PlainFrame> {
    proto::PlainFrame::decode(buf).map_err(|e| CoreError::Protocol(e.to_string()))
}

// ---------------------------------------------------------------------------
// API JSON pubblica su /v1/extension (usata anche dall'estensione e webapp)
// ---------------------------------------------------------------------------

/// Eventi push dal desktop verso extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ExtEvent {
    #[serde(rename = "card_status")]
    CardStatus {
        status: CardStatus,
        atr_hex: Option<String>,
    },
    #[serde(rename = "reader_connected")]
    ReaderConnected { name: String },
    #[serde(rename = "reader_disconnected")]
    ReaderDisconnected { name: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CardStatus {
    Inserted,
    Removed,
    Reading,
}

/// Richiesta APDU da extension/webapp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransmitRequest {
    /// "`transmit_apdu`"
    #[serde(rename = "type")]
    pub kind: String,
    pub request_id: String,
    /// Hex ("00A40400...") oppure base64 con prefisso "b64:".
    pub payload_hex: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    8000
}

impl TransmitRequest {
    /// Decodifica payload in byte APDU grezzi (max 65535).
    ///
    /// # Errors
    /// `CoreError::Protocol` su hex/base64 malformati o lunghezza fuori 4..65535.
    pub fn apdu_bytes(&self) -> Result<Vec<u8>> {
        let raw = if let Some(b64) = self.payload_hex.strip_prefix("b64:") {
            use base64::{Engine, engine::general_purpose::STANDARD as B64};
            B64.decode(b64)
                .map_err(|e| CoreError::Protocol(format!("b64: {e}")))?
        } else {
            hex::decode(self.payload_hex.trim())
                .map_err(|e| CoreError::Protocol(format!("hex: {e}")))?
        };
        if raw.is_empty() || raw.len() > 65535 {
            return Err(CoreError::Protocol("lunghezza APDU non valida".into()));
        }
        // Sanity ISO7816: minimo 4 byte header.
        if raw.len() < 4 {
            return Err(CoreError::Protocol(
                "APDU troppo corta (min 4B header)".into(),
            ));
        }
        Ok(raw)
    }
}

/// Risposta APDU verso extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransmitReply {
    #[serde(rename = "type")]
    pub kind: String, // "apdu_reply"
    pub request_id: String,
    pub data_hex: String,
    pub sw1: u8,
    pub sw2: u8,
    pub latency_ms: u64,
}

/// Messaggio generico di errore JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReply {
    #[serde(rename = "type")]
    pub kind: String, // "error"
    pub code: i32,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Segnalazione WebRTC DataChannel fallback (JSON su /v1/signal, 2026).
// Il DataChannel trasporta gli stessi `EncryptedFrame` E2EE (stesse SessionKeys):
// cambia solo il carrier per VPN che bloccano il TCP diretto. Offer/answer SDP
// viaggiano qui (loopback, autenticati dall'allowlist Origin); i candidati ICE
// sono solo `host` (niente STUN/TURN pubblico di default).
// ---------------------------------------------------------------------------

/// Richiesta di apertura canale: il mobile invia offer SDP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtcOffer {
    #[serde(rename = "type")]
    pub kind: String, // "rtc_offer"
    pub from: String, // "mobile"
    pub sdp: String,
}

/// Risposta desktop con answer SDP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtcAnswer {
    #[serde(rename = "type")]
    pub kind: String, // "rtc_answer"
    pub sdp: String,
}

/// Candidato ICE host-only (es. `candidate:... typ host ...`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtcCandidate {
    #[serde(rename = "type")]
    pub kind: String, // "rtc_candidate"
    pub from: String,
    pub candidate: String,
}
