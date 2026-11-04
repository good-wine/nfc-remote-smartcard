//! Plugin mobile Tauri: handshake E2EE verificato + sessione full-duplex.
//! - `mobile_handshake(ip, port, nonce, peer_pubkey[, mlkem])`: DH X25519 ed
//!   eventuale incapsulamento ML-KEM-768, verifica `HandshakeResp` (pubkey == QR,
//!   seq/nonce/SAS), poi spawna task TX (seal+write) e RX (decrypt+dispatch).
//! - Direzione desktop->mobile (`ApduRequest`): emette evento Tauri
//!   `mobile-apdu-request` e attende `mobile_apdu_reply` dal bridge nativo
//!   (Kotlin `NfcIsoDepHandler.transceive` / Swift `NfcBridge.send`); se il
//!   bridge non risponde entro `timeout_ms`, replica onesta `6F00` (no-card).
//! - Direzione mobile->desktop: `nfc_card_event` invia `CardEvent` cifrato.
//! - `mobile_transmit` resta solo loopback di sviluppo (mock 9000 esplicito).

use nfc_core::protocol::proto;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock, mpsc};

/// Client TLS con pin del certificato foglia letto dal QR (`wss://nfc.local:8443`).
pub mod tls_pin;

type SessionId = String;

/// Lavoro per il task TX (unico detentore di `tx_keys` + metà write del WS).
enum TxJob {
    SealAndSend(proto::PlainFrame),
}

/// Risposta dal bridge nativo (Kotlin/Swift) verso un `ApduRequest` in attesa.
struct NativeReply {
    data: Vec<u8>,
    sw1: u8,
    sw2: u8,
}

struct Session {
    tx_job: mpsc::Sender<TxJob>,
    /// `request_id` desktop -> canale risposta nativa.
    pending: Mutex<HashMap<String, tokio::sync::oneshot::Sender<NativeReply>>>,
}

#[derive(Default)]
pub struct MobileState {
    sessions: RwLock<HashMap<SessionId, Arc<Session>>>,
}

impl std::fmt::Debug for MobileState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MobileState").finish_non_exhaustive()
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Materiale di pairing così come arriva dal QR, dopo `parseQr` lato frontend.
///
/// Va in una struct invece che in parametri sciolti: la firma del comando è un
/// contratto con `secure-channel.ts` e cresceva di un campo per ogni aggiunta
/// (`ip`, `port`, `nonce`, `pubkey`, `mlkem`, poi `host`, `tls_port`, pin). Con i
/// parametri sciolti, ogni nuovo canale avrebbe richiesto di ricontare nomi e
/// ordine dei parametri: è esattamente il tipo di errore che una struct elimina
/// da sola.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrMaterial {
    /// IP LAN dell'engine: canale in chiaro di ripiego.
    pub ip: String,
    /// Porta del canale in chiaro (8080).
    pub port: u16,
    pub nonce_b64: String,
    pub peer_pubkey_b64: String,
    #[serde(default)]
    pub mlkem_b64: Option<String>,
    /// Host canonico per `wss://` (es. `nfc.local`).
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub tls_port: Option<u16>,
    /// SHA-256(DER foglia) base64url: pin del certificato.
    #[serde(default)]
    pub tls_pin_b64: Option<String>,
    /// Scadenza del QR (secondi epoch Unix), se presente.
    ///
    /// Non decide nulla: serve solo a distinguere "QR vecchio, rigenera" da
    /// "certificato diverso, non proseguire". Sono due reazioni opposte, e
    /// senza questo campo produrrebbero lo stesso testo — quello che mostrerebbe
    /// anche un intercettatore.
    #[serde(default)]
    pub exp_unix: Option<u64>,
}

/// Codici stabili degli errori di pairing.
///
/// Sono un contratto con `shared-ui-ts/src/pairing-errors.ts`: le stringhe
/// localizzate sono indicizzate per codice, quindi **rinominare un codice
/// rompe la traduzione** senza alcun errore di compilazione. I dettagli tecnici
/// viaggiano separati (`PairingError::detail`) e non sono mai mostrati come
/// traduzione, solo accodati al testo.
pub mod code {
    use super::PairingError;

    /// QR non leggibile o incompleto.
    pub const QR_INVALID: &str = "qrInvalid";
    /// QR scaduto: va rigenerato dalla tray.
    pub const QR_EXPIRED: &str = "qrExpired";
    /// Il QR è già stato consumato da un'altra sessione.
    pub const QR_USED: &str = "qrUsed";
    /// Certificato TLS non pinnato: connessione interrotta di proposito.
    pub const PIN_REJECTED: &str = "pinRejected";
    /// Nessun canale utilizzabile verso l'engine.
    pub const UNREACHABLE: &str = "unreachable";
    /// L'engine non espone un canale in chiaro raggiungibile da qui.
    pub const NO_PLAIN_CHANNEL: &str = "noPlainChannel";
    /// L'handshake E2EE non è arrivato in tempo.
    pub const HANDSHAKE_TIMEOUT: &str = "handshakeTimeout";
    /// L'engine ha chiuso la connessione.
    pub const PEER_CLOSED: &str = "peerClosed";
    /// Frame inatteso dal peer.
    pub const BAD_FRAME: &str = "badFrame";
    /// La chiave del peer non è quella del QR: possibile intercettazione.
    pub const PEER_MISMATCH: &str = "peerMismatch";
    /// Versione di protocollo negoziata incompatibile.
    pub const PROTO_MISMATCH: &str = "protoMismatch";
    /// Decifratura fallita.
    pub const DECRYPT_FAILED: &str = "decryptFailed";
    /// Errore interno non classificato.
    pub const INTERNAL: &str = "internal";

    /// Traduce il codice di chiusura WebSocket dell'engine in un codice di pairing.
    ///
    /// L'engine rifiuta un handshake con un codice stabile invece di chiudere in
    /// silenzio: senza, il telefono vedeva solo una connessione che sparisce e il
    /// suo testo di default presentava un'ipotesi — "molto probabilmente il QR è
    /// già stato usato" — come se fosse una diagnosi. Due reazioni diverse
    /// (rigenerare vs. aggiornare l'app) mascherate dalla stessa chiusura.
    ///
    /// Il `motivo` dell'engine è italiano ed entra nel `detail`: è il dettaglio
    /// per il log, non il messaggio che vede l'utente.
    #[must_use]
    pub fn da_chiusura(chiuso: u16, motivo: &str) -> PairingError {
        use nfc_core::protocol::close;
        let code = match chiuso {
            close::QR_USATO => QR_USED,
            close::QR_SCADUTO => QR_EXPIRED,
            close::QR_NON_CORRISPONDE => QR_INVALID,
            // Il nostro init porta sempre `keys_v` (vedi `build_handshake_init`):
            // vederlo rifiutato significa che il campo è stato rimosso per
            // strada. Un downgrade silenzioso è impossibile per costruzione, ma
            // la reazione deve restare "non riprovare".
            close::CHIAVI_LEGACY => PEER_MISMATCH,
            // QR ibrido su un engine compilato senza `pq`: i due lati non
            // possono parlare finché non sono allineati.
            close::BUILD_SENZA_PQ => PROTO_MISMATCH,
            close::HANDSHAKE_MALFORMATO => BAD_FRAME,
            _ => PEER_CLOSED,
        };
        PairingError::with_detail(code, format!("engine {chiuso}: {motivo}"))
    }
}

/// Errore di pairing strutturato: codice stabile + dettaglio tecnico.
///
/// Il motivo di esistere è che il frontend non può localizzare una prosa
/// italiana, e non può distinguere "certificato rifiutato" da "timeout di rete"
/// senza farne un'analisi testuale — fragile per costruzione, perché il testo
/// verrebbe toccato dalla traduzione o da un refactor.
///
/// # Serializzazione
/// `Serialize` perché il tipo di ritorno di un `#[tauri::command]` deve essere
/// serializzabile per attraversare l'IPC.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingError {
    /// Uno dei codici di [`code`].
    pub code: &'static str,
    /// Contesto tecnico (endpoint, durata, motivo della verifica).
    ///
    /// Non tradotto e non mostrato al posto del messaggio: accodato al testo
    /// localizzato, serve al log e alla diagnosi.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl PairingError {
    #[must_use]
    pub fn new(code: &'static str) -> Self {
        Self { code, detail: None }
    }

    #[must_use]
    pub fn with_detail(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: Some(detail.into()),
        }
    }
}

impl std::fmt::Display for PairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            Some(d) => write!(f, "[{}] {d}", self.code),
            None => write!(f, "[{}]", self.code),
        }
    }
}

/// Le stringhe già pronte diventano errori interni col testo come dettaglio.
///
/// Serve per non dover riscrivere d'un colpo ogni `.map_err(|e| format!(..))`
/// del crate: il codice esplicito si mette solo dove l'utente ha un'azione
/// diversa da fare, che è il punto in cui la localizzazione conta.
impl From<String> for PairingError {
    fn from(detail: String) -> Self {
        Self::with_detail(code::INTERNAL, detail)
    }
}

impl QrMaterial {
    /// Endpoint TLS completo, o `None` se il QR non lo porta.
    ///
    /// Restituisce un `Option` invece di un bool perché i tre campi sono
    /// un'unità: mezzo canale TLS (host senza pin) è peggio del chiaro, dato
    /// che sembrerebbe protetto. Qui i tre si richiedono insieme o si rifiuta.
    #[must_use]
    pub fn tls_endpoint(&self) -> Option<(String, u16, String)> {
        let host = self.host.as_deref().filter(|h| !h.is_empty())?;
        let port = self.tls_port.filter(|p| *p > 0)?;
        let pin = self.tls_pin_b64.as_deref().filter(|p| !p.is_empty())?;
        Some((host.to_string(), port, pin.to_string()))
    }
}

/// Comandi IPC Tauri (sottomodulo `commands`: i `pub #[tauri::command]`
/// devono vivere fuori dalla root del crate per via di `#[macro_export]`).
pub mod commands {
    use super::{
        MobileState, NativeReply, PairingError, QrMaterial, Session, TxJob, code, now_ms,
        uuid_simple,
    };
    use futures_util::{SinkExt, StreamExt};
    use nfc_core::{
        crypto::{Direction, KEYS_V, SessionKeys, X25519Keypair, sas_confirm},
        protocol::proto,
    };
    use prost::Message;
    use std::{collections::HashMap, sync::Arc};
    use tauri::Emitter;
    use tokio::sync::{Mutex, mpsc};

    type WsStream = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;
    type WsMsg = tokio_tungstenite::tungstenite::Message;
    type WsWrite = futures_util::stream::SplitSink<WsStream, WsMsg>;
    type WsRead = futures_util::stream::SplitStream<WsStream>;

    /// Materiale QR decodificato e validato in lunghezza (contenuto verificato dopo).
    ///
    /// # Errors
    /// `code::QR_INVALID` se base64 fallisce o nonce/pubkey non sono 32B.
    fn parse_qr_material(
        nonce_b64: &str,
        peer_pubkey_b64: &str,
    ) -> Result<([u8; 32], [u8; 32]), PairingError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let nonce: Vec<u8> = B64
            .decode(nonce_b64)
            .map_err(|e| PairingError::with_detail(code::QR_INVALID, format!("nonce: {e}")))?;
        let peer: Vec<u8> = B64
            .decode(peer_pubkey_b64)
            .map_err(|e| PairingError::with_detail(code::QR_INVALID, format!("pubkey: {e}")))?;
        if nonce.len() != 32 || peer.len() != 32 {
            return Err(PairingError::with_detail(
                code::QR_INVALID,
                format!("nonce {}B, pubkey {}B: attesi 32B", nonce.len(), peer.len()),
            ));
        }
        let nonce32: [u8; 32] = nonce.try_into().unwrap();
        let peer32: [u8; 32] = peer.try_into().unwrap();
        Ok((nonce32, peer32))
    }

    /// Chiavi di sessione + versione negoziata + ct PQ per l'init (se ibrido).
    struct KeyMaterial {
        rx_keys: SessionKeys,
        tx_keys: SessionKeys,
        proto_v: u32,
        init_ct: Vec<u8>,
    }

    /// DH X25519 ed eventuale incapsulamento ML-KEM verso l'ek del QR v2.
    ///
    /// # Errors
    /// `code::QR_INVALID` su ek malformata o build senza `pq` con QR ibrido.
    fn derive_key_material(
        x_shared: &[u8; 32],
        nonce32: &[u8; 32],
        mlkem_b64: Option<&str>,
    ) -> Result<KeyMaterial, PairingError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        #[cfg(feature = "pq")]
        let mlkem_ct: Option<(Vec<u8>, [u8; 32])> = match mlkem_b64 {
            Some(ek_b64) => {
                let ek = B64
                    .decode(ek_b64)
                    .map_err(|e| format!("mlkem ek b64: {e}"))?;
                Some(nfc_core::crypto::pq::encapsulate(&ek).map_err(|e| e.to_string())?)
            }
            None => None,
        };
        #[cfg(not(feature = "pq"))]
        let mlkem_ct: Option<(Vec<u8>, [u8; 32])> = {
            if mlkem_b64.is_some() {
                return Err(PairingError::with_detail(
                    code::QR_INVALID,
                    "desktop PQ ma build mobile senza `pq`",
                ));
            }
            None
        };
        let (proto_v, init_ct, rx_keys, tx_keys) = match &mlkem_ct {
            #[cfg(feature = "pq")]
            Some((ct, m_shared)) => (
                2u32,
                ct.clone(),
                SessionKeys::derive_hybrid(x_shared, m_shared, nonce32, Direction::MobileToDesktop)
                    .map_err(|e| e.to_string())?,
                SessionKeys::derive_hybrid(x_shared, m_shared, nonce32, Direction::MobileToDesktop)
                    .map_err(|e| e.to_string())?,
            ),
            #[cfg(not(feature = "pq"))]
            Some(_) => unreachable!("mlkem_ct impossibile senza feature pq"),
            None => (
                1u32,
                vec![],
                SessionKeys::derive(x_shared, nonce32, Direction::MobileToDesktop)
                    .map_err(|e| e.to_string())?,
                SessionKeys::derive(x_shared, nonce32, Direction::MobileToDesktop)
                    .map_err(|e| e.to_string())?,
            ),
        };
        Ok(KeyMaterial {
            rx_keys,
            tx_keys,
            proto_v,
            init_ct,
        })
    }

    /// Decifra e verifica `HandshakeResp`: pubkey uguale al QR, versione coerente.
    /// Ritorna la SAS a 6 cifre da confrontare col desktop.
    ///
    /// # Errors
    /// `code::BAD_FRAME` sul framing, `code::DECRYPT_FAILED` se la risposta non
    /// può essere autenticata — e quindi o è stata alterata o i due lati hanno
    /// materiale chiavi diverso (engine non aggiornato),
    /// `code::PEER_MISMATCH` se la chiave del peer non è quella del QR
    /// (intercettazione), `code::PROTO_MISMATCH` su versione incoerente.
    fn verify_handshake_response(
        rx_keys: &mut SessionKeys,
        bytes: &[u8],
        peer32: &[u8; 32],
        eph_pub: &[u8; 32],
        nonce32: &[u8; 32],
        proto_v: u32,
    ) -> Result<String, PairingError> {
        let enc_resp = nfc_core::protocol::decode_encrypted(bytes)
            .map_err(|e| PairingError::with_detail(code::BAD_FRAME, e.to_string()))?;
        let mut n12 = [0u8; 12];
        if enc_resp.nonce12.len() == 12 {
            n12.copy_from_slice(&enc_resp.nonce12);
        }
        let pt = rx_keys
            .open(enc_resp.seq, &n12, &enc_resp.ciphertext)
            .map_err(|e| PairingError::with_detail(code::DECRYPT_FAILED, e.to_string()))?;
        let plain = nfc_core::protocol::decode_plain(&pt)
            .map_err(|e| PairingError::with_detail(code::BAD_FRAME, e.to_string()))?;
        let Some(proto::plain_frame::Kind::HandshakeResp(r)) = plain.kind else {
            return Err(PairingError::with_detail(
                code::BAD_FRAME,
                "atteso handshake_resp",
            ));
        };
        // La chiave del peer deve essere **esattamente** quella del QR: il canale
        // out-of-band che l'ha trasmessa è l'unica prova di identità, e qui il
        // confronto è il binding anti-MITM. Un codice dedicato perché la
        // reazione dell'utente è diversa da un timeout: non si riprova, si
        // verifica che nessuno sia in mezzo.
        if r.eph_pubkey.as_slice() != peer32 {
            return Err(PairingError::with_detail(
                code::PEER_MISMATCH,
                "pubkey desktop diversa dal QR",
            ));
        }
        if r.proto_v != proto_v {
            return Err(PairingError::with_detail(
                code::PROTO_MISMATCH,
                format!("peer {} != negoziata {proto_v}", r.proto_v),
            ));
        }
        Ok(sas_confirm(peer32, eph_pub, nonce32))
    }

    /// Apre il WebSocket verso l'engine: TLS con pin, o chiaro in ripiego.
    ///
    /// Si prova `wss://<host>:<tls_port>` solo se il QR fornisce *tutti e tre* i
    /// dati (host, porta, pin). Un QR incompleto non deve degradare in un TLS
    /// senza pin: sembrerebbe protetto senza esserlo.
    ///
    /// La scelta sul fallimento è il punto delicato:
    ///
    /// - **Errore di rete** (DNS, connessione rifiutata, timeout): si ripiega sul
    ///   canale in chiaro, che resta E2EE. Reale: guest-WiFi che blocca mDNS.
    /// - **Rifiuto del pin**: si abortisce. Ripiegare qui significherebbe che
    ///   chiunque, rifiutando il TLS o presentando un certificato a caso,
    ///   sceglie se la sessione viaggia in chiaro.
    ///
    /// # Errors
    /// `code::QR_INVALID` se il pin è malformato, `code::PIN_REJECTED` se il
    /// certificato non è quello pinnato, e gli errori di [`Self::connect_plain`]
    /// se il fallback in chiaro non è raggiungibile.
    async fn connect_engine(qr: &QrMaterial) -> Result<(WsStream, &'static str), PairingError> {
        use super::tls_pin;

        let Some(tls) = qr.tls_endpoint() else {
            return connect_plain(qr).await;
        };

        let url = tls_pin::wss_url(&tls.0, tls.1);
        // Un pin malformato è un QR corrotto, non un problema di rete: va detto
        // come tale, altrimenti l'utente riproverebbe la stessa scansione.
        let client = tls_pin::pinned_client(&tls.2)
            .map_err(|e| PairingError::with_detail(code::QR_INVALID, e))?;
        match tokio_tungstenite::connect_async_tls_with_config(
            url.as_str(),
            None,
            false,
            Some(tokio_tungstenite::Connector::Rustls(client.config())),
        )
        .await
        {
            Ok((ws, _)) => {
                tracing::info!(host = %tls.0, "connessione wss con pin TLS riuscita");
                return Ok((ws, "wss"));
            }
            Err(e) => match decide_after_tls(client.rifiuto()) {
                AfterTls::Abort(motivo) => {
                    tracing::error!(
                        host = %tls.0,
                        %motivo,
                        "verifica del pin TLS fallita: connessione interrotta, niente ripiego in chiaro"
                    );
                    return Err(PairingError::with_detail(code::PIN_REJECTED, motivo));
                }
                AfterTls::RipiegoInChiaro => {
                    tracing::warn!(
                        host = %tls.0,
                        err = %e,
                        "wss non raggiungibile: ripiego sul canale in chiaro (E2EE)"
                    );
                }
            },
        }

        connect_plain(qr).await
    }

    /// Cosa fare dopo che il percorso TLS non ha prodotto una connessione.
    ///
    /// La decisione è una funzione pura e **non** un `if` dentro `connect_engine`
    /// perché è la proprietà di sicurezza più delicata del canale mobile, e
    /// finendo dentro un `await` su una connessione reale non sarebbe
    /// verificabile da alcun test.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum AfterTls {
        /// Il certificato non è quello pinnato: si abortisce.
        ///
        /// Ripiegare sul chiaro qui darebbe a chiunque, rifiutando la connessione
        /// TLS o presenting un certificato a caso, la possibilità di scegliere se
        /// la sessione viaggia cifrata. L'E2EE resta integro, ma la privacy del
        /// trasporto diventa negoziabile e l'utente non riceve alcun avviso.
        Abort(String),
        /// Errore di rete: si ripiega sul canale in chiaro, che resta E2EE.
        RipiegoInChiaro,
    }

    /// Traduce l'esito della connessione TLS in una decisione.
    ///
    /// L'ordine dei controlli è la sicurezza: `rifiuto` si guarda **prima** di
    /// qualsiasi altra cosa, e non è influenzato dal fatto che la connessione sia
    /// fallita per rete o per verifica.
    pub(crate) fn decide_after_tls(rifiuto: Option<String>) -> AfterTls {
        match rifiuto {
            Some(motivo) => AfterTls::Abort(motivo),
            None => AfterTls::RipiegoInChiaro,
        }
    }

    /// Canale in chiaro, raggiungibile solo sul loopback.
    ///
    /// La porta 8080 è bindata su `127.0.0.1` (vedi `ws_server::plain_bind_addr`),
    /// quindi questo percorso serve al telefono solo se l'engine è sullo stesso
    /// host — sviluppo e test. Su un device in LAN la connessione è destinata a
    /// fallire, e dirlo subito è più utile che aspettare il timeout di `connect`.
    ///
    /// # Errors
    /// `code::NO_PLAIN_CHANNEL` se l'engine non è su questo host,
    /// `code::UNREACHABLE` se la connessione fallisce comunque.
    async fn connect_plain(qr: &QrMaterial) -> Result<(WsStream, &'static str), PairingError> {
        if !qr
            .ip
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
        {
            return Err(PairingError::with_detail(
                code::NO_PLAIN_CHANNEL,
                format!("ip {} porta {}", qr.ip, qr.port),
            ));
        }
        let url = format!("ws://{}:{}/v1/mobile", qr.ip, qr.port);
        let (ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| PairingError::with_detail(code::UNREACHABLE, format!("{url}: {e}")))?;
        tracing::info!(%url, "canale in chiaro aperto (solo loopback)");
        Ok((ws, "ws"))
    }

    /// Rifiuta un QR scaduto, **prima** di aprire qualsiasi connessione.
    ///
    /// Il caso che lo rende necessario: dopo `--rotate-ca` (o un riavvio che
    /// rigenera il certificato foglia) il pin del vecchio QR non corrisponde più,
    /// e l'errore che arriverebbe sarebbe "pin TLS non corrisponde" — lo stesso
    /// che mostrerebbe un certificato presentato da qualcun altro. Le due
    /// situazioni richiedono reazioni opposte: rigenerare il QR, oppure non
    /// fidarsi e verificare la rete. La scadenza è nel payload proprio per
    /// distinguerle.
    ///
    /// Non è un controllo di sicurezza: l'engine rifiuta comunque l'handshake
    /// oltre il suo TTL. Serve a dare la reazione giusta.
    ///
    /// Il margine sull'orologio (`QR_EXPIRY_GRACE_SECS`) è applicato qui e non
    /// dentro `nfc_core`: la decisione "vecchio o no" deve stare in un posto solo,
    /// altrimenti i due lati possono divergere.
    ///
    /// # Errors
    /// `code::QR_EXPIRED` con i secondi trascorsi, se il QR è scaduto oltre il
    /// margine.
    fn check_expiry(qr: &QrMaterial) -> Result<(), PairingError> {
        let adesso = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        check_expiry_at(qr, adesso)
    }

    /// La decisione di scadenza con l'orologio passato come argomento.
    ///
    /// Separata da [`Self::check_expiry`] perché leggere l'orologio di sistema
    /// rende la funzione non verificabile: un test dovrebbe aspettare minuti per
    /// far scadere un QR, o falsificare il tempo globale di un processo.
    ///
    /// # Errors
    /// `code::QR_EXPIRED` con i secondi trascorsi oltre il margine.
    pub(crate) fn check_expiry_at(qr: &QrMaterial, adesso: u64) -> Result<(), PairingError> {
        let Some(exp) = qr.exp_unix else {
            return Ok(());
        };
        let scaduto = adesso.saturating_sub(exp);
        let margine = nfc_core::pairing::QR_EXPIRY_GRACE_SECS;
        if scaduto > margine {
            return Err(PairingError::with_detail(
                code::QR_EXPIRED,
                format!("scaduto da {} s", scaduto - margine),
            ));
        }
        Ok(())
    }

    /// Task TX: unico detentore di `tx_keys` e metà write del WS.
    fn spawn_tx_task(mut tx_keys: SessionKeys, mut write: WsWrite, mut rx: mpsc::Receiver<TxJob>) {
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                let TxJob::SealAndSend(frame) = job;
                match tx_keys.seal(&frame.encode_to_vec()) {
                    Ok((seq, n, ct)) => {
                        let f = proto::EncryptedFrame {
                            seq,
                            nonce12: n.to_vec(),
                            ciphertext: ct,
                        };
                        if write
                            .send(WsMsg::Binary(f.encode_to_vec().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("seal fallito: {e}");
                        break;
                    }
                }
            }
        });
    }

    /// Task RX: decifra e smista (`Ping` verso `Pong`, `ApduRequest` al bridge).
    fn spawn_rx_task(
        app: tauri::AppHandle,
        sid: String,
        session: Arc<Session>,
        mut read: WsRead,
        mut rx_keys: SessionKeys,
    ) {
        tokio::spawn(async move {
            loop {
                let Some(Ok(msg)) = read.next().await else {
                    break;
                };
                let WsMsg::Binary(bytes) = msg else { continue };
                if bytes.len() > 128 * 1024 {
                    continue;
                }
                let Ok(enc) = nfc_core::protocol::decode_encrypted(&bytes) else {
                    continue;
                };
                let mut n12 = [0u8; 12];
                if enc.nonce12.len() != 12 {
                    continue;
                }
                n12.copy_from_slice(&enc.nonce12);
                let pt = match rx_keys.open(enc.seq, &n12, &enc.ciphertext) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("decrypt/rx: {e}");
                        continue;
                    }
                };
                let Ok(plain) = nfc_core::protocol::decode_plain(&pt) else {
                    continue;
                };
                match plain.kind {
                    Some(proto::plain_frame::Kind::Ping(p)) => {
                        let pong = proto::PlainFrame {
                            kind: Some(proto::plain_frame::Kind::Pong(proto::Pong {
                                seq: p.seq,
                                t_ms: now_ms(),
                            })),
                        };
                        if session.tx_job.send(TxJob::SealAndSend(pong)).await.is_err() {
                            break;
                        }
                    }
                    Some(proto::plain_frame::Kind::ApduRequest(r)) => {
                        // 1) Notifica il bridge nativo / dev UI (osservabilità).
                        let _ = app.emit(
                            "mobile-apdu-request",
                            serde_json::json!({
                                "session_id": sid,
                                "request_id": r.request_id,
                                "apdu_hex": hex::encode(&r.apdu),
                            }),
                        );
                        // 2) Attesa risposta nativa con fallback onesto 6F00.
                        let (rtx, rrx) = tokio::sync::oneshot::channel();
                        session
                            .pending
                            .lock()
                            .await
                            .insert(r.request_id.clone(), rtx);
                        let tx_job = session.tx_job.clone();
                        let wait = std::time::Duration::from_millis(
                            u64::from(r.timeout_ms).clamp(1000, 30000),
                        );
                        tokio::spawn(async move {
                            let reply =
                                if let Ok(Ok(native)) = tokio::time::timeout(wait, rrx).await {
                                    proto::ApduResponse {
                                        request_id: r.request_id.clone(),
                                        data: native.data,
                                        sw1: u32::from(native.sw1),
                                        sw2: u32::from(native.sw2),
                                        latency_ms: 0,
                                    }
                                } else {
                                    // Timeout o bridge assente: 6F00 esplicito (mai 9000 bugiardo).
                                    tracing::warn!(
                                        request_id = %r.request_id,
                                        "bridge NFC senza risposta: replico 6F00"
                                    );
                                    proto::ApduResponse {
                                        request_id: r.request_id.clone(),
                                        data: vec![],
                                        sw1: 0x6F,
                                        sw2: 0x00,
                                        latency_ms: 0,
                                    }
                                };
                            let frame = proto::PlainFrame {
                                kind: Some(proto::plain_frame::Kind::ApduResponse(reply)),
                            };
                            let _ = tx_job.send(TxJob::SealAndSend(frame)).await;
                        });
                    }
                    _ => {}
                }
            }
            // Chiusura: sblocca eventuali attese (i receiver vedono Err -> 6F00).
            session.pending.lock().await.clear();
            tracing::info!(session = %sid, "rx mobile terminato");
        });
    }

    /// Costruisce l'`HandshakeInit`, che viaggia in chiaro come primo frame.
    ///
    /// Estratta da `mobile_handshake` perché `keys_v` non possa essere
    /// scordato: un init senza il campo viene rifiutato dall'engine come client
    /// legacy, e l'errore che ne risulterebbe ("aggiorna entrambi") indicherebbe
    /// un aggiornamento quando la colpa sarebbe di questa riga. Un test qui
    /// sotto lo dice esplicitamente; dentro un `async fn` con un WebSocket non
    /// sarebbe affatto banale da verificare.
    pub(crate) fn build_handshake_init(
        eph_pub: &[u8; 32],
        nonce32: &[u8; 32],
        init_ct: Vec<u8>,
        proto_v: u32,
    ) -> proto::HandshakeInit {
        proto::HandshakeInit {
            eph_pubkey: eph_pub.to_vec(),
            nonce32: nonce32.to_vec(),
            mlkem_ct: init_ct,
            proto_v,
            keys_v: KEYS_V,
        }
    }

    /// Genera effimera, deriva chiavi (classiche o ibride PQ) e completa handshake.
    /// Verifica la risposta del desktop (pubkey == QR, seq/nonce/SAS coerenti).
    ///
    /// Nota TLS: se il QR porta `host` + `tls_port` + `tls_pin_b64` il canale è
    /// `wss://nfc.local:8443` con pin del certificato foglia (si veda
    /// [`crate::tls_pin`]). Altrimenti — QR v1, o engine senza TLS — si ripiega
    /// su `ws://<ip>:<port>`, che resta sicuro perché l'handshake qui sotto è
    /// E2EE e vincola il peer al materiale del QR.
    ///
    /// # Errors
    /// [`PairingError`] con un codice di [`code`]: il frontend lo localizza e ci
    /// accoda l'azione suggerita.
    ///
    /// # Panics
    /// Non panica: ogni fallimento è un `Err` esplicito.
    #[tauri::command]
    pub async fn mobile_handshake(
        app: tauri::AppHandle,
        qr: QrMaterial,
        state: tauri::State<'_, Arc<MobileState>>,
    ) -> Result<String, PairingError> {
        // La scadenza si controlla **prima** di qualsiasi connessione: dopo una
        // rotazione della CA, un QR vecchio produrrebbe "pin non corrisponde",
        // che è anche il testo che mostrerebbe un intercettatore. Qui la
        // diagnosi è inequivocabile, e non si sprecano 15 secondi di timeout.
        //
        // Non è un controllo di sicurezza: l'engine rifiuta comunque l'handshake
        // oltre il suo TTL. Serve a dare la reazione giusta.
        check_expiry(&qr)?;

        let (nonce32, peer32) = parse_qr_material(&qr.nonce_b64, &qr.peer_pubkey_b64)?;

        // DH X25519 + eventuale incapsulamento ML-KEM verso l'ek del QRv2.
        let eph = X25519Keypair::generate();
        let x_shared = eph.diffie_hellman(&peer32);
        let KeyMaterial {
            mut rx_keys,
            tx_keys,
            proto_v,
            init_ct,
        } = derive_key_material(&x_shared, &nonce32, qr.mlkem_b64.as_deref())?;

        let eph_pub = eph.public_bytes();
        let init = proto::PlainFrame {
            kind: Some(proto::plain_frame::Kind::HandshakeInit(
                build_handshake_init(&eph_pub, &nonce32, init_ct, proto_v),
            )),
        };
        let enc = proto::EncryptedFrame {
            seq: 0,
            nonce12: vec![0u8; 12],
            ciphertext: init.encode_to_vec(),
        };

        // Connessione all'engine: TLS con pin se il QR lo porta, altrimenti
        // il fallback in chiaro. In entrambi i casi il contenuto è E2EE.
        let (ws, trasporto) = connect_engine(&qr).await?;
        let (mut write, mut read) = ws.split();
        tracing::info!(trasporto, "canale aperto con l'engine");
        write
            .send(WsMsg::Binary(enc.encode_to_vec().into()))
            .await
            .map_err(|e| PairingError::with_detail(code::UNREACHABLE, format!("send: {e}")))?;

        // Attendi HandshakeResp (15s) e VERIFICALA (binding anti-MITM sul QR).
        let resp = tokio::time::timeout(std::time::Duration::from_secs(15), read.next())
            .await
            .map_err(|_| PairingError::with_detail(code::HANDSHAKE_TIMEOUT, "15s senza risposta"))?
            .ok_or_else(|| PairingError::new(code::PEER_CLOSED))?
            .map_err(|e| PairingError::with_detail(code::UNREACHABLE, e.to_string()))?;
        // Un rifiuto dell'engine arriva come Close con codice: deve diventare
        // un codice di pairing, non un "frame inatteso" che perderebbe il motivo.
        let bytes = match resp {
            WsMsg::Binary(b) => b,
            WsMsg::Close(Some(cf)) => {
                let chiuso = u16::from(cf.code);
                return Err(code::da_chiusura(chiuso, cf.reason.as_str()));
            }
            WsMsg::Close(None) => return Err(PairingError::new(code::PEER_CLOSED)),
            _ => {
                return Err(PairingError::with_detail(
                    code::BAD_FRAME,
                    "atteso frame binario",
                ));
            }
        };
        let sas = verify_handshake_response(
            &mut rx_keys,
            &bytes,
            &peer32,
            &eph.public_bytes(),
            &nonce32,
            proto_v,
        )?;
        tracing::info!(%sas, proto_v, "handshake mobile verificato: confronta SAS col desktop");

        // Registra sessione e avvia i task TX/RX.
        let id = uuid_simple();
        let (tx_job_tx, tx_job_rx) = mpsc::channel::<TxJob>(16);
        let session = Arc::new(Session {
            tx_job: tx_job_tx.clone(),
            pending: Mutex::new(HashMap::new()),
        });
        state
            .sessions
            .write()
            .await
            .insert(id.clone(), session.clone());
        spawn_tx_task(tx_keys, write, tx_job_rx);
        spawn_rx_task(app, id.clone(), session, read, rx_keys);
        Ok(id)
    }

    /// Risposta del bridge nativo a un `ApduRequest` (Kotlin/Swift -> Rust).
    /// `data_hex` senza SW; `sw1`/`sw2` decimali (`0x90`/`0x00` = ok).
    ///
    /// # Errors
    /// `String` su hex invalido, sessione o `request_id` sconosciuti.
    #[tauri::command]
    pub async fn mobile_apdu_reply(
        session_id: String,
        request_id: String,
        data_hex: String,
        sw1: u8,
        sw2: u8,
        state: tauri::State<'_, Arc<MobileState>>,
    ) -> Result<(), String> {
        let data = hex::decode(&data_hex).map_err(|e| format!("data_hex: {e}"))?;
        let g = state.sessions.read().await;
        let s = g.get(&session_id).ok_or("sessione sconosciuta")?;
        let tx = s
            .pending
            .lock()
            .await
            .remove(&request_id)
            .ok_or("request_id scaduta")?;
        tx.send(NativeReply { data, sw1, sw2 })
            .map_err(|_| "task di risposta terminato".to_string())?;
        Ok(())
    }

    /// Evento carta dal bridge nativo -> inoltrato cifrato al desktop.
    /// Se `session_id` è omesso e c'è una sola sessione, la usa.
    ///
    /// # Errors
    /// `String` se nessuna sessione è attiva o il canale è chiuso.
    ///
    /// # Panics
    /// Non panica: `unwrap` è protetto dal controllo di cardinalità sopra.
    #[tauri::command]
    pub async fn nfc_card_event(
        kind: String,
        atr_hex: Option<String>,
        session_id: Option<String>,
        state: tauri::State<'_, Arc<MobileState>>,
    ) -> Result<(), String> {
        let proto_kind = match kind.as_str() {
            "inserted" => proto::card_event::Kind::Inserted,
            "removed" => proto::card_event::Kind::Removed,
            _ => proto::card_event::Kind::Reading,
        };
        let frame = proto::PlainFrame {
            kind: Some(proto::plain_frame::Kind::CardEvent(proto::CardEvent {
                kind: proto_kind as i32,
                atr_hex: atr_hex.unwrap_or_default(),
                ts_ms: now_ms(),
            })),
        };
        let g = state.sessions.read().await;
        let s = match (&session_id, g.len()) {
            (Some(id), _) => g.get(id).ok_or("sessione sconosciuta")?.clone(),
            (None, 1) => g.values().next().unwrap().clone(),
            (None, 0) => return Err("nessuna sessione attiva".into()),
            (None, _) => return Err("session_id richiesto (più sessioni)".into()),
        };
        drop(g);
        s.tx_job
            .send(TxJob::SealAndSend(frame))
            .await
            .map_err(|_| "sessione chiusa".to_string())?;
        Ok(())
    }

    /// Loopback di sviluppo (mock `9000` esplicito): NON è il path carta.
    /// Il path reale è `ApduRequest` -> evento -> `mobile_apdu_reply` (vedi sopra).
    ///
    /// # Errors
    /// `String` su hex invalido o APDU più corta di 4B.
    ///
    /// Nota clippy: gli argomenti restano `String` owned perché la firma IPC
    /// di Tauri deserializza valori owned (niente borrow dall'invoke JSON).
    #[allow(clippy::needless_pass_by_value)]
    #[tauri::command]
    pub fn mobile_transmit(
        session_id: String,
        apdu_hex: String,
        _timeout_ms: u64,
        _state: tauri::State<'_, Arc<MobileState>>,
    ) -> Result<serde_json::Value, String> {
        let bytes = hex::decode(&apdu_hex).map_err(|e| e.to_string())?;
        if bytes.len() < 4 {
            return Err("APDU troppo corta".into());
        }
        let _ = session_id;
        Ok(serde_json::json!({"dataHex": "", "sw1": 0x90, "sw2": 0x00, "latencyMs": 1}))
    }
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("sess-{n:x}")
}

/// Stato condiviso + export per Tauri mobile.
#[must_use]
pub fn init_state() -> Arc<MobileState> {
    Arc::new(MobileState::default())
}

/// Entry point Tauri (mobile + host). Registra barcode scanner e i comandi E2EE.
///
/// Il plugin barcode-scanner esiste solo su Android/iOS (`#![cfg(mobile)]` nel
/// crate): su host la registrazione sparisce e resta un builder valido per
/// `cargo check`/`cargo test`.
///
/// # Panics
/// Se Tauri non riesce ad avviarsi (context non valido o event loop terminato
/// con errore).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default()
        .manage(init_state())
        .invoke_handler(tauri::generate_handler![
            commands::mobile_handshake,
            commands::mobile_apdu_reply,
            commands::nfc_card_event,
            commands::mobile_transmit
        ]);

    #[cfg(mobile)]
    {
        builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    }

    builder
        .run(tauri::generate_context!())
        .expect("errore di avvio dell'app mobile");
}

#[cfg(test)]
mod tests {
    use super::commands::{AfterTls, check_expiry_at, decide_after_tls};
    use super::{PairingError, QrMaterial, code};

    /// QR senza `exp_unix` (engine o client legacy): nessun controllo possibile.
    fn qr_mondo(exp: Option<u64>) -> QrMaterial {
        QrMaterial {
            ip: "192.168.1.10".into(),
            port: 8080,
            nonce_b64: String::new(),
            peer_pubkey_b64: String::new(),
            mlkem_b64: None,
            host: Some("nfc.local".into()),
            tls_port: Some(8443),
            tls_pin_b64: Some("pin".into()),
            exp_unix: exp,
        }
    }

    /// Un certificato non pinnato **non** deve mai portare al canale in chiaro.
    ///
    /// È la regressione più insidiosa del canale mobile: se il rifiuto del pin
    /// venisse trattato come un errore di rete, chiunque potrebbe *scegliere* di
    /// far viaggiare la sessione in chiaro semplicemente rifiutando la connessione
    /// TLS. L'E2EE continuerebbe a reggere, quindi nessun test funzionale lo
    /// noterebbe, e la privacy del trasporto diventerebbe negoziabile.
    #[test]
    fn rifiuto_del_pin_non_ripiega_mai_in_chiaro() {
        let d = decide_after_tls(Some("pin TLS non corrisponde".into()));
        assert!(
            matches!(d, AfterTls::Abort(_)),
            "il rifiuto del pin deve abortire, non ripiegare: {d:?}"
        );
    }

    /// Solo un errore **di rete** legittima il ripiego.
    #[test]
    fn errore_di_rete_ripiega_in_chiaro() {
        let d = decide_after_tls(None);
        assert_eq!(d, AfterTls::RipiegoInChiaro);
    }

    /// Il motivo del rifiuto arriva all'utente: senza diagnostica, l'unica
    /// reazione possibile è riprovare all'infinito.
    #[test]
    fn il_motivo_del_rifiuto_è_conservato() {
        let AfterTls::Abort(motivo) =
            decide_after_tls(Some("pin TLS non corrisponde (x, y)".into()))
        else {
            panic!("atteso Abort");
        };
        assert!(motivo.contains("pin TLS non corrisponde"), "{motivo}");
    }

    /// Un QR scaduto viene respinto **prima** di aprire la connessione.
    ///
    /// È la diagnosi che rende `--rotate-ca` recuperabile: senza, un QR
    /// precedente fallirebbe con "pin TLS non corrisponde", che è anche il testo
    /// che mostrerebbe un certificato presentato da qualcun altro — e le due
    /// reazioni sono opposte.
    #[test]
    fn qr_scaduto_rifiutato_prima_della_connessione() {
        let t0 = 1_800_000_000u64;
        let margine = nfc_core::pairing::QR_EXPIRY_GRACE_SECS;
        let qr = qr_mondo(Some(t0 + 300));

        assert!(check_expiry_at(&qr, t0).is_ok(), "appena emesso");
        assert!(
            check_expiry_at(&qr, t0 + 300).is_ok(),
            "alla scadenza esatta è ancora valido"
        );
        // L'orologio del device può essere indietro di qualche minuto: non
        // respinto un QR valido, o l'utente riceverebbe "rigenera" da un QR
        // appena emesso e non saprebbe cosa fare.
        assert!(
            check_expiry_at(&qr, t0 + 300 + margine).is_ok(),
            "deriva del device entro il margine"
        );

        let e = check_expiry_at(&qr, t0 + 300 + margine + 1)
            .expect_err("oltre il margine deve essere respinto");
        assert_eq!(e.code, code::QR_EXPIRED);
        assert!(
            e.detail
                .as_deref()
                .unwrap_or_default()
                .contains("scaduto da 1 s"),
            "il dettaglio dice quanto: {:?}",
            e.detail
        );
    }

    /// Un QR che scade mentre l'orologio è indietro non viene respinto: il
    /// margine esiste per questo, e senza test il margine è un numero magico che
    /// il prossimo refactor è libero di cambiare.
    #[test]
    fn margine_tolera_la_deriva_fino_al_limite() {
        let t0 = 1_800_000_000u64;
        let margine = nfc_core::pairing::QR_EXPIRY_GRACE_SECS;
        let qr = qr_mondo(Some(t0));
        assert!(check_expiry_at(&qr, t0 + margine - 1).is_ok());
        assert!(check_expiry_at(&qr, t0 + margine).is_ok());
        assert_eq!(
            check_expiry_at(&qr, t0 + margine + 1).unwrap_err().code,
            code::QR_EXPIRED
        );
    }

    /// QR senza scadenza: la compatibilità con engine e client precedenti non
    /// può diventare un rifiuto. L'autorità resta l'handshake lato engine.
    #[test]
    fn qr_senza_scadenza_non_viene_rifiutato() {
        let qr = qr_mondo(None);
        assert!(check_expiry_at(&qr, 1_800_000_000 + 10_000_000).is_ok());
    }

    /// L'errore di scadenza è serializzabile con il `code` che il frontend
    /// localizza: senza `Serialize`, Tauri non riuscirebbe a trasportarlo e
    /// l'errore arriverebbe come testo grezzo — cioè non tradotto, che è
    /// esattamente il difetto che il tipo strutturato elimina.
    #[test]
    fn errore_di_scadenza_attraversa_l_ipc() {
        let e =
            check_expiry_at(&qr_mondo(Some(1_800_000_000u64)), 1_800_000_000 + 10_000).unwrap_err();
        let json = serde_json::to_value(&e).expect("serializzabile");
        assert_eq!(json["code"], code::QR_EXPIRED);
        assert!(json["detail"].is_string(), "il dettaglio deve arrivare");
    }

    /// L'init deve portare sempre la versione del materiale chiavi.
    ///
    /// Senza `keys_v` l'engine rifiuta il client come legacy: l'utente vedrebbe
    /// "aggiorna entrambi" mentre il problema sarebbe questa riga. È il motivo
    /// per cui la costruzione dell'init è una funzione separata.
    #[test]
    fn init_porta_sempre_keys_v() {
        let eph = [1u8; 32];
        let nonce = [2u8; 32];
        let h = crate::commands::build_handshake_init(&eph, &nonce, vec![], 1);
        assert_eq!(h.keys_v, nfc_core::crypto::KEYS_V);
        // E deve essere la versione che l'engine accetta, non una a caso.
        assert_eq!(h.keys_v, 2);
        assert_eq!(h.eph_pubkey.len(), 32);
        assert_eq!(h.nonce32.len(), 32);
    }

    /// Ogni codice di chiusura che l'engine può inviare deve avere una
    /// traduzione: un codice non previsto cadrebbe su `peerClosed`, che dice
    /// "molto probabilmente il QR è già stato usato" — l'ipotesi che questo
    /// meccanismo è nato per sostituire.
    #[test]
    fn ogni_codice_di_chiusura_e_tradotto() {
        use nfc_core::protocol::close;
        for (chiuso, atteso) in [
            (close::HANDSHAKE_MALFORMATO, code::BAD_FRAME),
            (close::QR_USATO, code::QR_USED),
            (close::QR_SCADUTO, code::QR_EXPIRED),
            (close::QR_NON_CORRISPONDE, code::QR_INVALID),
            (close::CHIAVI_LEGACY, code::PEER_MISMATCH),
            (close::BUILD_SENZA_PQ, code::PROTO_MISMATCH),
        ] {
            let e = code::da_chiusura(chiuso, "motivo di test");
            assert_eq!(e.code, atteso, "codice {chiuso} mal tradotto");
            let atteso_detail = format!("engine {chiuso}: motivo di test");
            assert_eq!(e.detail.as_deref(), Some(atteso_detail.as_str()));
        }
        // Fuori dal perimetro noto: resta una chiusura, non un panico.
        assert_eq!(code::da_chiusura(4999, "x").code, code::PEER_CLOSED);
    }

    /// Ogni codice restituito dal pairing deve essere serializzabile e non vuoto.
    ///
    /// Copre il caso in cui un `Err` viene costruito con una stringa vuota: il
    /// frontend mostrerebbe `Errore di pairing ()` e nessun test funzionale se
    /// ne accorgerebbe, perché il pairing fallisce comunque.
    #[test]
    fn codici_di_pairing_non_vuoti() {
        for c in [
            code::QR_INVALID,
            code::QR_EXPIRED,
            code::QR_USED,
            code::PIN_REJECTED,
            code::UNREACHABLE,
            code::NO_PLAIN_CHANNEL,
            code::HANDSHAKE_TIMEOUT,
            code::PEER_CLOSED,
            code::BAD_FRAME,
            code::PEER_MISMATCH,
            code::PROTO_MISMATCH,
            code::DECRYPT_FAILED,
            code::INTERNAL,
        ] {
            assert!(!c.is_empty(), "codice vuoto");
            assert!(
                serde_json::to_value(PairingError::new(c)).is_ok(),
                "codice non serializzabile: {c}"
            );
        }
    }
}
