//! Server WebSocket + REST — stato dell'arte 2026 (Axum 0.8 + rustls).
//! Servito in chiaro su 127.0.0.1:8080 (compat) e in TLS su nfc.local:8443
//! (primario, vedi `local_tls` + `docs/LOCAL-DOMAIN.md`).
//! Stack: **Axum 0.8** + `tower-http` CORS + `rustls` (via tungstenite feature).
//! - `GET /v1/mobile` (WS binario prost `EncryptedFrame`, E2EE X25519 o ibrida
//!   X25519+ML-KEM-768). Handshake con nonce `QRv2` + SAS a 6 cifre.
//! - `GET /v1/extension` (WS JSON per estensione/webapp, allowlist Origin).
//! - `GET /v1/status` (health), `POST /v1/transmit` (REST reale, stesso schema).
//!
//! Sicurezza 2026:
//!  - Bind solo 127.0.0.1 + middleware che rifiuta non-loopback (doppia difesa).
//!  - CORS `tower-http` con allowlist dinamica (PA/CIE + origini utente).
//!  - Limite frame 128KB, timeout handshake 15s, APDU 1..30s.
//!  - `MobileHub`: registry multi-sessione con `mpsc` (routing per
//!    `reader_name`, fallback LRU; i job extension -> mobile sono recapitati
//!    davvero, non 502 cieco).

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use tauri::{AppHandle, Manager};

use axum::{
    Router,
    extract::{
        ConnectInfo, Path, State,
        ws::{CloseFrame, Message as WsMsg, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderValue, StatusCode, request::Parts},
    response::{IntoResponse, Json},
    routing::{get, post},
};
use nfc_core::{
    crypto::{Direction, KEYS_V, SessionKeys, X25519Keypair, sas_confirm},
    protocol::close,
    protocol::proto,
    protocol::{self, CardStatus, TransmitReply},
    transport::TransportPolicy,
};
use prost::Message;
use tokio::sync::{RwLock, mpsc};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::{info, warn};
use uuid::Uuid;

use crate::events::{EngineEvent, EventBus};

// ---------------------------------------------------------------------------
// Stato condiviso
// ---------------------------------------------------------------------------

/// Origini autorizzate a usare /v1/extension (popolate da store + default PA).
#[derive(Debug, Default)]
pub struct OriginPolicy {
    allowed: RwLock<HashSet<String>>,
}

impl OriginPolicy {
    /// Parte statica dell'allowlist: nessun lock, quindi utilizzabile anche
    /// dal predicate sincrono di `CorsLayer`.
    fn is_allowed_static(origin: &str) -> bool {
        origin.starts_with("chrome-extension://")
            || origin.starts_with("moz-extension://")
            || origin.starts_with("tauri://")
            // Loopback in chiaro (8080) e in TLS (8443): le webapp servite
            // dall'engine hanno Origin `https://localhost:8443` /
            // `https://127.0.0.1:8443`, non `nfc.local`. Senza queste voci la
            // webapp su loopback riceveva 403 "origin non autorizzata" e la
            // console APDU era inutilizzabile.
            || origin.starts_with("http://localhost:")
            || origin.starts_with("http://127.0.0.1:")
            || origin.starts_with("https://localhost:")
            || origin.starts_with("https://127.0.0.1:")
            || origin.starts_with("https://[::1]:")
            || origin == "https://nfc.local:8443"
            || origin.ends_with(".nfc.local:8443")
            || origin == "https://nfc.local"
            || origin.ends_with(".nfc.local")
    }

    pub async fn is_allowed(&self, origin: Option<&str>) -> bool {
        let Some(o) = origin else { return true };
        if Self::is_allowed_static(o) {
            return true;
        }
        self.allowed.read().await.contains(o)
    }

    /// Variante sincrona per `CorsLayer::allow_origin`, che invoca un predicate
    /// non-async. Usa `try_read`: se il lock è momentaneamente preso da una
    /// `allow()` concorrente, fallisce **chiuso** (nega l'Origin) invece di
    /// concedere — il errore è un 403 CORS innocuo, non un'apertura.
    fn is_allowed_sync(&self, origin: Option<&str>) -> bool {
        let Some(o) = origin else { return true };
        if Self::is_allowed_static(o) {
            return true;
        }
        self.allowed.try_read().is_ok_and(|set| set.contains(o))
    }

    /// Guard per le letture LAN-visibili (`/v1/qr`, `/v1/metrics`).
    ///
    /// - Origin presente → deve stare in allowlist (blocca il drive-by da
    ///   browser, che inoltra sempre `Origin` in cross-origin).
    /// - Origin assente → ammesso **solo** da loopback (curl, webapp
    ///   same-origin); un client LAN senza `Origin` viene respinto.
    ///
    /// Rispetto a [`is_allowed`] un client LAN anonimo (senza `Origin`) non
    /// legge più il materiale di pairing: alza l'asticella sulla voce residua
    /// del threat model senza togliere la lettura LAN "legittima" del telefono
    /// (che presenta `Origin: https://nfc.local:8443`).
    pub async fn is_allowed_read(&self, origin: Option<&str>, from_loopback: bool) -> bool {
        match origin {
            Some(o) => self.is_allowed(Some(o)).await,
            None => from_loopback,
        }
    }

    pub async fn allow(&self, origin: String) {
        self.allowed.write().await.insert(origin);
    }

    /// Aggiunge l'origin con cui la webapp raggiunge l'engine dalla LAN **via
    /// IP**: `https://<ip-lan>:8443`. Nessuna voce statica la copre (solo
    /// loopback, `nfc.local` ed estensioni): senza questa, il browser del
    /// telefono apre la console ma la WS `/v1/extension` risponde 403
    /// "origin non autorizzata" **prima** del flusso di consenso — il banner
    /// nella tray non compare mai e la UI resta "canale locale: non
    /// autorizzato (avvia il consenso)" senza via d'uscita a schermo.
    ///
    /// L'IP è lo stesso che l'engine mette già in QR/mDNS/SAN; su cambio rete
    /// va rieseguita (lo fa anche `qr::regenerate_into`).
    pub async fn allow_lan_engine_origin(&self) {
        if let Some(ip) = nfc_core::net::lan_ipv4() {
            self.allowed
                .write()
                .await
                .insert(format!("https://{ip}:{}", nfc_core::local_domain::TLS_PORT));
        }
    }

    pub async fn snapshot(&self) -> Vec<String> {
        self.allowed.read().await.iter().cloned().collect()
    }
}

#[derive(Debug)]
pub struct ApduResult {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
    pub latency_ms: u64,
}

/// Registry sessioni mobile attive (multi-mobile 2026).
/// Supporta multiple sessioni simultanee con routing per `reader_name`.
#[derive(Debug, Default)]
pub struct MobileHub {
    sessions: RwLock<HashMap<String, SessionEntry>>,
}

#[derive(Debug)]
struct SessionEntry {
    tx: mpsc::Sender<MobileJob>,
    reader_name: String,
    connected_at: Instant,
    /// Ultimo instradamento verso questa sessione (routing LRU quando il job
    /// non ha un `reader_name` target).
    last_used: Instant,
}

impl MobileHub {
    /// Registra una nuova sessione mobile.
    ///
    /// `session_id` = identificativo univoco (es. UUID).
    /// `reader_name` = nome del reader (es. "vpcd-0", "pcsc-ACR122U").
    pub async fn register(
        &self,
        session_id: String,
        reader_name: String,
        tx: mpsc::Sender<MobileJob>,
    ) {
        let now = Instant::now();
        let entry = SessionEntry {
            tx,
            reader_name,
            connected_at: now,
            last_used: now,
        };
        self.sessions.write().await.insert(session_id, entry);
    }

    /// Rimuove una sessione mobile.
    pub async fn unregister(&self, session_id: &str) {
        self.sessions.write().await.remove(session_id);
    }

    /// Inoltra un job APDU alla sessione appropriata.
    ///
    /// Routing logic:
    /// 1. Se `job.target_reader.is_some()` → cerca sessione con quel `reader_name`
    /// 2. Altrimenti → LRU: la sessione usata meno di recente (`last_used`),
    ///    così l'instradamento ruota fra i mobile collegati
    /// 3. Fallback → prima sessione disponibile
    ///
    /// # Errors
    /// `anyhow` se nessuna sessione disponibile o canale chiuso.
    pub async fn send(&self, job: MobileJob) -> anyhow::Result<()> {
        let mut sessions = self.sessions.write().await;
        if sessions.is_empty() {
            return Err(anyhow::anyhow!("nessun lettore mobile connesso"));
        }

        let target_tx = if let Some(target_reader) = &job.target_reader {
            // Cerca sessione specifica per reader_name
            sessions
                .values_mut()
                .find(|e| e.reader_name == *target_reader)
                .map(|e| {
                    e.last_used = Instant::now();
                    e.tx.clone()
                })
        } else {
            None
        };

        let target_tx = if let Some(tx) = target_tx {
            tx
        } else {
            // LRU: la sessione usata meno di recente riceve il prossimo job
            let entry = sessions
                .values_mut()
                .min_by_key(|e| e.last_used)
                .ok_or_else(|| anyhow::anyhow!("nessun lettore mobile connesso"))?;
            let tx = entry.tx.clone();
            entry.last_used = Instant::now();
            tx
        };

        drop(sessions);
        target_tx
            .send(job)
            .await
            .map_err(|_| anyhow::anyhow!("mobile disconnesso (hub pieno/chiuso)"))?;
        Ok(())
    }

    /// Lista tutte le sessioni attive per UI/monitoring.
    pub async fn list_sessions(&self) -> Vec<(String, String, Instant)> {
        self.sessions
            .read()
            .await
            .iter()
            .map(|(id, e)| (id.clone(), e.reader_name.clone(), e.connected_at))
            .collect()
    }

    pub async fn is_online(&self) -> bool {
        !self.sessions.read().await.is_empty()
    }
}

/// Cap sulle negoziazioni `/v1/mobile` concorrenti. Difende da DoS/brute-force
/// sull'handshake (tentativi in parallelo entro il TTL del QR). Non limita il
/// numero di sessioni *stabilite* (hub multi-mobile): il permesso è rilasciato
/// appena l'handshake termina, in successo o errore.
pub const HANDSHAKE_MAX_CONCURRENT: usize = 8;

/// Finestra e cap del rate-limit per IP sull'handshake `/v1/mobile`
/// (anti brute-force: il cap di concorrenza limita i tentativi *in parallelo*,
/// questo limita quelli *nel tempo* da un singolo IP).
pub const HANDSHAKE_RATE_WINDOW: std::time::Duration = std::time::Duration::from_mins(1);
pub const HANDSHAKE_RATE_MAX: u32 = 20;

/// Finestra e cap del rate-limit per IP sulle letture LAN (`/v1/qr`,
/// `/v1/metrics`): limita lo scraping/enumerazione da un singolo IP.
pub const READ_RATE_WINDOW: std::time::Duration = std::time::Duration::from_mins(1);
pub const READ_RATE_MAX: u32 = 60;

/// Numero massimo di IP tracciati prima della pota opportunistica (difende la
/// mappa da crescita illimitata con IP arbitrari).
const RATE_LIMITER_MAX_ENTRIES: usize = 4096;

/// Rate-limiter a **finestra fissa** per IP, in memoria (si azzera al riavvio).
///
/// Chiave: `IpAddr` del peer. Non è un token-bucket: all'inizio di ogni finestra
/// il contatore riparte, quindi il caso peggiore è 2×`max` a cavallo del
/// confine — accettabile perché il fine è frenare brute-force/scraping, non
/// garantire un rate esatto.
#[derive(Debug)]
pub struct RateLimiter {
    window: std::time::Duration,
    max: u32,
    buckets: std::sync::Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(window: std::time::Duration, max: u32) -> Self {
        Self {
            window,
            max,
            buckets: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Registra un tentativo per `ip` e ritorna `false` se il cap della finestra
    /// corrente è superato (→ il chiamante risponde 429).
    #[must_use]
    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buckets.len() > RATE_LIMITER_MAX_ENTRIES {
            buckets.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = buckets.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
    }
}

/// Contesto globale del server.
pub struct WsContext {
    pub policy: TransportPolicy,
    pub bus: Arc<EventBus>,
    pub origins: Arc<OriginPolicy>,
    /// Canale legacy (compat): usato come fallback se hub vuoto.
    pub to_mobile: mpsc::Sender<MobileJob>,
    pub pending: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<ApduResult>>>>,
    pub handshake_material: RwLock<HandshakeMaterial>,
    pub desktop_kp: RwLock<X25519Keypair>,
    /// Chiave ML-KEM-768 desktop (`QRv2` pq=1). `None` se build senza `pq`.
    pub mlkem_ek_b64: RwLock<Option<String>>,
    /// Coppia ML-KEM per decapsulare il ct mobile (solo con feature `pq`).
    #[cfg(feature = "pq")]
    pub pq_kp: RwLock<Option<nfc_core::crypto::pq::MlKemKeypair>>,
    pub hub: Arc<MobileHub>,
    /// Tracker heartbeat Wi-Fi (sweep nel task dedicato di `lib.rs`).
    pub heartbeat: Arc<crate::heartbeat::Heartbeat>,
    /// Metriche Prometheus (solo loopback).
    pub metrics: Arc<crate::metrics::Metrics>,
    /// QR corrente (testo + PNG data-URL) per la pagina `GET /pair`.
    pub pair_qr: RwLock<(String, String)>,
    /// Client locali autorizzati (estensione, REST): consenso esplicito.
    pub auth: crate::local_auth::ClientAuth,
    /// Handle Tauri per risolvere risorse bundle (web/dist).
    /// Impostato nel setup Tauri (inizialmente `None` nei test).
    pub app_handle: RwLock<Option<AppHandle>>,
    /// Cap di concorrenza sulle negoziazioni `/v1/mobile` (anti-DoS/brute-force).
    pub handshake_gate: Arc<tokio::sync::Semaphore>,
    /// Rate-limit per IP sull'handshake `/v1/mobile`.
    pub handshake_limiter: RateLimiter,
    /// Rate-limit per IP sulle letture LAN (`/v1/qr`, `/v1/metrics`).
    pub read_limiter: RateLimiter,
}

impl std::fmt::Debug for WsContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `RwLock`/`mpsc`/`SessionKeys` non sono `Debug` utili nei log.
        f.debug_struct("WsContext")
            .field("policy", &self.policy)
            .field("origins", &"<allowlist>")
            .field("mobile_online", &"<async>")
            .finish_non_exhaustive()
    }
}

impl WsContext {
    /// Costruttore per test di integrazione (chiavi effimere, niente I/O).
    #[must_use]
    pub fn new_test() -> Arc<Self> {
        let bus = Arc::new(EventBus::new(64));
        let (tx, legacy_rx) = mpsc::channel::<MobileJob>(8);
        drop(legacy_rx);
        Arc::new(Self {
            policy: TransportPolicy::default(),
            bus,
            origins: Arc::new(OriginPolicy::default()),
            to_mobile: tx,
            pending: Arc::new(RwLock::new(HashMap::new())),
            handshake_material: RwLock::new(HandshakeMaterial::fresh([0u8; 32])),
            desktop_kp: RwLock::new(X25519Keypair::generate()),
            mlkem_ek_b64: RwLock::new(None),
            #[cfg(feature = "pq")]
            pq_kp: RwLock::new(None),
            hub: Arc::new(MobileHub::default()),
            heartbeat: Arc::new(crate::heartbeat::Heartbeat::new(
                TransportPolicy::default().dead_after,
            )),
            metrics: Arc::new(crate::metrics::Metrics::default()),
            pair_qr: RwLock::new((String::new(), String::new())),
            auth: crate::local_auth::ClientAuth::new_test(),
            app_handle: RwLock::new(None),
            handshake_gate: Arc::new(tokio::sync::Semaphore::new(HANDSHAKE_MAX_CONCURRENT)),
            handshake_limiter: RateLimiter::new(HANDSHAKE_RATE_WINDOW, HANDSHAKE_RATE_MAX),
            read_limiter: RateLimiter::new(READ_RATE_WINDOW, READ_RATE_MAX),
        })
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeMaterial {
    pub nonce32: [u8; 32],
    /// Istante di emissione QR: handshake ammessi solo entro `QR_TTL`.
    pub issued_at: Instant,
    /// Single-use: bruciato al primo handshake riuscito (anti replay del QR).
    pub used: bool,
}

/// Validità massima del QR dal momento della generazione.
pub const QR_TTL: std::time::Duration = std::time::Duration::from_mins(5);

/// Validità residua del QR in millisecondi: `ttl − elapsed`, mai negativa.
///
/// È lo stesso clock (`handshake_material.issued_at`) che l'handshake verifica
/// contro `QR_TTL`: la tray la usa per il countdown e per rigenerare allo zero.
#[must_use]
pub fn qr_remaining_ms(ttl: std::time::Duration, elapsed: std::time::Duration) -> u64 {
    let ttl_ms = ttl.as_millis();
    // `saturating_sub` clampa a zero oltre la scadenza; `min(ttl_ms)` tiene il
    // valore dentro l'intervallo, così il cast a u64 è sempre totale.
    u64::try_from(ttl_ms.saturating_sub(elapsed.as_millis()).min(ttl_ms)).unwrap_or(u64::MAX)
}

impl HandshakeMaterial {
    #[must_use]
    pub fn fresh(nonce32: [u8; 32]) -> Self {
        Self {
            nonce32,
            issued_at: Instant::now(),
            used: false,
        }
    }
}

#[derive(Debug)]
pub struct MobileJob {
    pub request_id: String,
    pub apdu: Vec<u8>,
    pub timeout_ms: u64,
    pub reply_tx: tokio::sync::oneshot::Sender<ApduResult>,
    /// Opzionale: se specificato, inoltra solo alla sessione con questo `reader_name`.
    /// Usato per routing multi-reader (es. "vpcd-0", "pcsc-ACR122U").
    pub target_reader: Option<String>,
}

// ---------------------------------------------------------------------------
// Router condiviso HTTP (8080) e HTTPS (8443 `nfc.local`)
// ---------------------------------------------------------------------------

/// Costruisce il Router servito sia in chiaro (compat 8080) sia in TLS
/// (8443). Estratto come funzione per riuso da `local_tls::serve_tls`.
/// Include anche `GET /` (landing con link ai servizi) e `GET /pair`
/// (pagina QR per `https://pair.nfc.local`).
pub fn router(ctx: Arc<WsContext>) -> Router {
    // CORS 2026: l'Origin è valutato dalla stessa allowlist dei guard dei
    // handler, mai `*`. Con `allow_origin(Any)` una pagina web arbitraria
    // poteva leggere in cross-origin gli endpoint su loopback che non hanno un
    // controllo esplicito.
    let origins = Arc::clone(&ctx.origins);
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            move |origin: &HeaderValue, _parts: &Parts| {
                origins.is_allowed_sync(origin.to_str().ok())
            },
        ))
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/", get(handle_landing))
        .route("/pair", get(handle_pair_page))
        .route("/v1/status", get(handle_status))
        .route("/v1/transmit", post(handle_transmit_rest))
        .route("/v1/signal", post(handle_signal_rest))
        .route("/v1/metrics", get(handle_metrics))
        .route("/v1/mobile", get(handle_mobile_upgrade))
        .route("/v1/extension", get(handle_extension_upgrade))
        .route("/v1/qr", get(handle_qr_get))
        .route("/v1/qr", post(handle_qr_regenerate))
        .route("/v1/scan", post(handle_scan_beacon))
        // Webapp/PWA (desktop + mobile): stessi file per ogni ruolo, la UI
        // sceglie la vista da `?role=`. Fallback SPA su index.html.
        .route("/app", get(web_index).post(web_index))
        .merge(web_router())
        .fallback(web_fallback)
        .layer(axum::middleware::from_fn(web_security_middleware))
        .layer(cors)
        .with_state(ctx)
}

/// Risposta 403 standard per guard falliti (loopback / Origin).
fn forbidden(reason: &str) -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"type":"error","code":403,"message":reason})),
    )
        .into_response()
}

/// `GET /v1/qr`: QR di pairing corrente (testo + PNG data-URL).
///
/// È l'equivalente REST del comando IPC `get_qr`: la webapp non ha accesso
/// all'IPC Tauri, quindi legge il pairing da qui.
///
/// **Solo allowlist Origin** (niente guard loopback): leggibile dalla LAN via
/// `https://nfc.local:8443/v1/qr`, così il telefono può recuperare il pairing
/// dal dominio invece di dipendere dal solo IP codificato nel QR.
///
/// L'Origin è il guard che conta: blocca il caso drive-by da browser
/// (`fetch("http://127.0.0.1:8080/v1/qr")` da un sito qualsiasi), che è il
/// vettore reale. Le richieste senza `Origin` restano accettate **solo da
/// loopback** (curl, webapp same-origin); un client LAN senza `Origin` è
/// respinto perché non può essere la webapp del telefono (che presenta
/// `Origin: https://nfc.local:8443`).
async fn handle_qr_get(
    State(ctx): State<Arc<WsContext>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> axum::response::Response {
    if !ctx.read_limiter.allow(addr.ip()) {
        ctx.metrics.rate_limited();
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"type":"error","code":429,"message":"troppe richieste"})),
        )
            .into_response();
    }
    let origin = headers.get("origin").and_then(|v| v.to_str().ok());
    if !ctx.origins.is_allowed_read(origin, is_loopback(addr)).await {
        return forbidden("origin non autorizzata");
    }
    let (text, png) = ctx.pair_qr.read().await.clone();
    Json(serde_json::json!({
        "type": "qr",
        "qr_text": text,
        "qr_png": png,
        "https": nfc_core::local_domain::https_base(),
    }))
    .into_response()
}

/// `POST /v1/scan`: beacon informativo dalla webapp quando un QR di pairing
/// valido è stato scansionato (qualsiasi browser, anche remoto).
///
/// NON è un'autorizzazione: il pairing resta autorizzato dal QR + handshake
/// E2EE. Serve solo a far sapere al desktop che qualcuno ha inquadrato il QR,
/// così il flusso "ho scansionato" ha un riscontro visibile sull'altro schermo.
/// L'origin è valutata come per `/v1/qr`: solo pagine servite da questo engine
/// possono inviarlo — niente spam da client arbitrari della LAN.
async fn handle_scan_beacon(
    State(ctx): State<Arc<WsContext>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let origin = headers.get("origin").and_then(|v| v.to_str().ok());
    if !ctx.origins.is_allowed(origin).await {
        return forbidden("origin non autorizzata");
    }
    ctx.bus.publish(crate::events::EngineEvent::QrScanned);
    Json(serde_json::json!({"type": "scan", "ok": true})).into_response()
}

/// `POST /v1/qr`: rigenera nonce + chiavi (invalida le sessioni precedenti).
///
/// Come `regenerate_qr` lato Tauri. La rotazione è delegata a `AppState`
/// quando l'engine è in-process; in fallback (QR non ancora pronto) restituisce
/// il QR corrente invece di un errore, così la webapp resta usabile.
async fn handle_qr_regenerate(
    State(ctx): State<Arc<WsContext>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> axum::response::Response {
    if !is_loopback(addr) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"type":"error","code":403,"message":"solo loopback"})),
        )
            .into_response();
    }
    let outcome = crate::qr::regenerate_into(&ctx).await;
    let (text, png) = ctx.pair_qr.read().await.clone();
    let mut body = serde_json::json!({"type": "qr", "qr_text": text, "qr_png": png});
    if let Err(e) = outcome {
        // QR precedente ancora valido: si restituisce con un avviso, non un 500.
        body["warning"] = serde_json::json!(format!("rigenerazione fallita: {e}"));
    }
    Json(body).into_response()
}

// ---------------------------------------------------------------------------
// Webapp / PWA (desktop + mobile)
// ---------------------------------------------------------------------------

/// Radice degli asset della webapp.
///
/// Priorità:
/// 1. `$NFC_WEB_DIST` (override esplicito, es. dev)
/// 2. Tauri bundle resource `web/dist` (produzione, via `AppHandle::path().resolve()`)
/// 3. `../../web/dist` relativo a `CARGO_MANIFEST_DIR` (sviluppo `cargo run`)
/// 4. `web/dist` relativo alla cwd (fallback generico)
///
/// Se la cartella non esiste il fallback risponde con una pagina che spiega come
/// buildarla, invece di un 404 muto.
async fn web_dist_dir(app_handle: &RwLock<Option<AppHandle>>) -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("NFC_WEB_DIST") {
        return std::path::PathBuf::from(dir);
    }
    // Produzione: risorsa nel bundle Tauri (risolta via AppHandle)
    let handle_guard = app_handle.read().await;
    if let Some(handle) = handle_guard.as_ref()
        && let Ok(path) = handle
            .path()
            .resolve("web/dist", tauri::path::BaseDirectory::Resource)
        && path.is_dir()
    {
        return path;
    }
    // Sviluppo: albero sorgente (`CARGO_MANIFEST_DIR` = `desktop/src-tauri`)
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let from_src = manifest.join("../../web/dist");
    if from_src.is_dir() {
        return from_src;
    }
    // Fallback generico
    std::path::PathBuf::from("web/dist")
}

/// `index.html` della webapp: identico per `/`, `/app` e route SPA.
async fn web_index(State(ctx): State<Arc<WsContext>>) -> axum::response::Response {
    no_store(serve_web_file(&ctx, "index.html").await)
}

/// Fallback SPA: qualsiasi path sconosciuto sotto la webapp restituisce
/// `index.html` (navigazione client-side), i path con estensione no.
async fn serve_web_file(ctx: &Arc<WsContext>, name: &str) -> axum::response::Response {
    let dir = web_dist_dir(&ctx.app_handle).await;
    let path = dir.join(name);
    if path.is_file() {
        return match tokio::fs::read(&path).await {
            Ok(bytes) => (
                [(axum::http::header::CONTENT_TYPE, content_type_for(name))],
                bytes,
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("webapp non leggibile: {e}"),
            )
                .into_response(),
        };
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "<!doctype html><meta charset=utf-8><title>NFC Remote</title>\
             <body style=\"font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem\">\
             <h1>Webapp non compilata</h1>\
             <p>Manca <code>{}</code>.</p>\
             <p>Compila con <code>npm --prefix web ci &amp;&amp; npm --prefix web run build</code>,\
             oppure imposta <code>NFC_WEB_DIST</code> su una directory già compilata.</p>\
             <p>Nel frattempo l'engine resta raggiungibile su \
             <a href=\"/v1/status\">/v1/status</a>, <a href=\"/pair\">/pair</a> \
             e <a href=\"/v1/extension\">/v1/extension</a>.</p>",
            path.display()
        ),
    )
        .into_response()
}

/// Route statiche della webapp.
///
/// `index.html` e `sw.js` prendono `no-store`: un service worker cacheato non
/// si aggiorna mai e l'utente resterebbe su una versione vecchia per sempre.
/// Gli asset in `assets/` hanno invece nome con hash → `immutable`.
fn web_router() -> Router<Arc<WsContext>> {
    Router::new()
        .route("/index.html", get(web_index).post(web_index))
        .route("/sw.js", get(web_sw).post(web_sw))
        .route(
            "/manifest.webmanifest",
            get(web_manifest).post(web_manifest),
        )
        .route("/assets/{*path}", get(web_assets))
}

/// CSP e header di sicurezza applicati alle sole risposte webapp (path non
/// `/v1/*`): il resto (JSON/WS) mantiene i default del router.
async fn web_security_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Le API e il canale E2EE restano senza CSP HTML: non ne hanno bisogno e
    // un header errato su `/v1/extension` romperebbe il WebSocket.
    let is_api = req.uri().path().starts_with("/v1/") || req.uri().path() == "/pair";
    let mut res = next.run(req).await;
    if !is_api {
        let h = res.headers_mut();
        h.insert(
            axum::http::header::CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static(WEB_CSP),
        );
        h.insert(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        );
        h.insert(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("no-referrer"),
        );
    }
    res
}

/// CSP della webapp: niente `unsafe-eval`, framing negato, connessioni solo
/// same-origin (il WS è sullo stesso host: `wss:`/`ws:` per lo schema).
///
/// `wasm-unsafe-eval` è l'eccezione **scoped** per il core WASM: senza,
/// Chromium blocca `WebAssembly.instantiate` con `script-src 'self'` e il
/// modulo `nfc-core-wasm` (`parse_pairing_qr`/`validate_apdu`) non si carica
/// mai. Non abilita `eval`: permette solo la compilazione WASM del modulo.
const WEB_CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
     style-src 'self'; img-src 'self' data:; connect-src 'self' wss: ws:; \
     manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; \
     frame-ancestors 'none'";

async fn web_manifest(State(ctx): State<Arc<WsContext>>) -> axum::response::Response {
    no_store(serve_web_file(&ctx, "manifest.webmanifest").await)
}

async fn web_sw(State(ctx): State<Arc<WsContext>>) -> axum::response::Response {
    no_store(serve_web_file(&ctx, "sw.js").await)
}

async fn web_assets(
    State(ctx): State<Arc<WsContext>>,
    Path(path): Path<String>,
) -> axum::response::Response {
    let res = serve_web_file(&ctx, &format!("assets/{path}")).await;
    // Nome con content-hash: cache immutabile, invalido cambiando il file.
    immutable(res)
}

/// Forza `Cache-Control` su una risposta già costruita.
fn no_store(mut res: axum::response::Response) -> axum::response::Response {
    res.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    res
}

fn immutable(mut res: axum::response::Response) -> axum::response::Response {
    res.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    res
}

/// Servizio statici della webapp con fallback SPA: path senza estensione
/// (rotte client-side) ricadono su `index.html`; le API `/v1/*` sono
/// instradate esplicitamente e quindi non arrivano qui.
///
/// Handler invece di `ServeDir` per evitare di esporre il tipo del fallback
/// (che `tower-http` cambia tra versioni) nella firma pubblica.
async fn web_fallback(
    State(ctx): State<Arc<WsContext>>,
    uri: axum::http::Uri,
) -> axum::response::Response {
    let rel = uri.path().trim_start_matches('/');
    let dir = web_dist_dir(&ctx.app_handle).await;
    // Nessuna traversata: normalizziamo e rifiutiamo qualsiasi `..`.
    let safe: std::path::PathBuf = rel
        .split('/')
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .collect();
    let candidate = dir.join(&safe);
    if safe.components().count() > 0 && candidate.is_file() {
        return serve_web_file(&ctx, &safe.to_string_lossy()).await;
    }
    serve_web_file(&ctx, "index.html").await
}

/// MIME minimale per gli asset serviti inline dalla webapp.
fn content_type_for(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        // La webapp 2026 è WASM-first: senza questo MIME il browser rifiuta
        // `instantiateStreaming` con `application/octet-stream` (MIME mismatch).
        "wasm" => "application/wasm",
        "css" => "text/css; charset=utf-8",
        "json" | "webmanifest" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Esposto come funzione (e non inline in `serve`) perché è una riga da cambiare
/// quando non è più un semplice `SocketAddr::from` ma un `Host` risolto — il
/// test può continuare a verificare che sia loopback senza dover avviare il
/// server.
#[must_use]
pub fn plain_bind_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Avvia il server in chiaro **solo su loopback**.
///
/// 8080 è il fallback dell'estensione sullo stesso desktop
/// (`ws://127.0.0.1:8080`), usato quando la CA locale non è fidata nel browser.
/// Il mobile in LAN non ci passa: usa `wss://nfc.local:8443` con il pin del
/// certificato contenuto nel QR, quindi questo canale non ha bisogno di essere
/// raggiungibile dalla rete — e non lo è.
///
/// # Errors
/// `anyhow` se il bind su 127.0.0.1 fallisce o il server termina in errore.
pub async fn serve(ctx: Arc<WsContext>, port: u16) -> anyhow::Result<()> {
    let app = router(ctx);
    let addr = plain_bind_addr(port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(port, addr = %addr, "WS/REST (axum 0.8) in ascolto su loopback (fallback estensione)");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn is_loopback(addr: SocketAddr) -> bool {
    // Il server è in ascolto su `[::]`: una connessione IPv4 arriva quindi come
    // `::ffff:127.0.0.1`. `Ipv6Addr::is_loopback()` è **falso** per gli
    // indirizzi IPv4-mapped ( confronta i segmenti con `::1`), quindi senza
    // questo unwrap ogni client loopback IPv4 — webapp su 127.0.0.1, app mobile
    // in locale, `curl --resolve` — prenderebbe un 403 "solo loopback".
    match addr.ip() {
        std::net::IpAddr::V6(v6) => {
            v6.to_ipv4_mapped().is_none_or(|v4| v4.is_loopback()) || v6.is_loopback()
        }
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
    }
}

async fn handle_status(State(ctx): State<Arc<WsContext>>) -> impl IntoResponse {
    let online = ctx.hub.is_online().await;
    Json(serde_json::json!({
        "ok": true,
        "engine": "nfc-desktop/0.3.0",
        "https": nfc_core::local_domain::https_base(),
        "wss_extension": nfc_core::local_domain::wss_extension(),
        "ws_legacy": nfc_core::local_domain::WS_LEGACY,
        "ws_legacy_scope": nfc_core::local_domain::WS_LEGACY_SCOPE,
        "mobile_online": online,
        "crypto": "x25519+hkdf+aesgcm/pq-hybrid-mlkem768",
    }))
}

/// Landing `GET /`: lista servizi su `nfc.local` (utile su <https://nfc.local:8443>/).
async fn handle_landing() -> impl IntoResponse {
    let base = nfc_core::local_domain::https_base();
    Json(serde_json::json!({
        "service": "nfc-remote",
        "domain": nfc_core::local_domain::LOCAL_DOMAIN,
        "https": base,
        "endpoints": {
            "status": format!("{base}/v1/status"),
            "transmit": format!("{base}/v1/transmit"),
            "ws_extension": nfc_core::local_domain::wss_extension(),
            "ws_mobile": nfc_core::local_domain::wss_mobile(),
            "pair": format!("{base}/pair"),
        }
    }))
}

/// Pagina `GET /pair` (HTML): QR + deep-link, usabile da `https://pair.nfc.local:8443`
/// senza tray app aperta. Il QR è single-use con TTL 5 minuti (rigeneralo dalla tray).
async fn handle_pair_page(State(ctx): State<Arc<WsContext>>) -> impl IntoResponse {
    use axum::response::Html;
    let online = ctx.hub.is_online().await;
    let (qr_text, qr_png) = ctx.pair_qr.read().await.clone();
    let short = if qr_text.len() > 48 {
        format!("{}…", &qr_text[..48])
    } else {
        qr_text
    };
    Html(format!(
        r#"<!doctype html><html lang="it"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NFC Remote — Pairing</title>
<style>body{{font-family:system-ui;max-width:480px;margin:24px auto;padding:0 16px}}img{{width:100%;max-width:340px;border:1px solid #ccc;border-radius:8px}}code{{word-break:break-all;font-size:12px}}</style>
</head><body>
<h1>Accoppia smartphone</h1>
<p>Stato mobile: <b>{}</b></p>
<img alt="QR pairing" src="{}">
<p><code>{}</code></p>
<p><a href="nfc://pair">Apri nella tray app (nfc://pair)</a></p>
<p>Servizi: <a href="/v1/status">status</a> · <a href="/v1/metrics">metrics</a> · WS <code>/v1/extension</code> · E2EE <code>/v1/mobile</code></p>
<p><small>QR single-use, validità 5 minuti. Dopo l'handshake confronta il SAS a 6 cifre sui due schermi.</small></p>
</body></html>"#,
        if online { "online" } else { "offline" },
        qr_png,
        short
    ))
}

/// Segnalazione WebRTC `POST /v1/signal` (solo loopback + allowlist Origin).
async fn handle_signal_rest(
    State(ctx): State<Arc<WsContext>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !is_loopback(addr) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"type":"error","code":403,"message":"solo loopback"})),
        );
    }
    let origin = headers.get("origin").and_then(|v| v.to_str().ok());
    if !ctx.origins.is_allowed(origin).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"type":"error","code":403,"message":"origin non autorizzata"})),
        );
    }
    let (status, value) = crate::webrtc_fallback::handle_signal(body).await;
    (status, Json(value))
}

/// Metriche Prometheus (`curl https://nfc.local:8443/v1/metrics`).
///
/// Solo allowlist Origin (niente guard loopback): le metriche sono utili anche
/// da un monitor LAN via `https://nfc.local:8443/v1/metrics`.
///
/// Espongono stato interno (sessioni, contatori APDU), quindi l'Origin è il
/// guard che impedisce la lettura drive-by da una pagina web arbitraria. Le
/// richieste senza `Origin` sono ammesse solo da loopback (vedi
/// [`OriginPolicy::is_allowed_read`]): un client LAN anonimo è respinto.
async fn handle_metrics(
    State(ctx): State<Arc<WsContext>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> axum::response::Response {
    if !ctx.read_limiter.allow(addr.ip()) {
        ctx.metrics.rate_limited();
        return (StatusCode::TOO_MANY_REQUESTS, "troppe richieste").into_response();
    }
    let origin = headers.get("origin").and_then(|v| v.to_str().ok());
    if !ctx.origins.is_allowed_read(origin, is_loopback(addr)).await {
        return forbidden("origin non autorizzata");
    }
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        ctx.metrics.render(),
    )
        .into_response()
}

async fn handle_transmit_rest(
    State(ctx): State<Arc<WsContext>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !is_loopback(addr) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"type":"error","code":403,"message":"solo loopback"})),
        );
    }
    let origin = headers.get("origin").and_then(|v| v.to_str().ok());
    if !ctx.origins.is_allowed(origin).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"type":"error","code":403,"message":"origin non autorizzata"})),
        );
    }
    // Consenso esplicito: il canale raggiunge la carta del telefono remoto e la
    // barriera è il token emesso dall'engine, non il loopback (chiunque sulla
    // macchina lo raggiunge).
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if token.is_none_or(|t| !ctx.auth.authenticate(t)) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({"type":"error","code":401,"message":"token richiesto: approva il consenso dall'app desktop"}),
            ),
        );
    }
    let req: nfc_core::protocol::TransmitRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    serde_json::json!({"type":"error","code":422,"message":format!("schema: {e}")}),
                ),
            );
        }
    };
    let apdu = match req.apdu_bytes() {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"type":"error","code":422,"message":e.to_string()})),
            );
        }
    };
    let rid = if req.request_id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        req.request_id
    };
    match forward_to_mobile(&ctx, rid.clone(), apdu, req.timeout_ms, None).await {
        Ok(r) => {
            let rep = TransmitReply {
                kind: "apdu_reply".into(),
                request_id: rid,
                data_hex: hex::encode(&r.data),
                sw1: r.sw1,
                sw2: r.sw2,
                latency_ms: r.latency_ms,
            };
            (StatusCode::OK, Json(serde_json::to_value(&rep).unwrap()))
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(
                serde_json::json!({"type":"error","code":502,"message":e.to_string(),"request_id":rid}),
            ),
        ),
    }
}

// ---------------------------------------------------------------------------
// Upgrade WS
// ---------------------------------------------------------------------------

/// Upgrade WS mobile: raggiungibile dalla **LAN via 8443/TLS**, non dal canale
/// in chiaro.
///
/// Questo handler è montato su entrambi i listener, ma `serve_tls` è l'unico
/// esposto su tutte le interfacce: 8080 è loopback-only, quindi qui la
/// raggiungibilità di rete è garantita solo dal percorso TLS, che il telefono
/// usa con il pin del certificato letto dal QR.
///
/// La protezione non è il transport TCP: è l'handshake E2EE
/// X25519 + ML-KEM-768 / AES-256-GCM, che autentica il peer contro il
/// materiale del QR (binding anti-MITM sulla SAS).
async fn handle_mobile_upgrade(
    State(ctx): State<Arc<WsContext>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    // Rate-limit per IP (tentativi nel tempo) prima del cap di concorrenza
    // (tentativi in parallelo): insieme frenano il brute-force dell'handshake.
    if !ctx.handshake_limiter.allow(addr.ip()) {
        ctx.metrics.rate_limited();
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "troppi tentativi di pairing, riprova più tardi",
        )
            .into_response();
    }
    // Cap sulle negoziazioni concorrenti: il permesso è rilasciato appena
    // l'handshake termina (ok o errore), quindi limita DoS/brute-force
    // sull'handshake senza toccare le sessioni già stabilite.
    let Ok(permit) = Arc::clone(&ctx.handshake_gate).try_acquire_owned() else {
        ctx.metrics.handshake_rejected();
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "troppe negoziazioni di pairing in corso, riprova",
        )
            .into_response();
    };
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle_mobile(ctx, socket, permit).await {
            warn!("mobile handler: {e:#}");
        }
    })
}

async fn handle_extension_upgrade(
    State(ctx): State<Arc<WsContext>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    if !is_loopback(addr) {
        return (StatusCode::FORBIDDEN, "solo loopback").into_response();
    }
    let origin = headers.get("origin").and_then(|v| v.to_str().ok());
    if !ctx.origins.is_allowed(origin).await {
        return (StatusCode::FORBIDDEN, "origin non autorizzata").into_response();
    }
    // L'origin alimenta l'etichetta della richiesta di consenso: va resa
    // **proprietaria prima** della closure `move`, che deve essere 'static.
    let origin_label = origin.map(str::to_owned);
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle_extension(ctx, socket, origin_label).await {
            warn!("extension handler: {e:#}");
        }
    })
}

// ---------------------------------------------------------------------------
// /v1/mobile — sessione E2EE (classica o ibrida PQ)
// ---------------------------------------------------------------------------

/// Chiavi e SAS risultanti da un handshake verificato.
struct MobileSession {
    rx_keys: SessionKeys,
    tx_keys: SessionKeys,
    sas: String,
}

/// Esegue e verifica l'handshake E2EE: nonce QR (TTL 5min, single-use),
/// DH X25519 (+ decapsulamento ML-KEM se negoziato), binding pubkey via SAS.
/// Brucia il nonce solo a handshake riuscito (i retry restano possibili).
///
/// # Errors
/// Qualsiasi `anyhow` su timeout, framing, nonce, PQ o cifratura.
/// Chiude il canale con un **codice stabile** e restituisce l'errore da loggare.
///
/// Deve essere l'unico modo di rifiutare un handshake. Prima ogni rifiuto era
/// una chiusura muta: il telefono vedeva soltanto `Close` e il suo testo di
/// default — "molto probabilmente il QR è già stato usato" — presentava
/// un'ipotesi come diagnosi. Ora il motivo attraversa il canale e viene tradotto
/// lato client, dove è classificabile e locale.
///
/// Il `motivo` resta italiano ed è il dettaglio tecnico: il testo che vede
/// l'utente deriva dal codice, non da qui.
async fn rifiuta(ws: &mut WebSocket, code: u16, motivo: impl Into<String>) -> anyhow::Error {
    let motivo = motivo.into();
    let frame = axum::extract::ws::CloseFrame {
        code,
        reason: motivo.clone().into(),
    };
    // Il Close può non arrivare (peer già andato via): non è il motivo per cui
    // il rifiuto fallisce, quindi non è un errore da propagare.
    let _ = ws.send(WsMsg::Close(Some(frame))).await;
    anyhow::anyhow!(motivo)
}

/// Legge e valida il primo frame dell'handshake, prima che esista una sessione.
///
/// Estratta da [`negotiate_mobile_session`]: con i codici di rifiuto ogni
/// fallimento richiede un `Close`, e la funzione superava il limite di righe.
/// Sintomo che stava facendo due cose — validare il QR, negoziare le chiavi —
/// che ora sono due funzioni con una responsabilità ciascuna.
///
/// Restituisce l'init e il nonce del QR, già confrontato con quello dell'init:
/// sono lo stesso valore, ma il confronto va fatto qui perché è il punto in cui
/// l'init smette di essere un messaggio qualsiasi e diventa *questo* QR.
async fn ricevi_handshake_init(
    ctx: &Arc<WsContext>,
    ws: &mut WebSocket,
) -> anyhow::Result<(proto::HandshakeInit, [u8; 32])> {
    let init_bytes = next_binary(ws).await?;
    let enc = protocol::decode_encrypted(&init_bytes)?;
    if enc.seq != 0 {
        return Err(rifiuta(
            ws,
            close::HANDSHAKE_MALFORMATO,
            "handshake: seq iniziale deve essere 0",
        )
        .await);
    }
    let plain = proto::PlainFrame::decode(&*enc.ciphertext)?;
    let Some(init) = plain.kind else {
        return Err(rifiuta(ws, close::HANDSHAKE_MALFORMATO, "handshake vuoto").await);
    };
    let proto::plain_frame::Kind::HandshakeInit(h) = init else {
        return Err(rifiuta(ws, close::HANDSHAKE_MALFORMATO, "atteso handshake_init").await);
    };
    if h.eph_pubkey.len() != 32 || h.nonce32.len() != 32 {
        return Err(rifiuta(
            ws,
            close::HANDSHAKE_MALFORMATO,
            "handshake: lunghezze errate",
        )
        .await);
    }
    // Controllo del materiale chiavi **prima** di consumare il QR: un client
    // legacy non deve bruciare la single-use flag, così resta rigenerabile.
    if h.keys_v != KEYS_V {
        return Err(rifiuta(
            ws,
            close::CHIAVI_LEGACY,
            "client con materiale chiavi pre-separazione (aggiorna l'app)",
        )
        .await);
    }
    let expected = {
        let m = ctx.handshake_material.read().await;
        if m.used {
            return Err(rifiuta(
                ws,
                close::QR_USATO,
                "QR già usato (rigenera il QR per una nuova sessione)",
            )
            .await);
        }
        if m.issued_at.elapsed() > QR_TTL {
            return Err(rifiuta(
                ws,
                close::QR_SCADUTO,
                "QR scaduto (validità 5 minuti, rigeneralo)",
            )
            .await);
        }
        m.nonce32
    };
    if h.nonce32.as_slice() != expected {
        return Err(rifiuta(
            ws,
            close::QR_NON_CORRISPONDE,
            "nonce QR non corrispondente (ri-scansiona il QR)",
        )
        .await);
    }
    Ok((h, expected))
}

async fn negotiate_mobile_session(
    ctx: &Arc<WsContext>,
    ws: &mut WebSocket,
) -> anyhow::Result<MobileSession> {
    info!("mobile connesso, in attesa handshake (15s)");
    let (h, expected) = ricevi_handshake_init(ctx, ws).await?;
    // DH X25519 (base) + eventuale ML-KEM-768 (ibrido PQ 2026, negoziato).
    let mobile_pk: [u8; 32] = h.eph_pubkey.clone().try_into().unwrap();
    let desktop_pub: [u8; 32];
    let x_shared: [u8; 32];
    {
        let kp = ctx.desktop_kp.read().await;
        desktop_pub = kp.public_bytes();
        x_shared = kp.diffie_hellman(&mobile_pk);
    }
    let (rx_keys, tx_keys, proto_v) = if h.mlkem_ct.is_empty() {
        // Il desktop trasmette sulla direzione desktop->mobile: la stessa
        // `Direction` su entrambe le istanze, perché `seal` usa `tx` e `open`
        // usa `rx`, e sono chiavi diverse.
        let r = SessionKeys::derive(&x_shared, &expected, Direction::DesktopToMobile)?;
        let t = SessionKeys::derive(&x_shared, &expected, Direction::DesktopToMobile)?;
        (r, t, 1u32)
    } else {
        #[cfg(feature = "pq")]
        {
            let g = ctx.pq_kp.read().await;
            let Some(pq) = g.as_ref() else {
                return Err(rifiuta(
                    ws,
                    close::QR_USATO,
                    "PQ richiesto ma chiavi ruotate (ri-scansiona QR)",
                )
                .await);
            };
            let m_shared = pq.decapsulate(&h.mlkem_ct)?;
            let r = SessionKeys::derive_hybrid(
                &x_shared,
                &m_shared,
                &expected,
                Direction::DesktopToMobile,
            )?;
            let t = SessionKeys::derive_hybrid(
                &x_shared,
                &m_shared,
                &expected,
                Direction::DesktopToMobile,
            )?;
            (r, t, 2u32)
        }
        #[cfg(not(feature = "pq"))]
        {
            return Err(rifiuta(
                ws,
                close::BUILD_SENZA_PQ,
                "client PQ ma build senza `pq` (ricompila con --features pq)",
            )
            .await);
        }
    };

    // SAS visiva anti-MITM: loggata + pubblicata via evento per le UI.
    let sas = sas_confirm(&desktop_pub, &mobile_pk, &expected);
    info!(%sas, proto_v, "handshake E2EE completato (verificare SAS su entrambi gli schermi)");

    let mut tx_keys = tx_keys;
    let resp_plain = proto::PlainFrame {
        kind: Some(proto::plain_frame::Kind::HandshakeResp(
            proto::HandshakeResp {
                eph_pubkey: desktop_pub.to_vec(),
                proto_v,
            },
        )),
    };
    let (seq, nonce12, ct) = tx_keys.seal(&resp_plain.encode_to_vec())?;
    let enc_resp = proto::EncryptedFrame {
        seq,
        nonce12: nonce12.to_vec(),
        ciphertext: ct,
    };
    ws.send(WsMsg::Binary(enc_resp.encode_to_vec().into()))
        .await?;
    // Brucia il nonce: il QR è single-use (riuscito -> nuova sessione = nuovo QR).
    ctx.handshake_material.write().await.used = true;
    Ok(MobileSession {
        rx_keys,
        tx_keys,
        sas,
    })
}

async fn handle_mobile(
    ctx: Arc<WsContext>,
    mut ws: WebSocket,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    // Il permesso copre solo la negoziazione: rilasciato subito dopo (successo
    // o errore) così le sessioni attive non consumano slot del cap.
    let negotiated = negotiate_mobile_session(&ctx, &mut ws).await;
    drop(permit);
    let MobileSession {
        mut rx_keys,
        mut tx_keys,
        sas,
    } = negotiated?;
    ctx.bus.publish(EngineEvent::MobileConnected(sas));
    ctx.metrics.ws_open(true);

    // Genera session_id univoco per questa connessione mobile.
    let session_id = Uuid::new_v4().to_string();
    // L'heartbeat usa il session_id (non l'etichetta fissa "mobile"): è la
    // chiave con cui lo sweep al timeout rimuove la sessione dall'hub.
    ctx.heartbeat.mark_alive(&session_id).await;
    // Per ora usiamo un reader_name generico; in futuro il mobile può inviare
    // il tipo di reader (vpcd, pcsc, ecc.) in un messaggio post-handshake.
    let reader_name = "mobile".to_string();

    // Registra hub: da qui i job extension vengono recapitati davvero.
    let (job_tx, mut job_rx) = mpsc::channel::<MobileJob>(16);
    ctx.hub
        .register(session_id.clone(), reader_name.clone(), job_tx)
        .await;

    let mut interval = tokio::time::interval(ctx.policy.heartbeat_interval);
    let mut pending: HashMap<String, tokio::sync::oneshot::Sender<ApduResult>> = HashMap::new();

    let res: anyhow::Result<()> = async {
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let ping = proto::PlainFrame {
                        kind: Some(proto::plain_frame::Kind::Ping(proto::Ping { seq: 0, t_ms: now_ms() })),
                    };
                    if let Ok((seq, n, ct)) = tx_keys.seal(&ping.encode_to_vec()) {
                        let f = proto::EncryptedFrame { seq, nonce12: n.to_vec(), ciphertext: ct };
                        if ws.send(WsMsg::Binary(f.encode_to_vec().into())).await.is_err() { break; }
                    }
                }
                // Job APDU da extension/REST -> mobile (cifrato).
                job = job_rx.recv() => {
                    let Some(job) = job else { break };
                    let MobileJob { request_id, apdu, timeout_ms, reply_tx, target_reader: _ } = job;
                    pending.insert(request_id.clone(), reply_tx);
                    let req = proto::PlainFrame {
                        kind: Some(proto::plain_frame::Kind::ApduRequest(proto::ApduRequest {
                            request_id,
                            apdu,
                            timeout_ms: u32::try_from(timeout_ms).unwrap_or(8000).clamp(1000, 30000),
                        })),
                    };
                    // Nota: request_id è già la chiave inserita; ricostruiamo senza clone extra.
                    let (seq, n, ct) = tx_keys.seal(&req.encode_to_vec())?;
                    let f = proto::EncryptedFrame { seq, nonce12: n.to_vec(), ciphertext: ct };
                    if ws.send(WsMsg::Binary(f.encode_to_vec().into())).await.is_err() { break; }
                }
                msg = ws.recv() => {
                    let Some(msg) = msg else { break };
                    let msg = msg?;
                    match msg {
                        WsMsg::Binary(b) => {
                            handle_mobile_binary(&ctx, &session_id, &mut rx_keys, &mut pending, &b).await;
                        }
                        WsMsg::Close(_) => break,
                        WsMsg::Ping(p) => { let _ = ws.send(WsMsg::Pong(p)).await; }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
    .await;

    ctx.hub.unregister(&session_id).await;
    // Fail-fast: i pending in attesa ricevono errore invece di hang.
    for (_, tx) in pending.drain() {
        let _ = tx.send(ApduResult {
            data: vec![],
            sw1: 0x6F,
            sw2: 0x00,
            latency_ms: 0,
        });
    }
    ctx.bus
        .publish(EngineEvent::MobileDisconnected("chiusura".into()));
    res
}

/// Elabora un frame binario mobile: decrypt, anti-replay e dispatch
/// (risposta APDU verso il pending, eventi carta verso il bus).
/// Frame malformati o non autentici scartati senza chiudere la sessione.
async fn handle_mobile_binary(
    ctx: &Arc<WsContext>,
    session_id: &str,
    rx_keys: &mut SessionKeys,
    pending: &mut HashMap<String, tokio::sync::oneshot::Sender<ApduResult>>,
    b: &[u8],
) {
    if b.len() > ctx.policy.max_frame_bytes {
        warn!("frame troppo grande, scartato");
        return;
    }
    let enc = match protocol::decode_encrypted(b) {
        Ok(e) => e,
        Err(e) => {
            warn!("frame non valido: {e}");
            return;
        }
    };
    let mut n12 = [0u8; 12];
    if enc.nonce12.len() != 12 {
        return;
    }
    n12.copy_from_slice(&enc.nonce12);
    let pt = match rx_keys.open(enc.seq, &n12, &enc.ciphertext) {
        Ok(p) => p,
        Err(e) => {
            warn!("decrypt/replay: {e}");
            return;
        }
    };
    // Frame valido e autentico: il peer è vivo.
    ctx.heartbeat.mark_alive(session_id).await;
    let Ok(plain) = protocol::decode_plain(&pt) else {
        return;
    };
    match plain.kind {
        Some(proto::plain_frame::Kind::ApduResponse(r)) => {
            if let Some(tx) = pending.remove(&r.request_id) {
                // SW ISO7816 fuori 0..255 = peer corrotto, scarta.
                let (Ok(sw1), Ok(sw2)) = (u8::try_from(r.sw1), u8::try_from(r.sw2)) else {
                    warn!("sw fuori range, frame scartato");
                    return;
                };
                let _ = tx.send(ApduResult {
                    data: r.data,
                    sw1,
                    sw2,
                    latency_ms: r.latency_ms,
                });
            }
            ctx.bus
                .publish(EngineEvent::Card(CardStatus::Reading, None));
        }
        Some(proto::plain_frame::Kind::CardEvent(e)) => {
            let status = match e.kind {
                x if x == proto::card_event::Kind::Inserted as i32 => CardStatus::Inserted,
                x if x == proto::card_event::Kind::Removed as i32 => CardStatus::Removed,
                _ => CardStatus::Reading,
            };
            let atr = if e.atr_hex.is_empty() {
                None
            } else {
                Some(e.atr_hex)
            };
            ctx.bus.publish(EngineEvent::Card(status, atr));
        }
        // Pong e altri: heartbeat già aggiornato sopra.
        _ => {}
    }
}

async fn next_binary(ws: &mut WebSocket) -> anyhow::Result<Vec<u8>> {
    use tokio::time::{Duration, timeout};
    let msg = timeout(Duration::from_secs(15), ws.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timeout handshake"))?
        .ok_or_else(|| anyhow::anyhow!("connessione chiusa"))??;
    match msg {
        WsMsg::Binary(b) => Ok(b.to_vec()),
        _ => anyhow::bail!("atteso frame binario"),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

// ---------------------------------------------------------------------------
// /v1/extension — JSON per estensione e webapp
// ---------------------------------------------------------------------------

/// Fase di autenticazione del canale locale. Ritorna `true` se il client è
/// autorizzato (token valido) e può proseguire; `false` se il flusso si è
/// esaurito (rifiuto, consenso avviato, frame invalido, socket chiuso).
async fn extension_authenticate(
    ctx: &Arc<WsContext>,
    ws: &mut WebSocket,
    origin: Option<String>,
) -> anyhow::Result<bool> {
    let Some(first) = ws.recv().await else {
        return Ok(false);
    };
    let first = first?;
    if let WsMsg::Text(t) = first {
        let v: serde_json::Value = serde_json::from_str(&t).unwrap_or(serde_json::Value::Null);
        match v.get("type").and_then(|x| x.as_str()) {
            Some("hello") => match v.get("token").and_then(|x| x.as_str()) {
                Some(token) if ctx.auth.authenticate(token) => return Ok(true),
                Some(_) => {
                    // Token presente ma non valido: revocato o mai emesso.
                    // Niente downgrade al flusso di consenso: chi sta riusando
                    // un token vecchio deve ricorrere all'approvazione esplicita.
                    local_unauthorized(ws, "token non valido").await?;
                }
                None => {
                    // Client senza token (es. estensione mai approvata):
                    // avvia il consenso esplicito.
                    run_consent(ctx, ws, origin).await?;
                }
            },
            Some("enroll") => {
                run_consent(ctx, ws, origin).await?;
            }
            _ => {
                local_unauthorized(ws, "primo frame non valido").await?;
            }
        }
    } else {
        local_unauthorized(ws, "primo frame non testuale").await?;
    }
    Ok(false)
}

async fn handle_extension(
    ctx: Arc<WsContext>,
    mut ws: WebSocket,
    origin: Option<String>,
) -> anyhow::Result<()> {
    // Fase di autenticazione: il canale è raggiungibile da qualsiasi processo
    // locale (loopback), quindi il primo frame deve portare un token autorizzato
    // dall'utente, oppure deve avviare il flusso di consenso. Niente token =
    // niente hello, niente transmit.
    if !extension_authenticate(&ctx, &mut ws, origin).await? {
        return Ok(());
    }

    info!("extension/webapp autenticata");
    ctx.metrics.ws_open(false);
    let mut rx = ctx.bus.subscribe();
    let hello =
        serde_json::json!({"type":"hello","engine":"nfc-desktop/0.3.0","crypto":"hybrid-ready"})
            .to_string();
    ws.send(WsMsg::Text(hello.into())).await?;

    loop {
        tokio::select! {
            ev = rx.recv() => {
                let Ok(ev) = ev else { break };
                if let Some(ext) = ev.to_ext_event() {
                    let txt = serde_json::to_string(&ext)?;
                    if ws.send(WsMsg::Text(txt.into())).await.is_err() { break; }
                }
            }
            msg = ws.recv() => {
                let Some(msg) = msg else { break };
                let msg = msg?;
                match msg {
                    WsMsg::Text(t) => {
                        let v: serde_json::Value = if let Ok(v) = serde_json::from_str(&t) { v } else {
                            let e = serde_json::json!({"type":"error","code":400,"message":"json non valido"}).to_string();
                            ws.send(WsMsg::Text(e.into())).await?;
                            continue;
                        };
                        match v.get("type").and_then(|x| x.as_str()) {
                            Some("transmit_apdu") => {
                                let req: nfc_core::protocol::TransmitRequest = match serde_json::from_value(v) {
                                    Ok(r) => r, Err(e) => {
                                        let err = serde_json::json!({"type":"error","code":422,"message":format!("schema: {e}")}).to_string();
                                        ws.send(WsMsg::Text(err.into())).await?;
                                        continue;
                                    }
                                };
                                let apdu = match req.apdu_bytes() {
                                    Ok(b) => b, Err(e) => {
                                        let err = serde_json::json!({"type":"error","code":422,"message":e.to_string()}).to_string();
                                        ws.send(WsMsg::Text(err.into())).await?;
                                        continue;
                                    }
                                };
                                let rid = if req.request_id.is_empty() { Uuid::new_v4().to_string() } else { req.request_id.clone() };
                                let reply = forward_to_mobile(&ctx, rid.clone(), apdu, req.timeout_ms, None).await;
                                let out = match reply {
                                    Ok(r) => {
                                        let rep = TransmitReply {
                                            kind: "apdu_reply".into(),
                                            request_id: rid,
                                            data_hex: hex::encode(&r.data),
                                            sw1: r.sw1, sw2: r.sw2,
                                            latency_ms: r.latency_ms,
                                        };
                                        serde_json::to_string(&rep)?
                                    }
                                    Err(e) => serde_json::json!({"type":"error","code":502,"message":e.to_string(),"request_id":rid}).to_string(),
                                };
                                ws.send(WsMsg::Text(out.into())).await?;
                            }
                            Some("ping") => {
                                ws.send(WsMsg::Text(r#"{"type":"pong"}"#.to_string().into())).await?;
                            }
                            _ => {
                                let e = serde_json::json!({"type":"error","code":400,"message":"type sconosciuto"}).to_string();
                                ws.send(WsMsg::Text(e.into())).await?;
                            }
                        }
                    }
                    WsMsg::Close(_) => break,
                    WsMsg::Ping(p) => { let _ = ws.send(WsMsg::Pong(p)).await; }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Rifiuta un client locale non autorizzato: errore JSON + Close con codice
/// stabile [`close::LOCAL_NON_AUTENTICATO`].
async fn local_unauthorized(ws: &mut WebSocket, motivo: &str) -> anyhow::Result<()> {
    let e = serde_json::json!({
        "type":"error","code":401,
        "message": format!("non autorizzato: {motivo} (approva il consenso dall'app desktop)")
    })
    .to_string();
    let _ = ws.send(WsMsg::Text(e.into())).await;
    let _ = ws
        .send(WsMsg::Close(Some(CloseFrame {
            code: close::LOCAL_NON_AUTENTICATO,
            reason: motivo.into(),
        })))
        .await;
    Ok(())
}

/// Flusso di consenso: notifica la UI desktop, resta in attesa sul socket fino
/// a `CONSENT_TTL` e consegna il token (o il rifiuto) appena l'utente decide.
async fn run_consent(
    ctx: &Arc<WsContext>,
    ws: &mut WebSocket,
    origin: Option<String>,
) -> anyhow::Result<()> {
    let label = origin.unwrap_or_else(|| "client locale".to_string());
    let (id, mut rx) = ctx.auth.request_consent(label.clone());
    info!(id = %id, label = %label, "consenso richiesto: approva dalla tray desktop");
    ctx.bus.publish(EngineEvent::ConsentRequested {
        id: id.clone(),
        label,
    });
    let pending = serde_json::json!({
        "type":"consent_status","status":"pending","id":id
    })
    .to_string();
    ws.send(WsMsg::Text(pending.into())).await?;

    let outcome = tokio::time::timeout(crate::local_auth::CONSENT_TTL, rx.recv()).await;
    match outcome {
        Ok(Some(crate::local_auth::ConsentOutcome::Approved { token })) => {
            info!(id = %id, "consenso approvato: token consegnato");
            ctx.bus.publish(EngineEvent::ConsentResolved {
                id: id.clone(),
                ok: true,
            });
            let ok = serde_json::json!({
                "type":"consent_status","status":"approved","token":token
            })
            .to_string();
            let _ = ws.send(WsMsg::Text(ok.into())).await;
            let _ = ws
                .send(WsMsg::Close(Some(CloseFrame {
                    code: 1000,
                    reason: "autorizzato".into(),
                })))
                .await;
        }
        Ok(Some(crate::local_auth::ConsentOutcome::Rejected)) => {
            info!(id = %id, "consenso rifiutato");
            ctx.bus.publish(EngineEvent::ConsentResolved {
                id: id.clone(),
                ok: false,
            });
            let no = serde_json::json!({
                "type":"consent_status","status":"rejected"
            })
            .to_string();
            let _ = ws.send(WsMsg::Text(no.into())).await;
            let _ = ws
                .send(WsMsg::Close(Some(CloseFrame {
                    code: 1000,
                    reason: "rifiutato".into(),
                })))
                .await;
        }
        _ => {
            // Timeout o socket morto: il consenso scade da solo.
            ctx.auth.expire(&id);
            ctx.bus
                .publish(EngineEvent::ConsentResolved { id, ok: false });
        }
    }
    Ok(())
}

/// Inoltro APDU verso sessione mobile attiva (hub, fail-fast se offline).
async fn forward_to_mobile(
    ctx: &Arc<WsContext>,
    request_id: String,
    apdu: Vec<u8>,
    timeout_ms: u64,
    target_reader: Option<String>,
) -> anyhow::Result<ApduResult> {
    use crate::metrics::ApduOutcome;
    if !ctx.hub.is_online().await {
        ctx.metrics.record_apdu(ApduOutcome::Offline);
        return Err(anyhow::anyhow!("nessun lettore mobile connesso"));
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    let job = MobileJob {
        request_id,
        apdu,
        timeout_ms,
        reply_tx: tx,
        target_reader,
    };
    if ctx.hub.send(job).await.is_err() {
        ctx.metrics.record_apdu(ApduOutcome::Offline);
        return Err(anyhow::anyhow!("nessun lettore mobile connesso"));
    }
    let to = std::time::Duration::from_millis(timeout_ms.clamp(1000, 30000));
    match tokio::time::timeout(to, rx).await {
        Err(_) => {
            ctx.metrics.record_apdu(ApduOutcome::Timeout);
            Err(anyhow::anyhow!("timeout APDU verso mobile"))
        }
        Ok(Err(_)) => {
            ctx.metrics.record_apdu(ApduOutcome::Error);
            Err(anyhow::anyhow!("mobile disconnesso durante transmit"))
        }
        Ok(Ok(r)) => {
            ctx.metrics.record_apdu(ApduOutcome::Ok(r.latency_ms));
            Ok(r)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{WEB_CSP, content_type_for};

    /// La webapp 2026 è WASM-first: senza `application/wasm` il browser
    /// rifiuta `instantiateStreaming` con un MIME mismatch e il modulo core
    /// non si carica mai. È una riga fragile quanto facile da perdere.
    #[test]
    fn wasm_ha_il_mime_giusto() {
        assert_eq!(
            content_type_for("assets/nfc_core_wasm_bg.wasm"),
            "application/wasm"
        );
        assert_eq!(
            content_type_for("assets/index-abc123.js"),
            "text/javascript; charset=utf-8"
        );
    }

    /// Senza `'wasm-unsafe-eval'` Chromium blocca `WebAssembly.instantiate`
    /// sotto `script-src 'self'`: la webapp WASM morirebbe solo in produzione,
    /// mai nel dev server locale. Il controllo nega anche l'`eval` generico.
    #[test]
    fn csp_ammette_il_wasm_e_solo_il_wasm() {
        assert!(
            WEB_CSP.contains("'wasm-unsafe-eval'"),
            "CSP senza wasm-unsafe-eval: {WEB_CSP}"
        );
        assert!(
            !WEB_CSP.contains("'unsafe-eval'"),
            "CSP con eval generico: {WEB_CSP}"
        );
    }

    /// L'IP LAN dell'engine (quello con cui il telefono apre la webapp) deve
    /// essere consentito nel canale locale `https://<ip>:8443`: è il caso
    /// mobile-browser, altrimenti 403 prima del consenso. Il test gira anche
    /// senza rete fisica: `lan_ipv4()` ripiega sull'IP della rotta di default.
    #[test]
    fn lan_engine_origin_e_automaticamente_consentita() {
        let rt = tokio::runtime::Runtime::new().expect("runtime per test");
        let policy = super::OriginPolicy::default();
        rt.block_on(policy.allow_lan_engine_origin());
        let Some(ip) = nfc_core::net::lan_ipv4() else {
            eprintln!("nessuna IP di rete: test senza significato");
            return;
        };
        let origin = format!("https://{ip}:{}", nfc_core::local_domain::TLS_PORT);
        assert!(
            rt.block_on(policy.is_allowed(Some(&origin))),
            "{origin} deve essere consentita alla WS /v1/extension"
        );
    }

    /// Rate-limiter a finestra fissa: entro il cap consente, oltre risponde
    /// `false`; IP diversi hanno bucket indipendenti.
    #[test]
    fn rate_limiter_finestra_fissa() {
        use super::RateLimiter;
        use std::net::{IpAddr, Ipv4Addr};

        let limiter = RateLimiter::new(std::time::Duration::from_secs(60), 3);
        let a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));
        assert!(limiter.allow(a));
        assert!(limiter.allow(a));
        assert!(limiter.allow(a));
        assert!(!limiter.allow(a), "oltre il cap → respinto");
        assert!(limiter.allow(b), "IP diverso: bucket indipendente");
    }
}
