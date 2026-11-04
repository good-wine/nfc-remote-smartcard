//! Engine desktop Tauri 2 (2026): Tokio multi-task con tray, IPC e updater.
//! Task supervisionati: `vpcd` TCP 35963 con backoff e jitter; HTTPS/WSS
//! `nfc.local:8443` in rustls sullo stesso Router del chiaro 8080; advertise
//! mDNS con hostname `nfc` e TXT per reconnect senza QR e risoluzione mobile;
//! sweep heartbeat ogni 5s con tolleranza Wi-Fi che libera l'hub al timeout;
//! registry `MobileHub` per il recapito reale APDU; ponte bus verso UI tray
//! con SAS post-handshake e log eventi.

use std::{sync::Arc, time::Duration};
use tauri::{Manager, tray::TrayIconBuilder};
use tokio::sync::{RwLock, mpsc};
use tracing::{error, info, warn};

mod events;
mod heartbeat;
pub mod local_auth;
pub mod local_tls;
mod metrics;
#[cfg(feature = "physical")]
mod pcsc_reader;
// Pubblico: i test d'integrazione generano il QR di pairing senza Tauri.
pub mod qr;
pub mod vpcd;
pub mod vpcd_stub;
mod webrtc_fallback;
pub mod ws_server;

use events::{EngineEvent, EventBus};
use nfc_core::{crypto::X25519Keypair, transport::TransportPolicy};
use tauri_plugin_notification::NotificationExt;
use ws_server::{HandshakeMaterial, MobileHub, MobileJob, OriginPolicy, WsContext};

/// Stato globale condiviso con i command Tauri IPC.
pub struct AppState {
    pub bus: Arc<EventBus>,
    pub ws_ctx: Arc<WsContext>,
    pub qr_text: RwLock<String>,
    pub qr_png: RwLock<String>,
    pub qr_sas: RwLock<String>,
    pub vpcd_up: RwLock<bool>,
    /// Handle del lockfile engine (flock esclusivo).
    /// Tenuto vivo per tutta la durata dell'engine; drop = rilascio lock.
    pub engine_lock_handle: std::fs::File,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("vpcd_up", &"<async>")
            .finish()
    }
}

impl AppState {
    /// Rigenera `QRv2`: nuovo nonce + X25519 + ML-KEM-768 (ibrido PQ 2026).
    /// Invalida sessioni precedenti (nuove chiavi desktop + nuovo nonce).
    ///
    /// Delega a `qr::regenerate_into`: la stessa rotazione è usata dalla
    /// webapp via `POST /v1/qr`, così tray e web non possono divergere
    /// (in particolare la coppia ML-KEM, senza la quale l'handshake ibrido
    /// non riuscirebbe a decapsulare).
    async fn regenerate_qr(&self) {
        match qr::regenerate_into(&self.ws_ctx).await {
            Ok(_) => {
                // `regenerate_into` scrive la sola fonte di verità in
                // `ws_ctx.pair_qr`. `AppState` ne è una **proiezione**: va
                // riallineata qui, altrimenti l'IPC `get_qr` (che legge
                // `AppState`, non `pair_qr`) continuerebbe a servire stringhe
                // vuote e la UI desktop mostrerebbe il riquadro QR vuoto,
                // mentre la webapp — che legge `GET /v1/qr` da `pair_qr` —
                // funzionerebbe. Le due copie non devono esistere: la SAS
                // invece resta in `AppState` perché sipopola solo dopo
                // l'handshake.
                let (text, png) = self.ws_ctx.pair_qr.read().await.clone();
                *self.qr_text.write().await = text;
                *self.qr_png.write().await = png;
            }
            Err(e) => warn!("QR build fallita: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Command IPC (WebView tray/config + deep-link nfc://pair)
// ---------------------------------------------------------------------------

#[tauri::command]
async fn get_qr(state: tauri::State<'_, Arc<AppState>>) -> Result<serde_json::Value, String> {
    // `pair_qr` è l'unica fonte di verità del QR: la rotazione può arrivare dal
    // comando `regenerate_qr` (IPC tray), da `POST /v1/qr` (webapp) o dal
    // deep-link `nfc://pair`, e tutti scrivono direttamente `pair_qr`. Le copie
    // `AppState.{qr_text,qr_png}` vengono riallineate solo dal primo percorso:
    // leggerle qui farebbe vedere alla tray un QR stantio (nonché non valido
    // per l'engine) dopo una rotazione partita da un altro percorso.
    let (qr_text, qr_png) = state.ws_ctx.pair_qr.read().await.clone();
    // Validità residua sullo stesso clock di `handshake_material.issued_at`
    // (che è ciò che `ws_server` verifica all'handshake): la tray la usa per il
    // countdown e per rigenerare da sola alla scadenza, senza pagare un round
    // trip che il QR in mano potrebbe già rendere inutile.
    let expires_in_ms = {
        let m = state.ws_ctx.handshake_material.read().await;
        crate::ws_server::qr_remaining_ms(crate::ws_server::QR_TTL, m.issued_at.elapsed())
    };
    Ok(serde_json::json!({
        "qr_text": qr_text,
        "qr_png": qr_png,
        "sas": state.qr_sas.read().await.clone(),
        "expires_in_ms": expires_in_ms,
    }))
}

#[tauri::command]
async fn regenerate_qr(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    state.regenerate_qr().await;
    get_qr(state).await
}

#[tauri::command]
async fn get_status(state: tauri::State<'_, Arc<AppState>>) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "vpcd_up": *state.vpcd_up.read().await,
        "mobile_online": state.ws_ctx.hub.is_online().await,
        "https": nfc_core::local_domain::https_base(),
        "wss_extension": nfc_core::local_domain::wss_extension(),
        "ws_legacy": nfc_core::local_domain::WS_LEGACY,
        "ws_legacy_scope": nfc_core::local_domain::WS_LEGACY_SCOPE,
        "crypto": "x25519+mlkem768-hybrid-ready",
    }))
}

#[tauri::command]
async fn allow_origin(
    origin: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    state.ws_ctx.origins.allow(origin).await;
    Ok(())
}

#[tauri::command]
async fn list_origins(state: tauri::State<'_, Arc<AppState>>) -> Result<Vec<String>, String> {
    Ok(state.ws_ctx.origins.snapshot().await)
}

#[tauri::command]
async fn notify_card(
    status: String,
    atr_hex: Option<String>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    use nfc_core::protocol::CardStatus;
    let s = match status.as_str() {
        "inserted" => CardStatus::Inserted,
        "removed" => CardStatus::Removed,
        _ => CardStatus::Reading,
    };
    state.bus.publish(EngineEvent::Card(s, atr_hex));
    Ok(())
}

#[tauri::command]
async fn list_consents(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    serde_json::to_value(state.ws_ctx.auth.pending()).map_err(|e| e.to_string())
}

/// Approva la richiesta di consenso: il token viene consegnato al socket in
/// attesa via canale (`run_consent`), qui non serve restituirlo.
#[tauri::command]
async fn approve_consent(id: String, state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    let _token = state.ws_ctx.auth.approve(&id)?;
    Ok(())
}

#[tauri::command]
async fn reject_consent(id: String, state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    state
        .ws_ctx
        .auth
        .reject(&id)
        .then_some(())
        .ok_or_else(|| "consenso non trovato o già risolto".to_string())
}

/// Client autorizzati (per la UI, senza hash dei token).
#[tauri::command]
async fn list_clients(state: tauri::State<'_, Arc<AppState>>) -> Result<serde_json::Value, String> {
    serde_json::to_value(state.ws_ctx.auth.list_clients()).map_err(|e| e.to_string())
}

#[tauri::command]
async fn revoke_client(id: String, state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    state
        .ws_ctx
        .auth
        .revoke(&id)
        .then_some(())
        .ok_or_else(|| "client non trovato".to_string())
}

// ---------------------------------------------------------------------------
// Task supervisionati (estratti da `run` per leggibilità e limite righe)
// ---------------------------------------------------------------------------

/// Deep-link `nfc://pair` da browser/estensione (solo build desktop).
#[cfg(desktop)]
fn register_pair_deeplink(handle: &tauri::AppHandle, state: Arc<AppState>) {
    use tauri_plugin_deep_link::DeepLinkExt;
    let st = state;
    handle.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            if url.scheme() == "nfc" && url.host_str() == Some("pair") {
                info!(%url, "deep-link pair ricevuto");
                let s = st.clone();
                tauri::async_runtime::spawn(async move {
                    s.regenerate_qr().await;
                });
            }
        }
    });
}

#[cfg(not(desktop))]
fn register_pair_deeplink(_handle: &tauri::AppHandle, _state: Arc<AppState>) {}

/// WS/REST Axum 8080 (chiaro, compat) con restart e backoff.
fn spawn_ws_plain(ctx: Arc<WsContext>) {
    tauri::async_runtime::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        loop {
            match ws_server::serve(ctx.clone(), 8080).await {
                Ok(()) => {
                    warn!("ws server terminato senza errore, restart tra 2s");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => {
                    warn!("ws server crashato, restart tra {backoff:?}: {e:#}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    });
}

/// HTTPS/WSS `nfc.local:8443` (primario 2026) con restart e backoff.
fn spawn_ws_tls(ctx: Arc<WsContext>) {
    tauri::async_runtime::spawn(async move {
        let mut backoff = Duration::from_secs(2);
        loop {
            match local_tls::serve_tls(ctx.clone()).await {
                Ok(()) => {
                    warn!("tls server terminato, restart tra 3s (verifica cert/8443)");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
                Err(e) => {
                    warn!("tls server crashato, restart tra {backoff:?}: {e:#}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    });
}

/// Costruisce lo stato gestito da Tauri.
///
/// Fuori da `run()` per due ragioni: `run()` era al limite di lunghezza e la
/// costruzione era il blocco più grosso; e la separazione rende visibile che
/// `pair_qr` è l'unica fonte di verità del QR, con `AppState.{qr_text,qr_png}`
/// come copie per l'IPC desktop.
fn build_state(
    to_mobile_tx: mpsc::Sender<MobileJob>,
    engine_lock_handle: std::fs::File,
) -> Arc<AppState> {
    let bus = Arc::new(EventBus::new(256));
    let origins = Arc::new(OriginPolicy::default());
    let pending = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    let ws_ctx = Arc::new(WsContext {
        policy: TransportPolicy::default(),
        bus: bus.clone(),
        origins,
        to_mobile: to_mobile_tx,
        pending,
        handshake_material: RwLock::new(HandshakeMaterial::fresh([0u8; 32])),
        desktop_kp: RwLock::new(X25519Keypair::generate()),
        mlkem_ek_b64: RwLock::new(None),
        #[cfg(feature = "pq")]
        pq_kp: RwLock::new(None),
        hub: Arc::new(MobileHub::default()),
        heartbeat: Arc::new(heartbeat::Heartbeat::new(
            TransportPolicy::default().dead_after,
        )),
        metrics: Arc::new(metrics::Metrics::default()),
        pair_qr: RwLock::new((String::new(), String::new())),
        auth: local_auth::ClientAuth::load(&nfc_core::local_domain::profile_dir()),
        app_handle: RwLock::new(None),
        handshake_gate: Arc::new(tokio::sync::Semaphore::new(
            ws_server::HANDSHAKE_MAX_CONCURRENT,
        )),
        handshake_limiter: ws_server::RateLimiter::new(
            ws_server::HANDSHAKE_RATE_WINDOW,
            ws_server::HANDSHAKE_RATE_MAX,
        ),
        read_limiter: ws_server::RateLimiter::new(
            ws_server::READ_RATE_WINDOW,
            ws_server::READ_RATE_MAX,
        ),
    });
    Arc::new(AppState {
        bus,
        ws_ctx,
        qr_text: RwLock::new(String::new()),
        qr_png: RwLock::new(String::new()),
        qr_sas: RwLock::new(String::new()),
        vpcd_up: RwLock::new(false),
        engine_lock_handle,
    })
}

/// Prende il lockfile che impedisce a `--rotate-ca` di girare con l'engine vivo.
///
/// Acquisisce un flock esclusivo sul file `engine.lock`. Se un altro engine è
/// già in esecuzione, il lock fallisce e l'engine non si avvia (exit code 1).
///
/// Il lock viene mantenuto vivo per tutta la durata dell'engine tenendo l'handle
/// del file in `AppState.engine_lock_handle`. Viene rilasciato automaticamente
/// all'uscita (drop dell'handle o OS cleanup).
fn take_engine_lock() -> std::fs::File {
    use nfc_core::local_domain;

    match local_domain::try_acquire_engine_lock() {
        Ok(f) => {
            info!(
                "engine lock acquisito: {}",
                local_domain::engine_lock_path().display()
            );
            f
        }
        Err(e) => {
            error!(
                "Impossibile acquisire engine lock: {e}. Un altro engine è già in esecuzione? \
                 Chiudilo prima di avviare una nuova istanza."
            );
            std::process::exit(1);
        }
    }
}

/// Rilascio del lockfile all'uscita dell'engine.
///
/// Il lock viene rilasciato automaticamente droppando l'handle del file.
/// Qui rimuoviamo solo il file per pulizia (idempotente).
fn on_engine_exit() {
    if let Err(e) = nfc_core::local_domain::clear_engine_lock() {
        eprintln!("lockfile d'engine non rimosso (già assente o permessi): {e}");
    }
}

/// Advertise mDNS `nfc` + TXT (reconnect senza QR, `nfc.local` su mobile).
fn spawn_mdns() {
    tauri::async_runtime::spawn(async move {
        let _ = tokio::task::spawn_blocking(|| {
            match nfc_core::mdns::Advertiser::advertise(nfc_core::local_domain::TLS_PORT) {
                Ok(a) => {
                    info!(
                        "mDNS pubblicato: {} · {} annuncia {:?} (i device risolvono nfc.local)",
                        a.fullname(),
                        nfc_core::mdns::MDNS_HOSTNAME,
                        a.addresses(),
                    );
                    std::thread::sleep(Duration::from_hours(8760));
                }
                Err(e) => warn!("mDNS fallito: {e}"),
            }
        })
        .await;
    });
}

/// Sweep heartbeat: dichiara offline i mobile silenziosi oltre `dead_after`.
fn spawn_heartbeat(st: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            for id in st.ws_ctx.heartbeat.sweep().await {
                warn!(peer = %id, "heartbeat scaduto");
                st.ws_ctx.hub.unregister(&id).await;
                st.bus
                    .publish(EngineEvent::MobileDisconnected("heartbeat timeout".into()));
            }
        }
    });
}

/// Ponte bus -> UI tray: SAS post-handshake, log eventi carta/reader e
/// richieste di consenso dei client locali (JSON strutturato per la UI).
fn spawn_bus_bridge(st: Arc<AppState>, handle: tauri::AppHandle) {
    use tauri::Emitter;
    tauri::async_runtime::spawn(async move {
        let mut rx = st.bus.subscribe();
        // Rate-limit del beacon di scansione: la webapp può ripetere l'analisi
        // del QR quante volte vuole, la notifica di sistema non deve diventare
        // spam. La prima scansione notifica subito, poi al più una ogni 30s.
        let mut ultimo_scanned = std::time::Instant::now();
        let mut primo_scanned = true;
        while let Ok(ev) = rx.recv().await {
            let msg = match &ev {
                EngineEvent::QrScanned => {
                    if primo_scanned
                        || ultimo_scanned.elapsed() >= std::time::Duration::from_secs(30)
                    {
                        primo_scanned = false;
                        ultimo_scanned = std::time::Instant::now();
                        let _ = handle
                            .notification()
                            .builder()
                            .title("NFC Remote: QR scansionato")
                            .body(
                                "Un telefono ha scansionato il QR di pairing dal browser. \
                                 Completa l'associazione con l'app NFC Remote nativa.",
                            )
                            .show();
                    }
                    let _ = handle.emit_to(
                        "main",
                        "engine-event",
                        serde_json::json!({"kind":"scanned","action":"qr_scanned"}),
                    );
                    continue;
                }
                EngineEvent::MobileConnected(sas) => {
                    *st.qr_sas.write().await = sas.clone();
                    // Associazione mobile: il QR è l'autorizzazione (nessun
                    // Consenti/Rifiuta), ma è proprio il momento in cui va
                    // confrontata la SAS anti-MITM su entrambi gli schermi:
                    // notifica di sistema (visibile anche a finestra chiusa)
                    // + evento strutturato perché il pannello la mostri.
                    let _ = handle
                        .notification()
                        .builder()
                        .title("NFC Remote: telefono associato")
                        .body(format!(
                            "Telefono associato al lettore. Confronta la SAS su entrambi gli schermi: {sas}"
                        ))
                        .show();
                    if let Some(w) = handle.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                    let _ = handle.emit_to(
                        "main",
                        "engine-event",
                        serde_json::json!({"kind":"mobile","action":"connected","sas":sas}),
                    );
                    continue;
                }
                EngineEvent::MobileDisconnected(r) => format!("mobile disconnesso: {r}"),
                EngineEvent::Card(s, atr) => {
                    format!("carta {s:?} {}", atr.as_deref().unwrap_or(""))
                }
                EngineEvent::ReaderConnected(n) => format!("reader connesso: {n}"),
                EngineEvent::ReaderDisconnected(n) => format!("reader perso: {n}"),
                // Consensi: sono eventi **strutturati**, la UI li tratta come
                // richieste con bottoni, non come righe di log.
                EngineEvent::ConsentRequested { id, label } => {
                    // Notifica di sistema (vista anche con finestra chiusa o
                    // su un altro workspace); il click riapre la finestra.
                    let _ = handle
                        .notification()
                        .builder()
                        .title("NFC Remote: consenso richiesto")
                        .body(format!(
                            "{label} chiede di usare il lettore. Apri l'app per approvare o rifiutare."
                        ))
                        .show();
                    // Una richiesta di consenso deve essere **vista**: la
                    // finestra può essere dietro o la card fuori dal bordo
                    // (QR di pairing grande). Porta la finestra in primo
                    // piano; la UI scorre la card alla ricezione dell'evento.
                    if let Some(w) = handle.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                    let _ = handle.emit_to(
                        "main",
                        "engine-event",
                        serde_json::json!({"kind":"consent","action":"requested","id":id,"label":label}),
                    );
                    continue;
                }
                EngineEvent::ConsentResolved { id, ok } => {
                    let _ = handle.emit_to(
                        "main",
                        "engine-event",
                        serde_json::json!({"kind":"consent","action":"resolved","id":id,"ok":ok}),
                    );
                    continue;
                }
            };
            let _ = handle.emit_to("main", "engine-event", msg);
        }
    });
}

/// Keepalive vpcd con backoff e jitter; probe fisico se feature `physical`.
fn spawn_vpcd(st: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        #[cfg(feature = "physical")]
        let mut pcsc_announced = false;
        loop {
            let mut client = vpcd::VpcdClient::new(vpcd::VpcdConfig::default());
            match client.connect().await {
                Ok(()) => {
                    *st.vpcd_up.write().await = true;
                    st.bus
                        .publish(EngineEvent::ReaderConnected("vpcd-0".into()));
                    backoff = Duration::from_secs(1);
                    #[cfg(feature = "physical")]
                    {
                        pcsc_announced = false;
                    }
                    // Liveness: GetStatus periodico; solo errori I/O riaprono il backoff.
                    loop {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        if client.card_present().await.is_err() {
                            *st.vpcd_up.write().await = false;
                            st.bus
                                .publish(EngineEvent::ReaderDisconnected("vpcd-0".into()));
                            break;
                        }
                    }
                }
                Err(e) => {
                    use rand::Rng;
                    *st.vpcd_up.write().await = false;
                    // Fallback fisico (feature `physical`): lettore USB/NFC diretto,
                    // annunciato una volta per ciclo di down.
                    #[cfg(feature = "physical")]
                    if !pcsc_announced && let Some(name) = pcsc_reader::probe().into_iter().next() {
                        st.bus
                            .publish(EngineEvent::ReaderConnected(format!("pcsc-{name}")));
                        pcsc_announced = true;
                    }
                    let jitter: u64 = rand::rng().random_range(0..1000);
                    warn!("vpcd non raggiungibile ({e}), retry tra {backoff:?}+{jitter}ms");
                    tokio::time::sleep(backoff + Duration::from_millis(jitter)).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    });
}

/// Costruisce la tray icon con menu (nascosta in `--daemon`).
fn build_tray(app_handle: &tauri::AppHandle) {
    let _ = TrayIconBuilder::new()
        .tooltip("NFC Smartcard Remote")
        .on_menu_event(|app, event| {
            if event.id.as_ref() == "quit" {
                app.exit(0);
            }
            if event.id.as_ref() == "show"
                && let Some(w) = app.get_webview_window("main")
            {
                let _ = w.show();
            }
        })
        .build(app_handle);
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/// Entry point da `main.rs`. Supporta `--daemon` (headless IT/GPO/MDM).
///
/// # Panics
/// Solo se il runtime Tauri non si avvia (configurazione invalida).
pub fn run() {
    // Provider TLS esplicito: `install_default` elimina ogni ambiguità anche se
    // un futuro crate del workspace riattivasse due provider. Oggi il workspace
    // compila solo aws-lc-rs (feature `ring`/`tls12` rimosse).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("info,nfc_desktop_lib=debug,nfc_core=debug")
        .init();
    let headless = std::env::args().any(|a| a == "--daemon");

    // Canale legacy (compat API): il recapito reale passa per MobileHub.
    // Il receiver è droppato subito: `send` fallisce veloce (nessun mobile).
    let (to_mobile_tx, legacy_rx) = mpsc::channel::<MobileJob>(32);
    drop(legacy_rx);

    // Acquisisci engine lock PRIMA di costruire lo stato — se fallisce, exit(1)
    let engine_lock_handle = take_engine_lock();

    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // 2026: seconda istanza (es. click su nfc://pair) porta in primo piano.
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_notification::init())
        .manage(build_state(to_mobile_tx.clone(), engine_lock_handle))
        .setup(move |app| {
            let state: tauri::State<Arc<AppState>> = app.state();
            let state = state.inner().clone();
            let app_handle = app.handle().clone();

            // Imposta l'AppHandle nel WsContext per risolvere le risorse bundle (web/dist)
            tauri::async_runtime::block_on(async {
                *state.ws_ctx.app_handle.write().await = Some(app_handle.clone());
            });

            register_pair_deeplink(&app_handle, state.clone());

            // La PKI deve esistere **prima** del QR: il pin TLS del certificato
            // foglia è ciò che permette al telefono di parlare `wss://`, e senza
            // pin degraderebbe al canale in chiaro senza alcun errore. Il server
            // TLS gira in un task concorrente e non è un punto di sincronizzazione
            // affidabile per questo.
            if let Err(e) = local_tls::ensure_pki_ready() {
                error!("PKI locale non disponibile: il QR uscirà senza pin TLS ({e:#})");
            }

            tauri::async_runtime::spawn(async move {
                state.regenerate_qr().await;
                for o in [
                    "https://www.interno.gov.it",
                    "https://cie.interno.gov.it",
                    "https://spid.gov.it",
                    "https://eidas.europa.eu",
                ] {
                    state.ws_ctx.origins.allow(o.into()).await;
                }
                // La webapp dal telefono arriva via IP LAN (`https://<ip>:8443`),
                // che l'allowlist statica non copre: senza questa voce la console
                // resta "non autorizzato" senza che il consenso parta mai.
                state.ws_ctx.origins.allow_lan_engine_origin().await;
            });

            let ctx = app.state::<Arc<AppState>>().inner().ws_ctx.clone();
            spawn_ws_plain(ctx.clone());
            spawn_ws_tls(ctx);
            spawn_mdns();
            {
                let h: tauri::State<Arc<AppState>> = app.state();
                let st = h.inner().clone();
                spawn_heartbeat(st.clone());
                spawn_bus_bridge(st.clone(), app_handle.clone());
                spawn_vpcd(st);
            }

            if !headless {
                build_tray(&app_handle);
            }
            info!(
                headless,
                "engine desktop 2026 avviato (axum+pq-hybrid+updater)"
            );
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_qr,
            regenerate_qr,
            get_status,
            allow_origin,
            list_origins,
            notify_card,
            list_consents,
            approve_consent,
            reject_consent,
            list_clients,
            revoke_client
        ])
        .build(tauri::generate_context!())
        .expect("tauri build fallita")
        .run(|_app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                on_engine_exit();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La fonte di verità del QR è `ws_ctx.pair_qr` (usata da `get_qr` IPC e da
    /// `GET /v1/qr`). Le copie `AppState.{qr_text,qr_png}` vengono riallineate
    /// da `regenerate_qr` e devono coincidere con la fonte: se un percorso
    /// divergesse, tray e webapp servirebbero QR diversi (con nonce/chiavi
    /// differenti, l'handshake dell'uno invaliderebbe l'altro).
    #[tokio::test]
    async fn regenerate_qr_proietta_su_appstate() {
        let ws_ctx = WsContext::new_test();
        // Crea un file temporario per il lock handle del test
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let state = Arc::new(AppState {
            bus: Arc::new(EventBus::new(8)),
            qr_text: RwLock::new(String::new()),
            qr_png: RwLock::new(String::new()),
            qr_sas: RwLock::new(String::new()),
            vpcd_up: RwLock::new(false),
            ws_ctx,
            engine_lock_handle: temp_file.into_file(),
        });

        state.regenerate_qr().await;

        let text = state.qr_text.read().await.clone();
        let png = state.qr_png.read().await.clone();
        assert!(
            text.starts_with("NFC://2/"),
            "qr_text vuoto o malformato: {text:?}"
        );
        assert!(
            png.starts_with("data:image/png;base64,"),
            "qr_png non è un data-URL PNG: {:?}",
            &png[..png.len().min(40)]
        );
        // Deve coincidere con la fonte di verità, altrimenti i due percorsi divergono.
        let (ctx_text, ctx_png) = state.ws_ctx.pair_qr.read().await.clone();
        assert_eq!(text, ctx_text);
        assert_eq!(png, ctx_png);
    }

    /// L'aritmetica della validità residua `get_qr` → countdown della tray:
    /// valori sensati nel TTL e clamp a zero oltre la scadenza.
    #[test]
    fn qr_remaining_ms_decrementa_e_clampa_a_zero() {
        use crate::ws_server::qr_remaining_ms;
        use std::time::Duration;

        let ttl = Duration::from_mins(5);
        // Appena emesso: tutto il TTL (entro il millisecondo di costruzione).
        let fresco = qr_remaining_ms(ttl, Duration::ZERO);
        assert!(
            ttl.as_millis().saturating_sub(u128::from(fresco)) < 2,
            "fresco: {fresco}"
        );
        // A metà TTL resta la metà (≈ 150s, tolleranza 1ms).
        let meta = qr_remaining_ms(ttl, Duration::from_secs(150));
        assert!(meta.abs_diff(150_000) <= 1, "metà TTL: {meta}");
        // Oltre la scadenza: 0, mai negativa (l'handler si aspetta u64).
        assert_eq!(qr_remaining_ms(ttl, Duration::from_secs(301)), 0);
        assert_eq!(qr_remaining_ms(ttl, Duration::from_secs(3600)), 0);
    }
}
