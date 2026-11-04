//! Autenticazione del canale locale su un WebSocket reale (`/v1/extension`).
//!
//! `api.rs` copre il REST con `oneshot`; qui il flusso di **consenso** e il
//! rifiuto dei token estranei passano davvero da un socket. I casi:
//! 1. `hello` senza token → consenso pendente, approvazione dall'engine →
//!    token consegnato sul socket e autenticante;
//! 2. `enroll` esplicito → stesso flusso di consenso di 1;
//! 3. `hello` con token valido → hello dell'engine;
//! 4. `hello` con token sconosciuto → errore JSON + close `4406` (e il flusso
//!    non degrada mai al consenso: un token revocato non fa ripartire la
//!    concessione, si riparte da zero come policy).

use std::{sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use nfc_desktop_lib::{
    local_auth::TEST_TOKEN,
    ws_server::{WsContext, router},
};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMsg};

/// Avvia il router su una porta effimera di loopback.
async fn avvia() -> (Arc<WsContext>, String) {
    let ctx = WsContext::new_test();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("indirizzo effimero");
    let app = router(Arc::clone(&ctx));
    tokio::spawn(async move {
        // `into_make_service_with_connect_info` è obbligatoria: i guard di
        // loopback estraggono `ConnectInfo<SocketAddr>`, come in
        // `local_tls::serve_tls`. Con un serve semplice ogni upgrade è 500.
        let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("server di test terminato: {e}");
        }
    });
    (ctx, format!("ws://{addr}/v1/extension"))
}

async fn manda_testo(ws: &mut Ws, testo: &str) {
    ws.send(WsMsg::Text(testo.into())).await.expect("invio");
}

async fn prossimo_json(ws: &mut Ws) -> serde_json::Value {
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timeout: nessun frame")
        .expect("errore di lettura")
        .expect("socket chiuso senza frame");
    match msg {
        WsMsg::Text(t) => serde_json::from_str(&t).expect("frame non JSON"),
        altro => panic!("atteso Text, ottenuto {altro:?}"),
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[tokio::test]
async fn hello_senza_token_consenso_e_token_consegnato() {
    let (ctx, url) = avvia().await;
    let (mut ws, _) = connect_async(url).await.expect("upgrade");
    manda_testo(&mut ws, r#"{"type":"hello"}"#).await;

    // 1. L'engine apre il consenso e lo segnala.
    let pending = prossimo_json(&mut ws).await;
    assert_eq!(pending["type"], "consent_status");
    assert_eq!(pending["status"], "pending");
    let id = pending["id"].as_str().expect("id consenso");
    assert_eq!(ctx.auth.pending().len(), 1);

    // 2. L'utente approva dall'UI desktop (comando → registry).
    let token = ctx.auth.approve(id).expect("token emesso");
    assert_eq!(ctx.auth.pending().len(), 0);
    assert!(ctx.auth.authenticate(&token));

    // 3. Il socket in attesa riceve il token e si chiude.
    let ok = prossimo_json(&mut ws).await;
    assert_eq!(ok["status"], "approved");
    assert_eq!(ok["token"], token);
}

#[tokio::test]
async fn hello_con_token_valido_ecce_happy_path() {
    let (_, url) = avvia().await;
    let (mut ws, _) = connect_async(url).await.expect("upgrade");
    let hello = format!(r#"{{"type":"hello","token":"{TEST_TOKEN}"}}"#);
    manda_testo(&mut ws, &hello).await;

    let risposta = prossimo_json(&mut ws).await;
    assert_eq!(risposta["type"], "hello");
    assert_eq!(risposta["engine"], "nfc-desktop/0.3.0");
}

#[tokio::test]
async fn enroll_esplicito_apre_il_consenso() {
    let (ctx, url) = avvia().await;
    let (mut ws, _) = connect_async(url).await.expect("upgrade");
    manda_testo(&mut ws, r#"{"type":"enroll"}"#).await;

    let pending = prossimo_json(&mut ws).await;
    assert_eq!(pending["type"], "consent_status");
    assert_eq!(pending["status"], "pending");
    let id = pending["id"].as_str().expect("id consenso");
    let token = ctx.auth.approve(id).expect("token emesso");

    let ok = prossimo_json(&mut ws).await;
    assert_eq!(ok["status"], "approved");
    assert_eq!(ok["token"], token);
    assert!(ctx.auth.authenticate(&token));
}

#[tokio::test]
async fn token_sconosciuto_chiude_4406_senza_degradare() {
    let (ctx, url) = avvia().await;
    let (mut ws, _) = connect_async(url).await.expect("upgrade");
    manda_testo(
        &mut ws,
        r#"{"type":"hello","token":"token-mai-emesso-o-revocato"}"#,
    )
    .await;

    // Errore JSON prima della chiusura.
    let err = prossimo_json(&mut ws).await;
    assert_eq!(err["type"], "error");
    assert_eq!(err["code"], 401);

    // Close con codice stabile 4406, e il consenso NON è stato aperto.
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timeout")
        .expect("errore di lettura")
        .expect("socket chiuso");
    match msg {
        WsMsg::Close(Some(cf)) => {
            assert_eq!(
                u16::from(cf.code),
                nfc_core::protocol::close::LOCAL_NON_AUTENTICATO
            );
        }
        altro => panic!("atteso Close, ottenuto {altro:?}"),
    }
    assert_eq!(ctx.auth.pending().len(), 0, "nessun consenso aperto");
}
