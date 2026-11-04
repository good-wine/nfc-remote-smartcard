//! Handshake E2EE su un WebSocket reale.
//!
//! `api.rs` usa `tower::ServiceExt::oneshot`, che non esegue mai l'upgrade: per
//! costruzione non può vedere il negoziato. Quindi il rifiuto dei client
//! legacy, i codici di chiusura e la derivazione delle chiavi per direzione
//! restavano coperti ciascuno da un unit test, **mai insieme** — ognuno poteva
//! essere verde mentre il sistema non funzionava.
//!
//! Qui i due lati parlano davvero su un socket. La verifica finale è che il
//! client decifri la risposta del desktop: se le chiavi fossero ancora uguali
//! nelle due direzioni quel controllo passerebbe comunque (stessa chiave da
//! entrambe le parti), per cui il caso `chiavi_separate` in `nfc-core` dice
//! l'altro versante e i due insieme coprono la proprietà.

use std::{sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt, stream::SplitSink, stream::SplitStream};
use nfc_core::{
    crypto::{Direction, KEYS_V, SessionKeys, X25519Keypair, sas_confirm},
    protocol::{close, proto},
};
use nfc_desktop_lib::ws_server::{WsContext, router};
use prost::Message;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message as WsMsg,
};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;
type Tx = SplitSink<Ws, WsMsg>;
type Rx = SplitStream<Ws>;

/// Avvia il router su una porta effimera di loopback.
///
/// Restituisce anche il contesto: serve a leggere la chiave pubblica del
/// desktop, che l'init deve targettizzare e che nessun endpoint espone.
async fn avvia_engine() -> (Arc<WsContext>, String) {
    let ctx = WsContext::new_test();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("indirizzo effimero");
    let app =
        router(Arc::clone(&ctx)).into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("server di test terminato: {e}");
        }
    });
    (ctx, format!("ws://{addr}/v1/mobile"))
}

/// L'init come lo costruisce il mobile: in chiaro dentro un `EncryptedFrame`
/// di seq 0 (il contenuto non è ancora cifrato, le chiavi non esistono).
fn init_per(eph_pub: &[u8; 32], nonce: &[u8; 32], keys_v: u32) -> proto::HandshakeInit {
    proto::HandshakeInit {
        eph_pubkey: eph_pub.to_vec(),
        nonce32: nonce.to_vec(),
        mlkem_ct: vec![],
        proto_v: 1,
        keys_v,
    }
}

async fn manda_init(tx: &mut Tx, init: &proto::HandshakeInit) {
    let frame = proto::PlainFrame {
        kind: Some(proto::plain_frame::Kind::HandshakeInit(init.clone())),
    };
    let enc = proto::EncryptedFrame {
        seq: 0,
        nonce12: vec![0u8; 12],
        ciphertext: frame.encode_to_vec(),
    };
    tx.send(WsMsg::Binary(enc.encode_to_vec().into()))
        .await
        .expect("invio init");
}

/// Primo frame atteso: un `Close`, del quale vogliamo il **codice**.
async fn attendi_chiusura(rx: &mut Rx) -> u16 {
    let msg = rx
        .next()
        .await
        .expect("il server non ha inviato nulla")
        .expect("errore di lettura sul WS");
    match msg {
        WsMsg::Close(Some(cf)) => u16::from(cf.code),
        WsMsg::Close(None) => panic!("chiusura senza frame: il motivo si perde"),
        altro => panic!("atteso Close, ottenuto {altro:?}"),
    }
}

/// Un init senza `keys_v` è il segnale di un client che non conosce la
/// separazione delle chiavi: va rifiutato, non negoziato.
#[tokio::test]
async fn client_legacy_rifiutato_con_codice() {
    let (_ctx, url) = avvia_engine().await;
    let (ws, _) = connect_async(&url).await.expect("connessione");
    let (mut tx, mut rx) = ws.split();

    let eph = X25519Keypair::generate();
    let nonce = [0u8; 32]; // `WsContext::new_test()` emette questo nonce
    manda_init(&mut tx, &init_per(&eph.public_bytes(), &nonce, 0)).await;

    assert_eq!(
        attendi_chiusura(&mut rx).await,
        close::CHIAVI_LEGACY,
        "l'engine deve rifiutare un client che non dichiara `keys_v`"
    );
}

/// Il nonce è ciò che lega l'init al QR emesso: uno sbagliato non deve
/// raggiungere il DH.
#[tokio::test]
async fn nonce_non_appartenente_al_qr_rifiutato() {
    let (_ctx, url) = avvia_engine().await;
    let (ws, _) = connect_async(&url).await.expect("connessione");
    let (mut tx, mut rx) = ws.split();

    let eph = X25519Keypair::generate();
    let nonce_diverso = [7u8; 32];
    manda_init(
        &mut tx,
        &init_per(&eph.public_bytes(), &nonce_diverso, KEYS_V),
    )
    .await;

    assert_eq!(
        attendi_chiusura(&mut rx).await,
        close::QR_NON_CORRISPONDE,
        "un nonce che non è quello emesso per questo QR deve essere rifiutato"
    );
}

/// Il percorso produttivo, e la prova che le chiavi per direzione sono
/// compatibili sui due lati: il client apre il `HandshakeResp` del desktop.
///
/// Il secondo collegamento con lo stesso QR deve essere rifiutato, perché il QR
/// è single-use: è anche il modo di controllare che il rifiuto avvenga **prima**
/// di tutto il resto, così un QR bruciato non viene sprecato in un DH inutile.
#[tokio::test]
async fn handshake_completo_e_qr_single_use() {
    let (ctx, url) = avvia_engine().await;
    let desktop_pub = ctx.desktop_kp.read().await.public_bytes();
    let nonce = ctx.handshake_material.read().await.nonce32;

    let (ws, _) = connect_async(&url).await.expect("connessione");
    let (mut tx, mut rx) = ws.split();

    let eph = X25519Keypair::generate();
    let eph_pub = eph.public_bytes();
    let x_shared = eph.diffie_hellman(&desktop_pub);

    // Il client è il lato mobile: trasmette su `MobileToDesktop`.
    let mut rx_keys =
        SessionKeys::derive(&x_shared, &nonce, Direction::MobileToDesktop).expect("derive");

    manda_init(&mut tx, &init_per(&eph_pub, &nonce, KEYS_V)).await;

    let resp = tokio::time::timeout(Duration::from_secs(10), rx.next())
        .await
        .expect("nessuna risposta entro 10s")
        .expect("stream chiuso")
        .expect("errore di lettura");
    let WsMsg::Binary(bytes) = resp else {
        // Qui un Close sarebbe un fallimento del negoziato: il codice lo dice.
        if let WsMsg::Close(Some(cf)) = resp {
            panic!("negoziato rifiutato con codice {}", u16::from(cf.code));
        }
        panic!("atteso frame binario, ottenuto {resp:?}");
    };

    // Questo `open` è il cuore del test: decifra con la chiave derivata sul
    // lato mobile. Se le due direzioni condividessero la chiave andrebbe bene
    // comunque; se invece fossero incoerenti fallirebbe qui.
    let enc = nfc_core::protocol::decode_encrypted(&bytes).expect("frame non prost");
    let mut n12 = [0u8; 12];
    n12.copy_from_slice(&enc.nonce12);
    let pt = rx_keys
        .open(enc.seq, &n12, &enc.ciphertext)
        .expect("chiavi incompatibili fra engine e client");

    let plain = nfc_core::protocol::decode_plain(&pt).expect("risposta non prost");
    let Some(proto::plain_frame::Kind::HandshakeResp(r)) = plain.kind else {
        panic!("atteso handshake_resp");
    };
    assert_eq!(r.eph_pubkey.as_slice(), desktop_pub, "pubkey desktop != QR");
    assert_eq!(r.proto_v, 1, "versione negoziata incoerente");

    // Stesso ordine di argomenti che usa il desktop (pubkey desktop, pubkey
    // mobile, nonce): la SAS è l'unico valore che l'utente confronta a occhio
    // fra i due schermi, quindi il formato è parte del contratto.
    let sas = sas_confirm(&desktop_pub, &eph_pub, &nonce);
    assert_eq!(sas.len(), 6, "la SAS deve restare a 6 cifre");
    assert!(
        sas.chars().all(|c| c.is_ascii_digit()),
        "SAS non numerica: {sas}"
    );

    // Il bruci del nonce avviene subito dopo l'invio della risposta: lo aspetto
    // esplicitamente invece di dormere, così il caso successivo non dipende dal
    // tempismo dello scheduler.
    let mut bruciato = false;
    for _ in 0..200 {
        if ctx.handshake_material.read().await.used {
            bruciato = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(bruciato, "il QR single-use non è stato bruciato");

    drop(tx);
    drop(rx);

    // Stesso QR, nuovo collegamento: il QR è già speso.
    let (ws2, _) = connect_async(&url).await.expect("seconda connessione");
    let (mut tx2, mut rx2) = ws2.split();
    let eph2 = X25519Keypair::generate();
    manda_init(&mut tx2, &init_per(&eph2.public_bytes(), &nonce, KEYS_V)).await;
    assert_eq!(
        attendi_chiusura(&mut rx2).await,
        close::QR_USATO,
        "un QR già usato deve essere rifiutato con un codice specifico"
    );
}

/// Il cap di concorrenza sull'handshake respinge con 503 la negoziazione in
/// eccesso, senza bloccare le sessioni già stabilite.
///
/// Le prime `HANDSHAKE_MAX_CONCURRENT` connessioni non inviano mai l'`init`:
/// `negotiate_mobile_session` resta in attesa del primo frame (timeout 15s), così
/// il permesso del cap è tenuto. La successiva riceve 503 all'upgrade.
#[tokio::test]
async fn handshake_oltre_il_cap_respinto_con_503() {
    use nfc_desktop_lib::ws_server::HANDSHAKE_MAX_CONCURRENT;

    let (_ctx, url) = avvia_engine().await;

    let mut occupati = Vec::with_capacity(HANDSHAKE_MAX_CONCURRENT);
    for i in 0..HANDSHAKE_MAX_CONCURRENT {
        let (ws, _) = connect_async(&url)
            .await
            .unwrap_or_else(|e| panic!("connessione {i} entro il cap: {e}"));
        occupati.push(ws);
    }

    let err = connect_async(&url)
        .await
        .expect_err("la negoziazione oltre il cap deve essere respinta");
    assert!(
        err.to_string().contains("503"),
        "atteso 503 per cap concorrenza, ottenuto: {err}"
    );

    drop(occupati);
}
