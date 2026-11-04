//! Round-trip reale dell'adapter v1: server compagno (`vpcd_stub::serve`) ↔
//! client dell'engine (`vpcd::VpcdClient`) su un socket vero, in-process.
//! È la prova che la risoluzione vpcd regge da sola, senza demone esterno:
//! il protocollo è una sola fonte di verità (`decode_request` nelle due
//! direzioni) e la connessione sopravvive ai comandi di keepalive.

use nfc_desktop_lib::vpcd::{VpcdClient, VpcdConfig};
use nfc_desktop_lib::vpcd_stub::{ATR_TEST, serve};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// Spawna uno stub che serve esattamente una connessione; ritorna la porta.
fn spawn_stub(card_present: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let port = listener.local_addr().expect("porta stub").port();
    let present = AtomicBool::new(card_present);
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            serve(stream, &present);
        }
    });
    port
}

fn client(port: u16) -> VpcdClient {
    VpcdClient::new(VpcdConfig {
        host: "127.0.0.1".into(),
        port,
        connect_timeout: Duration::from_secs(3),
        io_timeout: Duration::from_secs(5),
    })
}

#[tokio::test]
async fn carta_assente_keepalive_stabile() {
    let port = spawn_stub(false);
    let mut c = client(port);
    let (present, atr) = c.card_present().await.expect("get-status carta assente");
    assert_eq!((present, atr.len()), (false, 0));
    assert!(
        c.power_on().await.is_err(),
        "senza carta il power-on deve fallire (status != 0)"
    );
    // La connessione NON è stata invalidata: un secondo keepalive passa sulla
    // stessa socket — è il comportamento di cui l'engine ha bisogno per non
    // flappeggiare ReaderConnected/ReaderDisconnected.
    let (present, _) = c.card_present().await.expect("secondo get-status");
    assert!(!present, "la carta resta assente");
}

#[tokio::test]
async fn carta_presente_atr_e_transmit() {
    let port = spawn_stub(true);
    let mut c = client(port);
    let (present, atr) = c.card_present().await.expect("get-status carta presente");
    assert!(present);
    assert_eq!(atr, ATR_TEST);
    assert_eq!(c.power_on().await.expect("power-on con carta"), ATR_TEST);
    assert_eq!(
        c.transmit(&[0x00, 0xA4, 0x04, 0x00])
            .await
            .expect("transmit con carta"),
        [0x90, 0x00]
    );
    assert_eq!(c.power_off().await.expect("power-off"), (),);
}
