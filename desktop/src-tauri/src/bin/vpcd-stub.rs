//! Lettore PC/SC **virtuale** compagno dell'engine (adapter v1, loopback).
//!
//! L'engine parla con `vpcd` su `127.0.0.1:35963` usando il framing
//! `len BE32 || cmd u8 || payload` di [`nfc_desktop_lib::vpcd`] (adapter v1,
//! definito dal progetto). Il demone `vpcd` di **vsmartcard** usa un altro
//! protocollo e non può rispondere: questo binario è il server che parla
//! davvero l'adapter v1, così l'engine vede `ReaderConnected("vpcd-0")` e lo
//! stato `vpcd_up` non flappeggia — senza bisogno di hardware né di
//! compilare vsmartcard.
//!
//! Uso: `vpcd-stub [--host 127.0.0.1] [--port 35963] [--card-present]`

use nfc_desktop_lib::vpcd_stub::serve;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

fn main() {
    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = 35963;
    let mut card_present = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--host" => host = args.next().expect("--host richiede un valore"),
            "--port" => {
                port = args
                    .next()
                    .expect("--port richiede un valore")
                    .parse()
                    .expect("--port deve essere numerico");
            }
            "--card-present" => card_present = true,
            other => {
                eprintln!("argomento sconosciuto: {other}");
                std::process::exit(2);
            }
        }
    }

    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("bind {addr} fallito: {e}");
        std::process::exit(1);
    });
    println!("vpcd-stub in ascolto su {addr} (carta presente: {card_present})");

    let present = Arc::new(AtomicBool::new(card_present));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let p = Arc::clone(&present);
                std::thread::spawn(move || serve(stream, p.as_ref()));
            }
            Err(e) => eprintln!("accept fallita: {e}"),
        }
    }
}
