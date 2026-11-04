//! Server compagno dell'engine per il lettore PC/SC virtuale (adapter v1).
//!
//! Logica pura del lato server: [`serve`] gestisce una connessione un frame
//! alla volta, [`respond`] implementa i comandi e [`encode`] produce la
//! risposta `len BE32 || status || payload`. Fattore fuori dal binario così
//! il round-trip col client reale ([`crate::vpcd::VpcdClient`]) è testabile
//! in-process, senza demone esterno.
//!
//! Non emula una carta vera: di default comunica `carta assente`
//! (`GetStatus` → `[0]`). Con `card_present = true` risponde a un ATR
//! sintetico e a `Transmit` con un `9000` di test; la trasmissione APDU reale
//! resta nel percorso mobile.

use crate::vpcd::{VpcdCmd, decode_request};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};

/// ATR sintetico di test (nessuna carta vera: solo per far vedere `presente`).
pub const ATR_TEST: &[u8] = &[0x3B, 0x00];

/// Codifica una risposta `len BE32 || status || payload`.
#[must_use]
pub fn encode(status: u8, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(1 + payload.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.push(status);
    out.extend_from_slice(payload);
    out
}

/// Gestisce un comando adapter v1 e ritorna `(status, payload)`.
#[must_use]
pub fn respond(req: &[u8], card_present: bool) -> (u8, Vec<u8>) {
    match decode_request(req) {
        Ok((VpcdCmd::GetStatus, _)) if card_present => {
            let mut p = vec![0x01];
            p.extend_from_slice(ATR_TEST);
            (0, p)
        }
        Ok((VpcdCmd::GetStatus, _)) => (0, vec![0x00]),
        Ok((VpcdCmd::PowerOn, _)) if card_present => (0, ATR_TEST.to_vec()),
        Ok((VpcdCmd::PowerOff, _)) => (0, Vec::new()),
        Ok((VpcdCmd::Transmit, _)) if card_present => (0, vec![0x90, 0x00]),
        Ok((VpcdCmd::PowerOn | VpcdCmd::Transmit, _)) => (0x01, Vec::new()),
        Err(_) => (0xFF, Vec::new()),
    }
}

/// Gestisce una connessione finché il client si scollega o manda framing
/// invalido (in tal caso chiude, così il client riconnette da zero).
pub fn serve(mut stream: TcpStream, present: &AtomicBool) {
    let _ = stream.set_nodelay(true);
    loop {
        let mut header = [0u8; 4];
        if stream.read_exact(&mut header).is_err() {
            return; // client chiuso
        }
        let len = u32::from_be_bytes(header) as usize;
        if !(1..=64 * 1024).contains(&len) {
            return; // framing fuori contratto: chiudi, l'engine riconnette
        }
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        let mut full = Vec::with_capacity(4 + len);
        full.extend_from_slice(&header);
        full.extend_from_slice(&body);
        let (status, payload) = respond(&full, present.load(Ordering::Relaxed));
        if stream.write_all(&encode(status, &payload)).is_err() {
            return;
        }
    }
}
