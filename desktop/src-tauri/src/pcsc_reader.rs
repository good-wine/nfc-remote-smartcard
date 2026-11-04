//! Lettore fisico diretto via PC/SC (feature `physical`, opt-in 2026).
//! Quando `vpcd` è assente ma c'è un lettore USB/NFC fisico (es. postazione IT
//! con ACR122U), l'engine pubblica comunque `ReaderConnected("pcsc-<nome>")`
//! così extension/webapp vedono un reader. Il path APDU resta quello mobile:
//! il probe qui è solo presenza (trasmissione diretta su PC/SC fisico = passo
//! successivo, vedi `transmit_raw` dietro alla stessa feature).
//!
//! API `pcsc` 2.x (stabile da anni): `Context::establish`, `list_readers_len`,
//! `list_readers`. Compilato solo con `--features physical` (serve libpcsclite
//! di sistema: `libpcsclite-dev` / `pcsc-lite`).

#[cfg(feature = "physical")]
pub fn probe() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(ctx) = pcsc::Context::establish(pcsc::Scope::User) else {
        return out;
    };
    let Ok(len) = ctx.list_readers_len() else {
        return out;
    };
    if len == 0 {
        return out;
    }
    let mut buf = vec![0u8; len];
    let Ok(readers) = ctx.list_readers(&mut buf) else {
        return out;
    };
    for r in readers {
        out.push(r.to_string_lossy().into_owned());
    }
    out
}
