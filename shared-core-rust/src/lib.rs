//! nfc-core: nucleo condiviso desktop/mobile.
//! Architettura (`crypto` X25519 ibrido ML-KEM + HKDF-SHA256 + AES-256-GCM anti-replay;
//! `pairing` QR v2 base64url-JSON; `protocol` prost + JSON; `mdns` discovery;
//! `transport` policy heartbeat/timeout; `local_domain` nfc.local 8080/8443;
//! `net` scelta dell'IP di LAN per QR e mDNS).
//! Tutto asincrono, nessun I/O bloccante. Errori tipizzati in `error`.

pub mod crypto;
pub mod error;
pub mod local_domain;
// `mdns` e `net` sono rete grezza (multicast UDP, enumerazione interfacce):
// esiste solo dove c'è un kernel che la sa fare. La webapp gira in un browser,
// dove né il multicast né `getifaddrs` esistono, e `mdns-sd` trae `mio` +
// `socket2` che **non compilano** su wasm32. Espliciti, non un implicito
// `[cfg(target_arch)]`: la feature è una dichiarazione d'intento leggibile a
// ogni call site.
#[cfg(feature = "net")]
pub mod mdns;
#[cfg(feature = "net")]
pub mod net;
pub mod pairing;
pub mod protocol;
pub mod transport;

pub use error::{CoreError, Result};
