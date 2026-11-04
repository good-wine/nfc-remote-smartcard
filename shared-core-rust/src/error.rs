//! Errori tipizzati del core. Ogni fallimento è mappato qui,
//! mai `panic!` nei path di rete/crypto.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("handshake incompleto: {0}")]
    Handshake(String),
    #[error("protocollo: {0}")]
    Protocol(String),
    #[error("pairing QR non valido: {0}")]
    Pairing(String),
    #[error("rete: {0}")]
    Network(String),
    #[error("timeout dopo {0}ms")]
    Timeout(u64),
    #[error("replay rilevato: seq {got} <= {last}")]
    Replay { got: u64, last: u64 },
    #[error("mdns: {0}")]
    Mdns(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
