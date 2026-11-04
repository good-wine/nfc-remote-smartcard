//! Policy di trasporto: heartbeat, timeout, tolleranza Wi-Fi.
//! Il Wi-Fi introduce jitter 20-300ms: usiamo heartbeat 5s con finestra 15s
//! (3 miss) prima di dichiarare il peer morto, e coda APDU con timeout 8s.

use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct TransportPolicy {
    /// Intervallo ping.
    pub heartbeat_interval: Duration,
    /// Dopo quanto senza pong si dichiara disconnesso.
    pub dead_after: Duration,
    /// Timeout default APDU.
    pub apdu_timeout: Duration,
    /// Dimensione max frame WS (protezione memoria).
    pub max_frame_bytes: usize,
}

impl Default for TransportPolicy {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(5),
            dead_after: Duration::from_secs(15),
            apdu_timeout: Duration::from_millis(8000),
            max_frame_bytes: 128 * 1024,
        }
    }
}

/// Contatore monotono thread-safe per seq TX (usato anche fuori `SessionKeys`
/// per Ping/Pong non cifrati se necessario).
#[derive(Debug, Default)]
pub struct SeqCounter(std::sync::atomic::AtomicU64);

impl SeqCounter {
    pub fn next(&self) -> u64 {
        self.0
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .saturating_add(1)
    }
}
