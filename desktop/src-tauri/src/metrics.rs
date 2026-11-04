//! Metriche Prometheus su `GET /v1/metrics` (solo loopback, testo 0.0.4).
//! Zero dipendenze: contatori atomici + somma latenze. Nessuna label
//! ad alta cardinalità (solo `result=ok|timeout|offline|error`).

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    apdu_ok: AtomicU64,
    apdu_timeout: AtomicU64,
    apdu_offline: AtomicU64,
    apdu_error: AtomicU64,
    apdu_latency_sum_ms: AtomicU64,
    ws_extension: AtomicU64,
    ws_mobile: AtomicU64,
    handshake_rejected: AtomicU64,
    rate_limited: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub enum ApduOutcome {
    Ok(u64),
    Timeout,
    Offline,
    Error,
}

impl Metrics {
    pub fn record_apdu(&self, o: ApduOutcome) {
        match o {
            ApduOutcome::Ok(ms) => {
                self.apdu_ok.fetch_add(1, Ordering::Relaxed);
                self.apdu_latency_sum_ms.fetch_add(ms, Ordering::Relaxed);
            }
            ApduOutcome::Timeout => {
                self.apdu_timeout.fetch_add(1, Ordering::Relaxed);
            }
            ApduOutcome::Offline => {
                self.apdu_offline.fetch_add(1, Ordering::Relaxed);
            }
            ApduOutcome::Error => {
                self.apdu_error.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn ws_open(&self, mobile: bool) {
        (if mobile {
            &self.ws_mobile
        } else {
            &self.ws_extension
        })
        .fetch_add(1, Ordering::Relaxed);
    }

    /// Negoziazioni `/v1/mobile` respinte perché il cap di concorrenza era
    /// saturo (possibile brute-force/DoS sull'handshake).
    pub fn handshake_rejected(&self) {
        self.handshake_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Richieste respinte dal rate-limit per IP (429) su handshake o letture.
    pub fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let ok = self.apdu_ok.load(Ordering::Relaxed);
        let sum = self.apdu_latency_sum_ms.load(Ordering::Relaxed);
        let avg = sum.checked_div(ok).unwrap_or(0);
        format!(
            "# HELP nfc_apdu_total APDU inoltrate per esito\n\
             # TYPE nfc_apdu_total counter\n\
             nfc_apdu_total{{result=\"ok\"}} {ok}\n\
             nfc_apdu_total{{result=\"timeout\"}} {}\n\
             nfc_apdu_total{{result=\"offline\"}} {}\n\
             nfc_apdu_total{{result=\"error\"}} {}\n\
             # HELP nfc_apdu_latency_ms_avg Latenza media carta (ms) su esiti ok\n\
             # TYPE nfc_apdu_latency_ms_avg gauge\n\
             nfc_apdu_latency_ms_avg {avg}\n\
             # HELP nfc_ws_connections_total Connessioni WS totali\n\
             # TYPE nfc_ws_connections_total counter\n\
             nfc_ws_connections_total{{channel=\"extension\"}} {}\n\
             nfc_ws_connections_total{{channel=\"mobile\"}} {}\n\
             # HELP nfc_handshake_rejected_total Negoziazioni mobile respinte per cap concorrenza\n\
             # TYPE nfc_handshake_rejected_total counter\n\
             nfc_handshake_rejected_total {}\n\
             # HELP nfc_rate_limited_total Richieste respinte dal rate-limit per IP (429)\n\
             # TYPE nfc_rate_limited_total counter\n\
             nfc_rate_limited_total {}\n\
             # HELP nfc_build_info Versione engine\n\
             # TYPE nfc_build_info gauge\n\
             nfc_build_info{{version=\"0.3.0\",crypto=\"hybrid\"}} 1\n",
            self.apdu_timeout.load(Ordering::Relaxed),
            self.apdu_offline.load(Ordering::Relaxed),
            self.apdu_error.load(Ordering::Relaxed),
            self.ws_extension.load(Ordering::Relaxed),
            self.ws_mobile.load(Ordering::Relaxed),
            self.handshake_rejected.load(Ordering::Relaxed),
            self.rate_limited.load(Ordering::Relaxed),
        )
    }
}
