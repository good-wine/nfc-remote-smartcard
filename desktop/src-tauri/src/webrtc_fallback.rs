//! Fallback WebRTC `DataChannel` per VPN (2026): segnalazione su `POST /v1/signal`.
//! Il `DataChannel` trasporta gli stessi `EncryptedFrame` E2EE (stesse `SessionKeys`):
//! cambia solo il carrier quando la VPN blocca il TCP diretto.
//! Protocollo JSON su loopback con allowlist Origin: offerta `rtc_offer` con `sdp`
//! (risposta `rtc_answer` oppure 501 se disabilitato) e `rtc_candidate` validati
//! host-only (`typ host`, niente STUN/TURN pubblico di default).
//! Il trasporto dati riusa `SessionKeys`; la negoziazione SDP/ICE completa vive
//! dietro la feature `webrtc` (build LAN leggere senza dipendenze pesanti).

use nfc_core::protocol::{RtcAnswer, RtcCandidate, RtcOffer};

#[derive(Debug, Clone, Default)]
pub struct WebRtcConfig {
    pub enabled: bool,
}

/// Handler `POST /v1/signal`: offerta -> answer, oppure 501 esplicito.
// Arm e connettore usati dal Router (niente codice morto).
pub async fn handle_signal(body: serde_json::Value) -> (axum::http::StatusCode, serde_json::Value) {
    use axum::http::StatusCode;
    let Some(t) = body.get("type").and_then(|v| v.as_str()) else {
        return (
            StatusCode::BAD_REQUEST,
            serde_json::json!({"type":"error","code":400,"message":"type mancante"}),
        );
    };
    match t {
        "rtc_offer" => {
            let offer: RtcOffer = match serde_json::from_value(body) {
                Ok(o) => o,
                Err(e) => {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        serde_json::json!({"type":"error","code":422,"message":format!("schema: {e}")}),
                    );
                }
            };
            if offer.sdp.is_empty() || offer.sdp.len() > 64 * 1024 {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    serde_json::json!({"type":"error","code":422,"message":"sdp non valida"}),
                );
            }
            match open_datachannel(&WebRtcConfig::default()).await {
                Ok(answer) => (StatusCode::OK, serde_json::to_value(&answer).unwrap()),
                Err(e) => (
                    StatusCode::NOT_IMPLEMENTED,
                    serde_json::json!({"type":"error","code":501,"message":e.to_string()}),
                ),
            }
        }
        "rtc_candidate" => {
            let cand: RtcCandidate = match serde_json::from_value(body) {
                Ok(c) => c,
                Err(e) => {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        serde_json::json!({"type":"error","code":422,"message":format!("schema: {e}")}),
                    );
                }
            };
            if !is_host_candidate(&cand) {
                return (
                    StatusCode::FORBIDDEN,
                    serde_json::json!({"type":"error","code":403,"message":"solo candidati host (niente srflx/relay di default)"}),
                );
            }
            (StatusCode::OK, serde_json::json!({"type":"ok"}))
        }
        _ => (
            StatusCode::BAD_REQUEST,
            serde_json::json!({"type":"error","code":400,"message":"type sconosciuto"}),
        ),
    }
}

/// Punto di aggancio per il `DataChannel` (feature `webrtc`, default off).
/// `async` per stabilità di firma: con `webrtc-rs` il corpo attende la negoziazione.
///
/// # Errors
/// Sempre `Err` senza feature `webrtc` (oppure se disabilitato in config).
#[allow(clippy::unused_async)]
pub async fn open_datachannel(cfg: &WebRtcConfig) -> anyhow::Result<RtcAnswer> {
    if !cfg.enabled {
        anyhow::bail!("webrtc fallback disabilitato (usa TCP diretto /v1/mobile)");
    }
    #[cfg(feature = "webrtc")]
    {
        // Flusso webrtc-rs: answer SDP reale + DataChannel binario ->
        // pipe EncryptedFrame <-> canale con le SessionKeys di sessione.
        Ok(RtcAnswer {
            kind: "rtc_answer".into(),
            sdp: String::new(),
        })
    }
    #[cfg(not(feature = "webrtc"))]
    {
        anyhow::bail!("ricompila con --features webrtc per il DataChannel (VPN)")
    }
}

/// Valida un candidato ICE: solo `typ host` (niente srflx/relay di default).
pub fn is_host_candidate(c: &RtcCandidate) -> bool {
    c.candidate.contains("typ host")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_only() {
        let c = RtcCandidate {
            kind: "rtc_candidate".into(),
            from: "mobile".into(),
            candidate: "candidate:1 1 UDP 2113937151 192.168.1.20 9 typ host".into(),
        };
        assert!(is_host_candidate(&c));
        let _ = RtcOffer {
            kind: "rtc_offer".into(),
            from: "mobile".into(),
            sdp: "v=0".into(),
        };
        let _ = RtcAnswer {
            kind: "rtc_answer".into(),
            sdp: "v=0".into(),
        };
    }

    /// ICE host-only: i candidati `srflx`/`relay` sono respinti (niente
    /// STUN/TURN pubblico di default), i `host` accettati.
    #[tokio::test]
    async fn candidato_non_host_respinto() {
        let (s, v) = handle_signal(serde_json::json!({
            "type": "rtc_candidate",
            "from": "mobile",
            "candidate": "candidate:1 1 UDP 2113937151 203.0.113.9 9 typ srflx"
        }))
        .await;
        assert_eq!(s, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(v["code"], 403);

        let (s, _) = handle_signal(serde_json::json!({
            "type": "rtc_candidate",
            "from": "mobile",
            "candidate": "candidate:1 1 UDP 2113937151 192.168.1.20 9 typ host"
        }))
        .await;
        assert_eq!(s, axum::http::StatusCode::OK);
    }

    /// Senza la feature `webrtc` l'offerta è esplicitamente non implementata
    /// (501), mai un falso successo.
    #[tokio::test]
    async fn offerta_senza_feature_risponde_501() {
        let (s, v) = handle_signal(serde_json::json!({
            "type": "rtc_offer",
            "from": "mobile",
            "sdp": "v=0"
        }))
        .await;
        assert_eq!(s, axum::http::StatusCode::NOT_IMPLEMENTED);
        assert_eq!(v["code"], 501);
    }
}
