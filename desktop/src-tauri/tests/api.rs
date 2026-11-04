//! Test E2E del Router Axum senza rete: costruisce `WsContext::new_test()`
//! (chiavi effimere, niente I/O) e invoca le route via `tower::ServiceExt::oneshot`.
//! Copre: landing, status, metrics, transmit 502 senza mobile, 422 su APDU invalida,
//! 403 su Origin non allowlist, 404. Il WS (`/v1/mobile`, `/v1/extension`)
//! richiede upgrade reale ed è coperto da test manuali + Playwright.

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use nfc_desktop_lib::local_auth::TEST_TOKEN;
use nfc_desktop_lib::ws_server::{WsContext, router};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tower::ServiceExt;

const LIM: usize = 256 * 1024;

/// Header di autorizzazione del token di prova (`ClientAuth::new_test()`).
fn bearer() -> String {
    format!("Bearer {TEST_TOKEN}")
}

/// Loopback fittizio: replica `into_make_service_with_connect_info` di `serve()`.
fn loopback() -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45999))
}

async fn body_json(app: axum::Router, mut req: Request<Body>) -> (StatusCode, serde_json::Value) {
    req.extensions_mut().insert(loopback());
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), LIM).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn landing_e_status() {
    let ctx = WsContext::new_test();
    let (s, v) = body_json(
        router(ctx),
        Request::builder().uri("/").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["service"], "nfc-remote");

    let ctx = WsContext::new_test();
    let (s, v) = body_json(
        router(ctx),
        Request::builder()
            .uri("/v1/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["mobile_online"], false);
    assert!(v["https"].as_str().unwrap().contains("nfc.local"));
}

#[tokio::test]
async fn metrics_prometheus() {
    let ctx = WsContext::new_test();
    let mut req = Request::builder()
        .uri("/v1/metrics")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(loopback());
    let res = router(ctx).oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let b = to_bytes(res.into_body(), LIM).await.unwrap();
    let t = String::from_utf8(b.to_vec()).unwrap();
    assert!(t.contains("nfc_apdu_total"));
    assert!(t.contains("nfc_build_info"));
}

#[tokio::test]
async fn transmit_senza_mobile_502() {
    let ctx = WsContext::new_test();
    let body = serde_json::json!({
        "type": "transmit_apdu",
        "request_id": "t1",
        "payload_hex": "00A4040007A000000247100100",
        "timeout_ms": 1500,
    });
    let (s, v) = body_json(
        router(ctx),
        Request::builder()
            .method("POST")
            .uri("/v1/transmit")
            .header("content-type", "application/json")
            .header("authorization", bearer())
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_eq!(v["code"], 502);
}

#[tokio::test]
async fn transmit_senza_token_401() {
    // Loopback + Origin ok ma senza token: il canale arriva alla carta del
    // telefono remoto, quindi deve fallire la **autorizzazione** prima di
    // qualunque lavoro. Prima di questo modulo bastava omettere l'Origin.
    let ctx = WsContext::new_test();
    let body = serde_json::json!({
        "type": "transmit_apdu",
        "request_id": "t401",
        "payload_hex": "00A4040007A000000247100100",
    });
    let (s, v) = body_json(
        router(ctx),
        Request::builder()
            .method("POST")
            .uri("/v1/transmit")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["code"], 401);
}

#[tokio::test]
async fn transmit_token_estraneo_401() {
    let ctx = WsContext::new_test();
    let body = serde_json::json!({
        "type": "transmit_apdu",
        "request_id": "t401b",
        "payload_hex": "00A4040007A000000247100100",
    });
    let (s, _) = body_json(
        router(ctx),
        Request::builder()
            .method("POST")
            .uri("/v1/transmit")
            .header("content-type", "application/json")
            .header("authorization", "Bearer token-mai-emesso")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn transmit_apdu_invalida_422() {
    let ctx = WsContext::new_test();
    let body = serde_json::json!({
        "type": "transmit_apdu",
        "request_id": "t2",
        "payload_hex": "ZZZ",
    });
    let (s, _) = body_json(
        router(ctx),
        Request::builder()
            .method("POST")
            .uri("/v1/transmit")
            .header("content-type", "application/json")
            .header("authorization", bearer())
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn webapp_e_qr_rest() {
    let ctx = WsContext::new_test();
    nfc_desktop_lib::qr::regenerate_into(&ctx)
        .await
        .expect("QR di pairing");

    // `/` resta la landing JSON (contratto API), la webapp vive su `/app`.
    let (s, _) = body_json(
        router(ctx.clone()),
        Request::builder().uri("/app").body(Body::empty()).unwrap(),
    )
    .await;
    // 200 con la webapp compilata, 503 con la pagina che spiega la build:
    // in entrambi i casi HTML e mai un 404 silenzioso.
    assert!(
        s == StatusCode::OK || s == StatusCode::SERVICE_UNAVAILABLE,
        "status {s}"
    );

    // `GET /v1/qr` è il canale REST che usa la webapp al posto dell'IPC Tauri.
    let mut req = Request::builder()
        .uri("/v1/qr")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(loopback());
    let res = router(ctx).oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let b = to_bytes(res.into_body(), LIM).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["type"], "qr");
    let text = v["qr_text"].as_str().unwrap();
    assert!(text.starts_with("NFC://2/"), "qr_text: {text}");
    // Il PNG deve essere base64 STANDARD: i data-URL con `-`/`_` non vengono
    // renderizzati dai browser (bug silenzioso: immagine bianca).
    let png = v["qr_png"].as_str().unwrap();
    let payload = png
        .strip_prefix("data:image/png;base64,")
        .expect("data-URL PNG");
    assert!(
        !payload.contains('-') && !payload.contains('_'),
        "base64 non standard"
    );
    assert!(
        payload.len() > 1000,
        "PNG sospettosamente piccolo: {}",
        payload.len()
    );
}

/// Il server è in ascolto su `[::]`, quindi una connessione IPv4 arriva come
/// `::ffff:127.0.0.1`. `Ipv6Addr::is_loopback()` è **falso** per quella forma:
/// senza lo unwrap dei mapped, ogni client loopback IPv4 (webapp su 127.0.0.1,
/// app mobile in locale) prendeva 403 su `/v1/transmit` e `POST /v1/qr`.
#[tokio::test]
async fn loopback_ipv4_mapped_ammesso() {
    let v4_mapped = ConnectInfo(SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001,
        )),
        45999,
    ));
    let v6_loop = ConnectInfo(SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        45999,
    ));
    let remoto = ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        45999,
    ));

    for (nome, ci) in [("ipv4-mapped", v4_mapped), ("ipv6 ::1", v6_loop)] {
        let body = serde_json::json!({
            "type": "transmit_apdu",
            "request_id": "r1",
            "payload_hex": "00A4000C023F00",
        })
        .to_string();
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/transmit")
            .header("content-type", "application/json")
            .header("authorization", bearer())
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(ci);
        let res = router(WsContext::new_test()).oneshot(req).await.unwrap();
        // 502 (mobile non connesso) e non 403: la richiesta ha superato il guard.
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY, "caso {nome}");
    }

    // Un host di rete reale resta escluso, anche se mappato in IPv6.
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/transmit")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"type":"transmit_apdu","request_id":"r","payload_hex":"00A4000C023F00"}"#,
        ))
        .unwrap();
    req.extensions_mut().insert(remoto);
    let res = router(WsContext::new_test()).oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// Il canale in chiaro deve restare confinato al loopback.
///
/// Questo test blocca il ritorno all'allargamento a `0.0.0.0`: durante lo
/// sviluppo mobile 8080 era stato aperto a tutte le interfacce perché il
/// telefono non si fidava della CA locale, e `/v1/status` intanto dichiarava un
/// URL da loopback — quindi la superficie reale e quella dichiarata erano
/// diverse. Ora il mobile va su `wss://` con pin TLS, quindi 8080 non ha più
/// ragione di essere pubblico.
///
/// Si verifica l'indirizzo di bind, non il comportamento via rete: quest'ultimo
/// dipenderebbe dall'isolamento di rete della macchina di test.
#[test]
fn piano_in_chiaro_e_loopback_only() {
    let addr = nfc_desktop_lib::ws_server::plain_bind_addr(8080);
    assert!(
        addr.ip().is_loopback(),
        "8080 deve essere loopback-only: {addr}"
    );
    assert!(!addr.ip().is_unspecified(), "mai 0.0.0.0: {addr}");
    assert_eq!(addr.port(), 8080);
}

/// `/v1/status` deve dichiarare l'ambito del canale legacy come dato
/// strutturato, non come prosa dentro l'URL.
///
/// Il JSON è un contratto machine-readable: se l'ambito stesse dentro
/// `ws_legacy`, ogni consumer che fa match su quella stringa continuerebbe a
/// funzionare mentre la semantica è cambiata — che è come il canale è stato
/// dichiarato privato mentre era pubblico.
#[tokio::test]
async fn status_dichiara_l_ambito_del_canale_legacy() {
    let (code, v) = body_json(
        router(WsContext::new_test()),
        Request::builder()
            .uri("/v1/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(v["ws_legacy_scope"], "loopback-only");
    assert_eq!(v["ws_legacy"], nfc_core::local_domain::WS_LEGACY);
}

/// Le **scritture** REST devono restare confinate al loopback.
///
/// Difesa in profondità: il bind di 8080 è già solo loopback (vedi
/// `piano_in_chiaro_e_loopback_only`), ma il guard per handler resta utile se
/// un domani quel bind torna pubblico per qualche motivo — chiunque in LAN
/// potrebbe altrimenti chiedere una transazione APDU.
///
/// Il telefono in LAN non è più tenuto fuori da qui: passa da `wss://` su 8443.
#[tokio::test]
async fn scritture_rest_solo_loopback_anche_se_il_bind_e_pubblico() {
    let remoto = ConnectInfo(SocketAddr::from(([192, 168, 1, 50], 5555)));

    // Scritture: ogni endpoint che muta stato resta 403 dalla rete.
    for (method, uri, body) in [
        (
            "POST",
            "/v1/transmit",
            r#"{"type":"transmit_apdu","request_id":"r","payload_hex":"00A4000C023F00"}"#,
        ),
        ("POST", "/v1/signal", r#"{"sdp":"x"}"#),
        ("POST", "/v1/qr", ""),
    ] {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("origin", "https://nfc.local:8443")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(remoto);
        let res = router(WsContext::new_test()).oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} dalla rete deve essere 403"
        );
    }
}

#[tokio::test]
async fn origin_non_allowlist_403() {
    let ctx = WsContext::new_test();
    let body = serde_json::json!({
        "type": "transmit_apdu",
        "request_id": "t3",
        "payload_hex": "00A4040007A000000247100100",
    });
    let (s, v) = body_json(
        router(ctx),
        Request::builder()
            .method("POST")
            .uri("/v1/transmit")
            .header("content-type", "application/json")
            .header("origin", "https://evil.example")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["code"], 403);
}

/// `/v1/qr` e `/v1/metrics` sono **leggibili dalla LAN** (il telefono deve
/// poter recuperare il pairing dal dominio, non solo dal QR scansionato), ma
/// non da una pagina web arbitraria: il guard è l'allowlist Origin.
///
/// Le scritture (`/v1/transmit`, `/v1/signal`, `POST /v1/qr`) restano invece
/// loopback-only: vedi `transmit_*` e `origin_non_allowlist_403`.
#[tokio::test]
async fn qr_e_metrics_leggibili_da_lan_ma_bloccati_drive_by() {
    let ctx = WsContext::new_test();
    nfc_desktop_lib::qr::regenerate_into(&ctx)
        .await
        .expect("QR di pairing");

    for uri in ["/v1/qr", "/v1/metrics"] {
        // 1. Client LAN con Origin legittima → 200 (mobile su nfc.local).
        let mut req = Request::builder()
            .uri(uri)
            .header("origin", "https://nfc.local:8443")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 168, 1, 50], 5555))));
        let res = router(ctx.clone()).oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "{uri} da LAN con Origin valida"
        );

        // 2. Client LAN con Origin ostile → 403 (scenario drive-by fetch).
        let mut req = Request::builder()
            .uri(uri)
            .header("origin", "https://evil.example")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 168, 1, 50], 5555))));
        let res = router(ctx.clone()).oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{uri} da evil.example");

        // 3. Loopback + Origin assente (curl, webapp same-origin) → 200.
        let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        req.extensions_mut().insert(loopback());
        let res = router(ctx.clone()).oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "{uri} da loopback senza Origin"
        );

        // 4. LAN (non-loopback) senza Origin → 403: solo il loopback può
        //    omettere `Origin`; un client LAN anonimo non legge il pairing.
        let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 168, 1, 50], 5555))));
        let res = router(ctx.clone()).oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "{uri} da LAN senza Origin"
        );
    }
}

/// Il rate-limit per IP sulle letture taglia l'ennesima richiesta con 429.
/// Le prime `READ_RATE_MAX` passano (loopback, Origin assente → ammesso),
/// la successiva è respinta.
#[tokio::test]
async fn letture_rate_limited_per_ip() {
    use nfc_desktop_lib::ws_server::READ_RATE_MAX;

    let ctx = WsContext::new_test();
    for _ in 0..READ_RATE_MAX {
        let (s, _) = body_json(
            router(ctx.clone()),
            Request::builder()
                .uri("/v1/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "richiesta entro il rate-limit");
    }
    let (s, _) = body_json(
        router(ctx.clone()),
        Request::builder()
            .uri("/v1/metrics")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "oltre il rate-limit");
}
