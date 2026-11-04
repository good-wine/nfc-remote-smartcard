//! HTTPS locale `nfc.local:8443` con CA utente dedicata (2026).
//! - CA root in `profile/ca/` (permessi 0600), foglia in `profile/tls/` con SAN
//!   `nfc.local, *.nfc.local (+api/app/pair), localhost` (auto IP/DNS via rcgen).
//! - Generazione **atomica** CA+foglia: rcgen non può ricaricare un CA cert da
//!   PEM per firmare dopo (niente `Certificate::from_pem`), quindi se manca un
//!   qualsiasi file si rigenera tutto; rotazioni esplicite solo con `--rotate-ca`
//!   (richiede ridistribuire la fiducia: è il prezzo della semplicità auditabile).
//!   `--refresh-leaf` è il caso intermedio: rigenera la **sola foglia** con le
//!   SAN attuali (`x509-parser` ricostruisce la CA da PEM e la stessa chiave
//!   firma il nuovo leaf), senza toccare la CA già distribuita.
//! - `serve_tls(ctx)`: stesso `ws_server::router` servito via `axum-server`
//!   rustls su `127.0.0.1:8443` con **solo TLS 1.3** e key exchange ibrido
//!   post-quantum **X25519MLKEM768** per primo (feature `prefer-post-quantum`,
//!   feature `tls12` rimossa: identica postura del client mobile).
//!   Il server in chiaro 8080 resta per compat.
//! - CLI `nfc-desktop --setup-local-domain` / `--rotate-ca`.
//!
//! La chiave CA NON lascia mai l'host. Trust una tantum: Windows (`CurrentUser`
//! Root), macOS (login Keychain), Linux (NSSDB + ca-certificates), Firefox
//! (proprio store: `security.enterprise_roots.enabled=true` o import manuale).

use std::{net::SocketAddr, sync::Arc};

use nfc_core::local_domain;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::crypto::aws_lc_rs as provider;
use tracing::info;

use crate::ws_server::WsContext;

/// Entry CLI: ritorna true se l'argomento è stato gestito (il chiamante esce).
#[must_use]
pub fn handle_cli() -> bool {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--setup-local-domain") {
        match ensure_pki() {
            Ok(info) => {
                println!("{info}");
                print_hosts_and_trust();
            }
            Err(e) => {
                eprintln!("setup-local-domain fallito: {e:#}");
                std::process::exit(1);
            }
        }
        return true;
    }
    if args.iter().any(|a| a == "--rotate-ca") {
        match rotate_ca() {
            Ok(()) => {
                println!("CA ruotata: ridistribuisci la fiducia (vedi sotto) e riavvia l'engine.");
            }
            Err(e) => {
                eprintln!("rotate-ca fallito: {e:#}");
                std::process::exit(1);
            }
        }
        print_hosts_and_trust();
        return true;
    }
    if args.iter().any(|a| a == "--refresh-leaf") {
        match refresh_leaf() {
            Ok(()) => {
                println!(
                    "Foglia rigenerata con le SAN attuali (CA invariata): \
                     riavvia l'engine e rigenera il QR di pairing."
                );
            }
            Err(e) => {
                eprintln!("refresh-leaf fallito: {e:#}");
                std::process::exit(1);
            }
        }
        return true;
    }
    false
}

/// Rotazione CA: cancella CA+foglia e rigenera; le sessioni E2EE esistenti
/// restano valide (chiavi di sessione indipendenti dai cert TLS), ma browser
/// e `curl --cacert` devono fidarsi della nuova CA (ridistribuire via GPO/MDM).
///
/// **Rifiuta se l'engine sta servendo TLS.** Non è una pedanteria: l'engine
/// tiene in memoria il certificato foglia con cui serve il TLS, mentre il pin
/// del QR lo rileggerebbe da disco. Ruotando sotto un engine attivo, ogni QR
/// nuovo porterebbe l'impronta del certificato **nuovo** mentre il server
/// presenta quello **vecchio**: ogni pairing fallirebbe con "pin non
/// corrisponde", e rigenerare il QR non aiuterebbe — servirebbe riavviare. Un
/// errore che si presenta come un attacco, per una rotazione che l'utente ha
/// fatto lui stesso.
///
/// La guardia è il **lockfile in combinazione con la porta TLS**, non il
/// lockfile da solo. Il lockfile da solo è insufficiente: `SIGTERM` — cioè
/// `systemctl stop`, l'MDM, un `Ctrl-C` — non passa da `RunEvent::Exit`, quindi
/// il file resterebbe a terra e **ogni** shutdown lascerebbe un relitto da
/// cancellare a mano prima della prima rotazione. Verificare che qualcuno stia
/// davvero in ascolto distingue i due casi senza dipendere dalla pulizia
/// dell'uscita. Il file serve a coprire la finestra fra avvio e bind.
///
/// # Errors
/// `anyhow` su I/O profilo, generazione cert, o se un engine serve già sulla
/// porta TLS.
pub fn rotate_ca() -> anyhow::Result<()> {
    if local_domain::engine_lock_present() && tls_port_busy() {
        anyhow::bail!(
            "un engine è in esecuzione: la porta {} è occupata e il lockfile ({}) \
             è presente. Chiudi il desktop e riprova. La rotazione viene rifiutata \
             perché, con l'engine attivo, i QR emessi avrebbero il pin di un \
             certificato che il server non sta presenting: ogni pairing \
             fallirebbe con un errore che sembrerebbe un attacco",
            local_domain::TLS_PORT,
            local_domain::engine_lock_path().display()
        );
    }
    if local_domain::engine_lock_present() {
        // Lockfile senza porta occupata: l'engine non sta servendo. Non è un
        // errore da nascondere, ma nemmeno da far fallire — altrimenti la
        // rotazione diventerebbe impraticabile dopo il primo shutdown pulito o
        // un semplice `Ctrl-C`.
        info!(
            "lockfile d'engine presente ma porta {} libera: engine non in \
             esecuzione, procedo con la rotazione",
            local_domain::TLS_PORT
        );
        let _ = local_domain::clear_engine_lock();
    }

    for p in [
        local_domain::ca_cert_path(),
        local_domain::ca_key_path(),
        local_domain::leaf_cert_path(),
        local_domain::leaf_key_path(),
    ] {
        let _ = std::fs::remove_file(p);
    }
    let _ = ensure_pki()?;
    Ok(())
}

/// `true` se qualcuno sta già in ascolto sulla porta TLS.
///
/// Si risponde a "lo slot è occupato?" tentando il bind: se riesce, la porta era
/// libera e il listener va rimesso giù subito. Non esiste un modo portable di
/// chiedere "c'è un ascoltatore?" senza risorse di sistema, e il bind è
/// l'unica prova disponibile.
///
/// Un falso positivo — porta occupata da un processo che non è l'engine — costa
/// un messaggio che chiede di liberare la porta. Un falso negativo non è
/// possibile in modo rilevante: se l'engine serve, tiene la porta.
fn tls_port_busy() -> bool {
    std::net::TcpListener::bind(("127.0.0.1", local_domain::TLS_PORT)).is_err()
}

/// Firma una nuova foglia con le SAN attuali usando la CA ricostruita dai PEM
/// su disco (`CertificateParams::from_ca_cert_pem` + stessa chiave): le
/// subject e la chiave pubblica restano quelle della CA già distribuita, quindi
/// chi si fida di quella CA continua a validare la nuova foglia.
fn sign_leaf_with_ca(
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> anyhow::Result<(rcgen::Certificate, KeyPair)> {
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let ca_keypair = KeyPair::from_pem(ca_key_pem)?;
    let ca_certificate = ca_params.self_signed(&ca_keypair)?;

    let mut leaf_params = CertificateParams::new(local_domain::leaf_sans())?;
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, local_domain::LOCAL_DOMAIN);
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_keypair = KeyPair::generate()?;
    let leaf_certificate = leaf_params.signed_by(&leaf_keypair, &ca_certificate, &ca_keypair)?;
    Ok((leaf_certificate, leaf_keypair))
}

/// Rigenera la **sola foglia** con le SAN attuali, firmata dalla CA già
/// esistente (che non cambia). È il caso intermedio fra "niente da fare"
/// e `--rotate-ca`: quando cambia l'IP di LAN o si aggiungono SAN senza
/// voler redistribuire la fiducia in tutta la LAN.
///
/// Rifiuta se un engine sta servendo TLS, con la stessa motivazione di
/// [`rotate_ca`]: il server presenta in memoria la foglia vecchia mentre il
/// pin dei nuovi QR verrebbe letto da disco — ogni pairing fallirebbe con un
/// errore che sembrerebbe un attacco.
///
/// Idempotente per la CA ([`ensure_pki`] prima, se la PKI non esiste ancora).
///
/// # Errors
/// `anyhow` su I/O profilo, lettura PEM o generazione cert.
pub fn refresh_leaf() -> anyhow::Result<()> {
    if local_domain::engine_lock_present() && tls_port_busy() {
        anyhow::bail!(
            "un engine è in esecuzione: la porta {} è occupata e il lockfile ({}) \
             è presente. Chiudi il desktop e riprova. Il refresh della sola foglia \
             è rifiutato perché, con l'engine attivo, i QR emessi avrebbero il pin \
             di un certificato che il server non sta presentando: ogni pairing \
             fallirebbe con un errore che sembrerebbe un attacco",
            local_domain::TLS_PORT,
            local_domain::engine_lock_path().display()
        );
    }
    if local_domain::engine_lock_present() {
        // Stessa logica di `rotate_ca`: un lockfile senza porta occupata è un
        // relitto di un shutdown (`SIGTERM` non pulisce), non un engine vivo.
        info!(
            "lockfile d'engine presente ma porta {} libera: engine non in \
             esecuzione, procedo col refresh della foglia",
            local_domain::TLS_PORT
        );
        let _ = local_domain::clear_engine_lock();
    }

    let _ = ensure_pki()?;
    let ca_cert = std::fs::read_to_string(local_domain::ca_cert_path())?;
    let ca_key = std::fs::read_to_string(local_domain::ca_key_path())?;
    let (leaf_certificate, leaf_keypair) = sign_leaf_with_ca(&ca_cert, &ca_key)?;

    write_private(
        &local_domain::leaf_key_path(),
        leaf_keypair.serialize_pem().as_bytes(),
    )?;
    std::fs::write(
        local_domain::leaf_cert_path(),
        leaf_certificate.pem().as_bytes(),
    )?;
    info!("Foglia rigenerata con le SAN attuali (CA invariata)");
    Ok(())
}

/// Garantisce che la PKI esista prima che qualcuno ne abbia bisogno.
///
/// Va chiamata **esplicitamente e in sequenza** prima di generare il QR di
/// pairing, non affidata al fatto che `serve_tls` la esegua. `serve_tls` gira in
/// un task concorrente allo `setup`, quindi senza questa chiamata il QR poteva
/// essere emesso mentre la foglia non esisteva ancora: il campo `tls_pin_b64`
/// veniva omesso (il QR resta valido, quindi nessun errore) e il telefono
/// degradava al canale in chiaro per tutta la sessione, finché l'utente non
/// avesse rigenerato il QR dalla tray.
///
/// Idempotente e economica: `ensure_pki` ritorna subito se i PEM ci sono già.
///
/// # Errors
/// `anyhow` su I/O profilo o generazione cert.
pub fn ensure_pki_ready() -> anyhow::Result<()> {
    ensure_pki()?;
    Ok(())
}

/// Config TLS 2026 del server: solo TLS 1.3 e `X25519MLKEM768` per primo.
///
/// Viene esposta come funzione pura (PEM → `ServerConfig`) perché i test
/// possano asserire la postura senza alzare un socket.
///
/// # Errors
/// `rustls::Error` se i PEM non sono leggibili o la coppia cert/chiave non
/// combacia.
fn rustls_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<rustls::ServerConfig, String> {
    let mut cert_rd = cert_pem;
    let certs = rustls_pemfile::certs(&mut cert_rd)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificato PEM: {e}"))?;
    if certs.is_empty() {
        return Err("il PEM del certificato non contiene chain".into());
    }
    let mut key_rd = key_pem;
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_rd)
        .next()
        .ok_or_else(|| "il PEM della chiave non contiene una PKCS#8".to_string())
        .and_then(|k| k.map_err(|e| format!("chiave PEM: {e}")))?;

    rustls::ServerConfig::builder_with_provider(Arc::new(provider::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("protocolli TLS: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::Pkcs8(key))
        .map_err(|e| format!("cert/chiave: {e}"))
}

/// Serve lo stesso Router su TLS `127.0.0.1:8443` (rustls, HSTS via docs).
///
/// # Errors
/// `anyhow` se la PKI manca, i PEM non si caricano o il bind fallisce.
pub async fn serve_tls(ctx: Arc<WsContext>) -> anyhow::Result<()> {
    let _ = ensure_pki()?;
    let cert_pem = std::fs::read(local_domain::leaf_cert_path())?;
    let key_pem = std::fs::read(local_domain::leaf_key_path())?;
    let server_config = rustls_server_config(&cert_pem, &key_pem).map_err(anyhow::Error::msg)?;
    let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));
    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], local_domain::TLS_PORT));
    let app = crate::ws_server::router(ctx);
    info!(%addr, "HTTPS/WSS (rustls, TLS 1.3 + X25519MLKEM768) su https://nfc.local:8443");
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// PKI locale (rcgen 0.13, API verificate)

fn ensure_pki() -> anyhow::Result<String> {
    let ca_cert = local_domain::ca_cert_path();
    let ca_key = local_domain::ca_key_path();
    let leaf_cert = local_domain::leaf_cert_path();
    let leaf_key = local_domain::leaf_key_path();
    for p in [&ca_cert, &ca_key, &leaf_cert, &leaf_key] {
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
    }
    if ca_cert.exists() && ca_key.exists() && leaf_cert.exists() && leaf_key.exists() {
        return Ok(format!(
            "PKI nfc.local pronta in {}",
            local_domain::profile_dir().display()
        ));
    }
    // Generazione atomica: la CA esiste solo come oggetto in memoria al momento
    // della firma (rcgen non ricarica CA cert da PEM per firmare dopo).
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(
        DnType::CommonName,
        "NFC Remote Local Root (nfc.local, non pubblica)",
    );
    ca_dn.push(
        DnType::OrganizationName,
        "NFC Remote (installazione locale)",
    );
    ca_params.distinguished_name = ca_dn;
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_keypair = KeyPair::generate()?;
    let ca_certificate = ca_params.self_signed(&ca_keypair)?;

    let mut leaf_params = CertificateParams::new(local_domain::leaf_sans())?;
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, local_domain::LOCAL_DOMAIN);
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_keypair = KeyPair::generate()?;
    let leaf_certificate = leaf_params.signed_by(&leaf_keypair, &ca_certificate, &ca_keypair)?;

    write_private(&ca_key, ca_keypair.serialize_pem().as_bytes())?;
    std::fs::write(&ca_cert, ca_certificate.pem().as_bytes())?;
    write_private(&leaf_key, leaf_keypair.serialize_pem().as_bytes())?;
    std::fs::write(&leaf_cert, leaf_certificate.pem().as_bytes())?;
    info!("PKI nfc.local generata (CA+foglia atomiche)");
    Ok(format!(
        "PKI nfc.local generata in {} (ridistribuisci la fiducia se è una rotazione)",
        local_domain::profile_dir().display()
    ))
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    // Windows: ACL utente via installer (setup script limita a CurrentUser).
    std::fs::write(path, bytes)?;
    Ok(())
}

fn print_hosts_and_trust() {
    println!("\n== 1. Risoluzione nfc.local ==");
    println!("  Su mobile/LAN: nessuna configurazione, l'engine annuncia nfc.local via mDNS.");
    println!("  ATTENZIONE mobile: Firefox non fa mDNS (Chrome Android sì): il DNS della LAN");
    println!("  risponde NXDOMAIN per nfc.local, quindi su Firefox usa l'URL a IP del desktop:");
    let lan =
        nfc_core::net::lan_ipv4().map_or_else(|| "127.0.0.1".to_string(), |ip| ip.to_string());
    println!(
        "    https://{lan}:8443/   (fallback senza mDNS; le IP-SAN sono incluse nella foglia)"
    );
    println!("  Su questo desktop servono invece i loopback, che già funzionano:");
    println!("    https://127.0.0.1:8443/   e   https://localhost:8443/");
    println!("    (il certificato include i SAN 127.0.0.1 e ::1)");
    println!("\n  Per far risolvere nfc.local anche sul desktop, esegui lo script:");
    println!(
        "    sudo {}",
        local_domain::profile_dir()
            .join("../../../scripts/setup-local-domain.sh")
            .display()
    );
    println!(
        "\n  Attenzione: su systemd con `nsswitch` = `hosts: ... resolve ... files ...`\n  \
         il modulo nss-resolve interroga systemd-resolved PRIMA di /etc/hosts, quindi\n  \
         la riga in hosts da sola non basta: va anche instradato .local su mDNS."
    );
    println!("\n== 2. Fiducia CA locale (UNA TANTUM, utente, niente admin su Win/macOS) ==");
    println!("  CA: {}", local_domain::ca_cert_path().display());
    println!(
        "  Windows: certutil -user -addstore Root <ca.pem>  (oppure scripts\\trust-ca-windows.ps1)"
    );
    println!(
        "  macOS:   security add-trusted-cert -k ~/Library/Keychains/login.keychain-db <ca.pem>"
    );
    println!(
        "  Linux:   sudo cp <ca.pem> /usr/local/share/ca-certificates/nfc-local-root.crt && sudo update-ca-certificates"
    );
    println!(
        "           + Firefox/Chrome-NSS: certutil -d sql:$HOME/.pki/nssdb -A -t C -n nfc-local-root -i <ca.pem>"
    );
    println!(
        "  Firefox: in alternativa about:config security.enterprise_roots.enabled=true (usa store OS)."
    );
    println!("\n== 3. Verifica ==");
    println!(
        "  curl --cacert {} https://nfc.local:8443/v1/status",
        local_domain::ca_cert_path().display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Genera una CA + foglia rcgen effimera (niente I/O) e asserisce la
    /// postura TLS 2026 del server **con handshake reali**: un client solo
    /// TLS 1.2 viene rifiutato, un client TLS 1.3 negozia TLS 1.3 con
    /// X25519MLKEM768 come primo gruppo di key exchange.
    ///
    /// A differenza del mobile, nel grafo del desktop `reqwest` (tauri updater)
    /// riattiva la feature `tls12` a compile-time: è questo test la barriera
    /// vera contro la re-negoziazione verso TLS 1.2, non la feature Cargo.
    #[test]
    fn server_2026_rifiuta_tls12_e_negozia_tls13_pq() {
        let ca_kp = rcgen::KeyPair::generate().expect("chiave CA");
        let leaf_kp = rcgen::KeyPair::generate().expect("chiave foglia");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca_params.self_signed(&ca_kp).expect("CA self-signed");
        let leaf_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_kp, &ca_cert, &ca_kp)
            .expect("foglia");

        let cert_pem = leaf_cert.pem();
        let key_pem = leaf_kp.serialize_pem().as_bytes().to_vec();
        let config = rustls_server_config(cert_pem.as_bytes(), &key_pem).expect("server config");

        assert_eq!(
            config.crypto_provider().kx_groups[0].name(),
            rustls::NamedGroup::X25519MLKEM768,
            "il server deve offrire X25519MLKEM768 per primo"
        );

        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = Arc::new(AcceptAll);
        for (nome, vers, atteso_ok) in [
            ("client solo TLS 1.2", 2, false),
            ("client TLS 1.2+1.3", 0, true),
            ("client solo TLS 1.3", 1, true),
        ] {
            let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_protocol_versions(&client_versions(vers))
            .expect("versioni client")
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
            let mut c = rustls::ClientConnection::new(
                Arc::new(client_cfg),
                rustls::pki_types::ServerName::try_from("localhost").expect("nome"),
            )
            .expect("client conn");
            let mut s =
                rustls::ServerConnection::new(Arc::new(config.clone())).expect("server conn");
            let esito = pump(&mut c, &mut s);
            assert_eq!(esito.is_ok(), atteso_ok, "{nome}: esito inatteso {esito:?}");
            if atteso_ok {
                assert_eq!(
                    c.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_3),
                    "{nome}: il server deve negoziare TLS 1.3"
                );
            }
        }

        // Il server deve restare utilizzabile con la via di `serve_tls`
        // (`RustlsConfig::from_config`): una `ServerConfig` non servibile
        // passerebbe i controlli sopra ma fermerebbe l'HTTPS vero.
        let _ = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));
    }

    /// La ri-firma con CA ricostruita dai PEM (`--refresh-leaf`) deve produrre
    /// una foglia che i client che si fidano della CA già distribuita validano,
    /// con le SAN attuali (dominio + IP di LAN): handshake reale contro un
    /// client che ha nel root store solo la CA.
    #[test]
    fn leaf_rifirmata_valida_col_root_store_della_ca() {
        let ca_kp = rcgen::KeyPair::generate().expect("chiave CA");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca = ca_params.self_signed(&ca_kp).expect("CA self-signed");

        let (leaf, leaf_kp) = sign_leaf_with_ca(&ca.pem(), &ca_kp.serialize_pem())
            .expect("ri-firma con CA ricostruita");
        let config =
            rustls_server_config(leaf.pem().as_bytes(), leaf_kp.serialize_pem().as_bytes())
                .expect("server config con la foglia rifirmata");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).expect("root store");
        let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&client_versions(1))
        .expect("versioni client")
        .with_root_certificates(roots)
        .with_no_client_auth();

        // Il nome DNS e, se l'host ha una rete, l'IP di LAN (SAN inclusa da
        // `leaf_sans()`): senza l'IP-SAN il secondo handshake fallirebbe.
        let mut nomi = vec!["nfc.local".to_string()];
        if let Some(ip) = nfc_core::net::lan_ipv4() {
            nomi.push(ip.to_string());
        }
        for nome in nomi {
            let mut c = rustls::ClientConnection::new(
                Arc::new(client_cfg.clone()),
                rustls::pki_types::ServerName::try_from(nome.clone()).expect("server name"),
            )
            .expect("client conn");
            let mut s =
                rustls::ServerConnection::new(Arc::new(config.clone())).expect("server conn");
            let esito = pump(&mut c, &mut s);
            assert!(
                esito.is_ok(),
                "l'handshake verso {nome} deve passare col root store della CA: {esito:?}"
            );
        }
    }

    /// Verificatore client che accetta ogni certificato (solo per il test:
    /// qui si testa la postura del **server**, non la fiducia del client).
    #[derive(Debug)]
    struct AcceptAll;

    impl rustls::client::danger::ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Versioni del client di test: 2 = solo TLS 1.2, 1 = solo TLS 1.3,
    /// altro = entrambi (i safe default di rustls; `tls12` è compilato nel
    /// grafo del desktop a causa di reqwest/updater).
    fn client_versions(solo: u8) -> Vec<&'static rustls::SupportedProtocolVersion> {
        match solo {
            2 => vec![&rustls::version::TLS12],
            1 => vec![&rustls::version::TLS13],
            _ => rustls::ALL_VERSIONS.to_vec(),
        }
    }

    /// Scambia i pacchetti TLS finché l'handshake non è completo.
    fn pump(
        c: &mut rustls::ClientConnection,
        s: &mut rustls::ServerConnection,
    ) -> Result<(), rustls::Error> {
        for _ in 0..32 {
            let mut to_s = Vec::new();
            let mut to_c = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut to_s)
                    .map_err(|e| rustls::Error::General(e.to_string()))?;
            }
            while s.wants_write() {
                s.write_tls(&mut to_c)
                    .map_err(|e| rustls::Error::General(e.to_string()))?;
            }
            if !to_s.is_empty() && s.wants_read() {
                s.read_tls(&mut to_s.as_slice())
                    .map_err(|e| rustls::Error::General(e.to_string()))?;
            }
            if !to_c.is_empty() && c.wants_read() {
                c.read_tls(&mut to_c.as_slice())
                    .map_err(|e| rustls::Error::General(e.to_string()))?;
            }
            s.process_new_packets()?;
            c.process_new_packets()?;
            if !c.is_handshaking() && !s.is_handshaking() {
                return Ok(());
            }
        }
        Err(rustls::Error::General(
            "handshake non completata in 32 round".into(),
        ))
    }
}
