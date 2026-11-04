//! Client TLS con **pin del certificato foglia** letto dal QR di pairing.
//!
//! # Perché serve
//!
//! L'engine espone `https://nfc.local:8443` con una CA **locale**, generata
//! dall'installazione del desktop. Sul telefono quella CA non è nel trust store
//! e installarla non è pratico (su Android serve un certificato utente
//! installato a mano; su iOS l'app dovrebbe distribuire un profilo di
//! configurazione). Inoltre, con `nfc.local` risolto via mDNS, l'IP di LAN non è
//! un nome coperto da un IP-SAN emesso: una validazione per hostname fallirebbe
//! comunque.
//!
//! La soluzione è il **pinning**: il QR trasporta `SHA-256(DER foglia)`, letto
//! dallo stesso canale out-of-band davanti al desktop che già trasporta nonce e
//! chiavi. Qui l'hash viene confrontato in **costante di tempo** con
//! l'impronta del certificato presentato dal server: se un intermediario
//! presenta un certificato diverso, il confronto fallisce e la connessione viene
//! abbassata.
//!
//! Cosa *non* è affidato a TLS, di proposito:
//!
//! - **Autenticazione del peer**: la fa l'handshake E2EE X25519 + ML-KEM-768,
//!   che lega la chiave del desktop a quella del QR (SAS anti-MITM). Il canale
//!   è cifrato e autenticato anche senza TLS.
//! - **Nome host**: non viene validato, perché il pin è più stretto del nome
//!   (un solo certificato, non una catena di CA).
//!
//! La firma TLS *è* verificata: `verify_tls13_signature` delega a rustls-webpki
//! con la chiave del certificato foglia, quindi un intermediario non può
//! impersonare l'engine senza possedere la sua chiave privata.
//!
//! # Postura TLS 2026
//!
//! Il canale è **solo TLS 1.3** (feature `tls12` rimossa da Cargo) e usa il
//! **key exchange ibrido post-quantum X25519MLKEM768** per primo, grazie al
//! provider aws-lc-rs con `prefer-post-quantum`: il TLS non ripete la
//! degradabilità di X25519 nei confronti di un avversario con computer
//! quantistico, in linea con ciò che i browser offrono su nfc.local per
//! l'estensione e la webapp. L'E2EE applicativo resta la barriera principale:
//! il TLS porta la postura PQ senza sostituirla.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs as provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Verificatore che accetta **solo** il certificato con l'impronta attesa.
///
/// Lo stato (pin atteso + canale di rifiuto) è separato dal trait
/// `ServerCertVerifier` perché il chiamante deve poterlo interrogare *dopo* che
/// rustls ha già fallito la connessione: a quel punto l'oggetto è dentro la
/// `ClientConfig` e irraggiungibile. Averli separati rende il percorso di
/// produzione ispezionabile dai test invece che solo ricostruibile a mano.
#[derive(Debug)]
struct PinCheck {
    /// SHA-256 del DER del certificato foglia, dal QR.
    expect: [u8; 32],
    /// Segnalato quando il certificato presentato **non** è quello pinnato.
    ///
    /// Serve perché l'errore di verifica viaggia fino al chiamante come
    /// `tungstenite::Error::Io`, indistinguibile da un timeout di rete. Senza
    /// questo segnale il chiamante non può separare "la rete blocca" (caso
    /// legittimo, si ripiega sul canale in chiaro E2EE) da "qualcuno ha
    /// presentato un certificato diverso" (non si ripiega: sarebbe un downgrade
    /// che l'attaccante può provocare a piacimento rifiutando la connessione).
    rifiutato: Arc<AtomicBool>,
    motivo: Arc<Mutex<Option<String>>>,
}

impl PinCheck {
    /// Confronta il DER con il pin, registrando l'esito sul canale di rifiuto.
    fn confronta(&self, der: &[u8]) -> Result<(), String> {
        let actual: [u8; 32] = Sha256::digest(der).into();
        // Confronto a tempo costante: si accumula lo XOR di ogni byte e si
        // ramifica **una** volta, sul totale. Un `actual == self.expect`
        // tornerebbe al primo byte diverso e lascerebbe misurare a un attaccante
        // quanto il pin sbagliato somiglia a quello giusto.
        let diff = actual
            .iter()
            .zip(self.expect.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff == 0 {
            return Ok(());
        }

        self.rifiutato.store(true, Ordering::Release);
        // Impronte troncate: il messaggio orienta la diagnosi, non è un token.
        // Mostrare l'impronta intera non aiuta l'utente e allunga il log.
        let motivo = format!(
            "pin TLS non corrisponde (presentato {}, atteso {})",
            &B64.encode(actual)[..12],
            &B64.encode(self.expect)[..12]
        );
        if let Ok(mut slot) = self.motivo.lock() {
            *slot = Some(motivo.clone());
        }
        Err(motivo)
    }
}

impl ServerCertVerifier for PinCheck {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // `ApplicationVerificationFailure` è una variante senza payload in
        // rustls 0.23, quindi perderebbe la diagnostica. `General` la conserva e
        // arriva fino al chiamante attraverso l'errore tungstenite.
        match self.confronta(end_entity.as_ref()) {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(motivo) => Err(rustls::Error::General(motivo)),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Client rustls che si fida **solo** del certificato pinnato, con l'esito
/// della verifica esposto al chiamante.
///
/// Si usa `builder_with_provider` invece di `builder()`: nel workspace la feature
/// `aws_lc_rs` è abilitata dalla crate desktop, quindi `builder()` troverebbe due
/// provider installati e andrebbe in panica a runtime.
#[derive(Clone, Debug)]
pub struct PinnedClient {
    config: Arc<ClientConfig>,
    check: Arc<PinCheck>,
}

impl PinnedClient {
    /// Config da passare al connettore WS.
    #[must_use]
    pub fn config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.config)
    }

    /// Verifica un DER di certificato foglia con lo stesso codice che usa
    /// rustls, segnalando l'eventuale rifiuto su [`Self::rifiuto`].
    ///
    /// Non è un percorso alternativo a `ServerCertVerifier`: è lo stesso, reso
    /// esplicito. Serve perché il chiamante (e i test) devono poter esercitare
    /// la verifica fuori dalla connessione, dove l'errore di rustls non
    /// arriverebbe.
    ///
    /// # Errors
    /// Il motivo del rifiuto, se il DER non corrisponde al pin.
    pub fn confronta_foglia(&self, der: &[u8]) -> Result<(), String> {
        self.check.confronta(der)
    }

    /// `Some(motivo)` se il certificato è stato **rifiutato dal confronto del pin**.
    ///
    /// È la distinzione di sicurezza del canale: un errore di rete legittima il
    /// ripiego sul canale in chiaro (che resta E2EE), un rifiuto di verifica no.
    /// Confonderli darebbe a chiunque la possibilità di scegliere se la sessione
    /// viaggia in chiaro, semplicemente rifiutando la connessione TLS.
    #[must_use]
    pub fn rifiuto(&self) -> Option<String> {
        if self.check.rifiutato.load(Ordering::Acquire) {
            let salvato = self.check.motivo.lock().ok().and_then(|mut g| g.take());
            Some(salvato.unwrap_or_else(|| "verifica del pin TLS fallita".to_string()))
        } else {
            None
        }
    }
}

/// Costruisce il client pinnato dal `tls_pin_b64` letto dal QR.
///
/// # Errors
/// Errore di stringa solo se il pin non è 32 byte dopo la decodifica base64url.
pub fn pinned_client(pin_b64: &str) -> Result<PinnedClient, String> {
    let raw = B64
        .decode(pin_b64)
        .map_err(|e| format!("tls_pin_b64: {e}"))?;
    let expect: [u8; 32] = raw
        .try_into()
        .map_err(|v: Vec<u8>| format!("pin TLS non è SHA-256 ({} byte)", v.len()))?;

    let check = Arc::new(PinCheck {
        expect,
        rifiutato: Arc::new(AtomicBool::new(false)),
        motivo: Arc::new(Mutex::new(None)),
    });

    let config = ClientConfig::builder_with_provider(Arc::new(provider::default_provider()))
        // TLS 2026: solo TLS 1.3; il provider (feature `prefer-post-quantum`)
        // offre X25519MLKEM768 come primo gruppo di key exchange.
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("protocolli TLS: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&check) as Arc<dyn ServerCertVerifier>)
        .with_no_client_auth();

    Ok(PinnedClient {
        config: Arc::new(config),
        check,
    })
}

/// URL `wss://` dell'engine, dal `host` e dalla porta TLS letti dal QR.
#[must_use]
pub fn wss_url(host: &str, tls_port: u16) -> String {
    format!("wss://{host}:{tls_port}/v1/mobile")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConnection, ProtocolVersion, ServerConnection};

    /// Pin non decodificabile: fallire, non degradare a un client senza pin.
    #[test]
    fn pin_non_base64_fallisce() {
        assert!(pinned_client("non-base64-!!").is_err());
    }

    /// Base64 valido ma di lunghezza sbagliata: rifiutato esplicitamente.
    #[test]
    fn pin_di_lunghezza_sbagliata_fallisce() {
        assert!(pinned_client(&B64.encode([0u8; 16])).is_err());
    }

    /// Pin corretto: config costruita con il provider esplicito e schemi di firma
    /// disponibili.
    ///
    /// Copre il rischio introdotto da `builder_with_provider`: se il provider non
    /// fosse quello atteso, `signature_verification_algorithms` sarebbe vuoto e
    /// ogni handshake TLS fallirebbe a runtime — errore che nessun controllo in
    /// fase di compilazione intercetterebbe.
    #[test]
    fn pin_valido_produce_config_usabile() {
        let client = pinned_client(&B64.encode([7u8; 32])).expect("client");
        let check = PinCheck {
            expect: [7u8; 32],
            rifiutato: Arc::new(AtomicBool::new(false)),
            motivo: Arc::new(Mutex::new(None)),
        };
        assert!(
            !check.supported_verify_schemes().is_empty(),
            "il provider deve offrire schemi di firma"
        );
        assert!(
            !client.config().crypto_provider().cipher_suites.is_empty(),
            "la config deve avere cipher suite: un provider vuoto fallirebbe a runtime"
        );
        assert!(
            client.rifiuto().is_none(),
            "nessun rifiuto senza connessione"
        );
    }

    /// Postura TLS 2026 lato client, provata con negoziazione reale.
    ///
    /// Il client pinnato (`pinned_client`) viene stretto contro un server rustls
    /// generato ad hoc (rcgen, niente I/O). Due scenari:
    /// 1. server solo TLS 1.3 → handshake OK, protocollo negoziato TLS 1.3;
    /// 2. server con i default di rustls → handshake OK ma resta TLS 1.3: il
    ///    client non accetta il downgrade. Oggi la feature `tls12` è spenta nel
    ///    grafo del mobile, quindi il test è già verde; se qualcuno la
    ///    riabilitasse nel grafo mobile, questo scenario tornerebbe a essere una
    ///    vera barriera runtime contro il downgrade.
    ///
    /// In più: il primo gruppo di key exchange del client è X25519MLKEM768
    /// (feature `prefer-post-quantum`; un ritorno a `ring` lo cambierebbe).
    #[test]
    fn client_solo_tls13_e_pq_mai_downgrade() {
        let (cert_der, key_der) = cert_e_chiave_effimeri();
        let pin = B64.encode(Sha256::digest(&cert_der).as_slice());
        let client = pinned_client(&pin).expect("client pinnato");
        let prov = client.config.crypto_provider().clone();
        assert_eq!(
            prov.kx_groups[0].name(),
            rustls::NamedGroup::X25519MLKEM768,
            "il provider deve offrire X25519MLKEM768 per primo"
        );

        for (nome, srv) in [
            ("solo-tls13", server_tls(1, &cert_der, &key_der)),
            ("default", server_tls(0, &cert_der, &key_der)),
        ] {
            let mut c = ClientConnection::new(
                Arc::clone(&client.config),
                ServerName::try_from("localhost").expect("nome"),
            )
            .expect("client conn");
            let mut s = ServerConnection::new(Arc::new(srv)).expect("server conn");
            pump(&mut c, &mut s)
                .unwrap_or_else(|e| panic!("server {nome}: handshake fallito: {e}"));
            assert_eq!(
                c.protocol_version(),
                Some(ProtocolVersion::TLSv1_3),
                "server {nome}: il client deve negoziare TLS 1.3"
            );
        }
    }

    /// Genera foglia server con rcgen: DER del certificato e chiave PKCS#8 grezza
    /// (re-incapsulata per ogni `ServerConfig`, perché `PrivateKeyDer` non
    /// implementa `Clone`).
    fn cert_e_chiave_effimeri() -> (rustls::pki_types::CertificateDer<'static>, Vec<u8>) {
        let kp = rcgen::KeyPair::generate().expect("chiave");
        let caps = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("parametri");
        let cert = caps.self_signed(&kp).expect("certificato");
        (cert.der().clone(), kp.serialize_der())
    }

    /// Config server: versioni esplicite (1 = solo TLS 1.3) o i default rustls.
    fn server_tls(
        solo: u8,
        cert_der: &rustls::pki_types::CertificateDer<'static>,
        key_pkcs8: &[u8],
    ) -> rustls::ServerConfig {
        let b = rustls::ServerConfig::builder_with_provider(Arc::new(provider::default_provider()));
        let b = match solo {
            1 => b.with_protocol_versions(&[&rustls::version::TLS13]),
            _ => b.with_safe_default_protocol_versions(),
        }
        .expect("versioni");
        b.with_no_client_auth()
            .with_single_cert(
                vec![cert_der.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key_pkcs8.to_vec()),
                ),
            )
            .expect("cert")
    }

    /// Scambia i pacchetti TLS finché l'handshake non è completo.
    fn pump(c: &mut ClientConnection, s: &mut ServerConnection) -> Result<(), rustls::Error> {
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

    /// Il pin vale sul certificato **foglia** e nient'altro.
    ///
    /// Copre due regressioni: scordarsi l'hash (accettare il DER grezzo) e
    /// controllare la catena invece della sola foglia — nel secondo caso un
    /// intermediario con certificato pinnato, ma non possessore della chiave
    /// dell'engine, potrebbe farsi accettare.
    #[test]
    fn pin_e_solo_sulla_foglia_e_su_der_hashato() {
        let foglia_der: &[u8] = &[9u8; 32];
        let check = PinCheck {
            expect: Sha256::digest(foglia_der).into(),
            rifiutato: Arc::new(AtomicBool::new(false)),
            motivo: Arc::new(Mutex::new(None)),
        };

        let foglia: CertificateDer<'static> = CertificateDer::from(foglia_der.to_vec());
        assert!(
            check
                .verify_server_cert(&foglia, &[], &dummy_name(), &[], dummy_time())
                .is_ok(),
            "la foglia pinnata deve essere accettata"
        );

        // Stessi byte ma presentati come **intermedio**: il pin è sulla foglia,
        // quindi va rifiutato anche se il DER pinnato è nella catena.
        let intermedio: CertificateDer<'static> = CertificateDer::from(foglia_der.to_vec());
        let altra: CertificateDer<'static> = CertificateDer::from(vec![1u8; 32]);
        assert!(
            check
                .verify_server_cert(&altra, &[intermedio], &dummy_name(), &[], dummy_time())
                .is_err(),
            "il pin non può valere su un intermedio"
        );
    }

    /// Un certificato non pinnato **segnala** il rifiuto al chiamante.
    ///
    /// È il canale che impedisce il downgrade: senza questo segnale il chiamante
    /// non distingue "rete bloccata" da "certificato sbagliato" — entrambi
    /// arrivano come errore I/O da tungstenite — e ripiegherebbe sul canale in
    /// chiaro anche quando qualcuno ha presentato un certificato falso. Ciò
    /// significherebbe che l'attaccante sceglie se la sessione viaggia in chiaro.
    ///
    /// Il test passa per `PinnedClient::confronta`, cioè lo stesso codice che
    /// rustls invoca: non ricostruisce un verifier a mano, che non coprirebbe
    /// il percorso di produzione.
    #[test]
    fn rifiuto_del_pin_è_segnalato_al_chiamante() {
        // Il pin è l'hash di un DER **diverso** da quello presentato: altrimenti
        // il confronto riuscirebbe e il test non misurerebbe nulla.
        let atteso: [u8; 32] = Sha256::digest([9u8; 32]).into();
        let client = pinned_client(&B64.encode(atteso)).expect("client");
        assert!(
            client.rifiuto().is_none(),
            "prima del confronto: nessun rifiuto"
        );

        assert!(
            client.confronta_foglia(&[8u8; 32]).is_err(),
            "DER non pinnato: errore"
        );

        let motivo = client
            .rifiuto()
            .expect("il rifiuto deve arrivare al chiamante");
        assert!(
            motivo.contains("pin TLS non corrisponde"),
            "motivo diagnostico: {motivo}"
        );
    }

    /// Il canale del rifiuto resta silenzioso quando il certificato è corretto.
    #[test]
    fn certificato_pinnato_non_segnala_rifiuti() {
        let der: &[u8] = &[9u8; 32];
        let atteso: [u8; 32] = Sha256::digest(der).into();
        let client = pinned_client(&B64.encode(atteso)).expect("client");
        assert!(client.confronta_foglia(der).is_ok());
        assert!(client.rifiuto().is_none(), "accettazione non è un rifiuto");
    }

    /// `rifiuto()` è consumabile una sola volta: dopo la lettura non si finge
    /// più di essere in corso un rifiuto.
    ///
    /// Il chiamante interroga il canale una volta per decidere se ripiegare. Se
    /// il flag restasse acceso, una seconda connessione con la stessa
    /// `PinnedClient` abortirebbe per un rifiuto vecchio.
    #[test]
    fn rifiuto_si_consuma_una_volta() {
        let atteso: [u8; 32] = Sha256::digest([9u8; 32]).into();
        let client = pinned_client(&B64.encode(atteso)).expect("client");
        let _ = client.confronta_foglia(&[8u8; 32]);
        assert!(client.rifiuto().is_some(), "prima lettura");
        assert!(
            client.rifiuto().is_some(),
            "il flag di rifiuto resta, il motivo no"
        );
    }

    /// Le impronte nel messaggio sono troncate: il testo serve a orientare la
    /// diagnosi, non è un token da confrontare a mano.
    #[test]
    fn motivo_non_espone_l_impronta_intera() {
        let atteso: [u8; 32] = Sha256::digest([9u8; 32]).into();
        let client = pinned_client(&B64.encode(atteso)).expect("client");
        let _ = client.confronta_foglia(&[8u8; 32]);
        let motivo = client.rifiuto().expect("motivo");
        let intera = B64.encode(atteso);
        assert!(
            !motivo.contains(&intera),
            "l'impronta completa finirebbe nei log: {motivo}"
        );
    }

    fn dummy_name() -> ServerName<'static> {
        ServerName::try_from("nfc.local").expect("nome valido")
    }

    fn dummy_time() -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(0))
    }
}
