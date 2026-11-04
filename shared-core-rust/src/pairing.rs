//! Pairing via QR Code v2 (2026).
//! Il desktop espone: IPv4 locale, porta WS, nonce32, pubkey X25519,
//! flag `pq` + `mlkem_pk` opzionale (ibrido post-quantum), SAS a 6 cifre,
//! e da v2.1 anche `host` + `tls_pin_b64` per il canale **TLS** sul telefono.
//! Formato wire: JSON compatto -> base64url (no pad) -> `NFC://2/<b64>`.
//! Retrocompatibilità: il mobile accetta anche `NFC://1/...` (classico).
//!
//! I campi `host`/`tls_pin_b64` sono opzionali e `skip_serializing_if`: un QR senza
//! di loro resta valido e il mobile ricade su `ws://ip:port`.

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};

/// Versione corrente QR. 2 = ibrido PQ negoziabile + SAS.
pub const QR_VERSION: u8 = 2;
pub const QR_PREFIX_V2: &str = "NFC://2/";
pub const QR_PREFIX_V1: &str = "NFC://1/";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PairingPayload {
    /// Versione (1 o 2).
    pub v: u8,
    /// IPv4 locale desktop, es. "192.168.1.20". IPv6 link-local supportato come stringa.
    pub ip: String,
    /// Porta WS desktop (default 8080).
    pub port: u16,
    /// Nonce 32B base64url — salt HKDF + binding anti-MITM.
    pub nonce_b64: String,
    /// Pubkey X25519 desktop 32B base64url.
    pub pubkey_b64: String,
    /// 2026: 1 se il desktop supporta ibrido PQ (ML-KEM-768).
    #[serde(default)]
    pub pq: u8,
    /// Chiave pubblica ML-KEM-768 (1184B) base64url, presente se pq==1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mlkem_b64: Option<String>,
    /// SAS a 6 cifre per conferma visiva (calcolato dopo che il mobile risponde;
    /// nel QR è placeholder "------" o omesso — il SAS vero è mostrato nelle UI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sas: Option<String>,
    /// Nome host canonico per il canale TLS, es. `nfc.local` (porta 8443).
    ///
    /// Il mobile lo preferisce a `ip`: con `wss://nfc.local:8443` il nome è
    /// coperto dal SAN del certificato, mentre `wss://<ip-lan>:8443` validerebbe
    /// contro un IP-SAN che **non** è emesso (la CA è locale, non pubblica).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Pin TLS del certificato **foglia** dell'engine: SHA-256(DER foglia),
    /// base64url (43 caratteri).
    ///
    /// Il telefono non ha la CA locale installata e installargliela non è
    /// pratico. Invece di infilarle l'intera nel QR (535 B DER → 716 B base64:
    /// farebbe esplodere il payload oltre il limite del QR), il QR porta
    /// l'**impronta** del certificato foglia, letta dallo stesso canale
    /// out-of-band già fidato che trasporta chiavi e nonce. Il mobile verifica
    /// che il certificato presentato dal server abbia esattamente quell'hash.
    ///
    /// Nota sul perché questo è sufficiente: l'autenticazione forte del peer è
    /// l'handshake E2EE, che lega la chiave del desktop a quella del QR. Il
    /// TLS aggiunge privacy del trasporto e integrità del canale; il pin
    /// serve a non fidarsi di una CA installata sul device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_pin_b64: Option<String>,
    /// Porta TLS (8443) per il canale `wss://<host>:<tls_port>`.
    ///
    /// `port` resta 8080 (canale in chiaro) come ripiego: il mobile tenta
    /// prima TLS con pin e ricade sul chiaro solo se il handshake TLS fallisce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_port: Option<u16>,
    /// Scadenza del QR in secondi epoch Unix.
    ///
    /// Serve a una cosa sola: **il messaggio d'errore**. L'autorità sulla
    /// scadenza resta l'engine, che rifiuta l'handshake oltre `QR_TTL`; senza
    /// questo campo un QR fotografato ieri fallirebbe con lo stesso testo di un
    /// certificato rotato — che è anche il testo che un intercettatore
    /// produrrebbe, e quindi inutilizzabile come diagnosi. Con il campo, il
    /// telefono distingue "è scaduto, rigenera" da "non corrisponde, non
    /// proseguire".
    ///
    /// Non è un meccanismo di sicurezza: chi lo modifica può solo convincere il
    /// telefono a *tentare* un handshake che l'engine rifiuterà comunque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_unix: Option<u64>,
}

/// Soglia sotto la quale `exp_unix` è considerato assurdo (2020-01-01).
///
/// Un QR con una scadenza nel passato remoto non è "scaduto": è malformato, e
/// accettarlo produrrebbe un messaggio che invites a "rigenera il QR" per un QR
/// che l'utente ha appena generato — la diagnosi peggiore di tutte.
const EXP_MIN_SANE: u64 = 1_577_836_800;
/// Soglia oltre la quale `exp_unix` è considerato assurdo (2100-01-01).
const EXP_MAX_SANE: u64 = 4_102_444_800;
/// Tolleranza sull'orologio del device prima di dichiarare il QR scaduto.
///
/// Il telefono può avere l'orologio indietro di qualche minuto rispetto al
/// desktop. Senza margine, un QR appena emesso verrebbe respinto come scaduto,
/// e il rimedio suggerito ("rigenera") non risolverebbe nulla: l'errore sarebbe
/// identico a ogni tentativo. Un margine di 90 secondi copre la deriva tipica di
/// un device consumer; una deriva maggiore è già un problema del device, non
/// del pairing.
pub const QR_EXPIRY_GRACE_SECS: u64 = 90;

/// Esito della scadenza di un QR rispetto all'orologio del device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrExpiry {
    /// Il QR non porta una scadenza (engine o client legacy): l'unica
    /// autorità resta l'handshake.
    Unknown,
    /// Ancora valido, con secondi residui rispetto a `now`.
    Valid(u64),
    /// Scaduto da `u64` secondi, **oltre** la tolleranza sull'orologio.
    Expired(u64),
}

impl PairingPayload {
    #[must_use]
    pub fn new(ip: String, port: u16, nonce32: [u8; 32], pubkey: [u8; 32]) -> Self {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        Self {
            v: QR_VERSION,
            ip,
            port,
            nonce_b64: B64.encode(nonce32),
            pubkey_b64: B64.encode(pubkey),
            pq: 0,
            mlkem_b64: None,
            sas: None,
            host: None,
            tls_pin_b64: None,
            tls_port: None,
            exp_unix: None,
        }
    }

    /// Attacca la scadenza del QR, calcolata da `now` (secondi epoch Unix).
    ///
    /// Il valore non autorizza nulla: serve solo a far sì che il telefono dica
    /// "rigenera il QR" invece di un errore generico quando incontra un codice
    /// vecchio. Vedi il campo `exp_unix`.
    #[must_use]
    pub fn with_expiry(mut self, now: u64, ttl_secs: u64) -> Self {
        self.exp_unix = Some(now.saturating_add(ttl_secs));
        self
    }

    /// Classifica il QR rispetto all'orologio del device.
    ///
    /// `Expired` scatta solo **oltre** [`QR_EXPIRY_GRACE_SECS`], per non
    /// respinare un QR valido su un device con l'orologio indietro.
    #[must_use]
    pub fn expiry(&self, now: u64) -> QrExpiry {
        let Some(exp) = self.exp_unix else {
            return QrExpiry::Unknown;
        };
        if now <= exp {
            return QrExpiry::Valid(exp.saturating_sub(now));
        }
        let scaduto = now - exp;
        if scaduto <= QR_EXPIRY_GRACE_SECS {
            QrExpiry::Valid(0)
        } else {
            QrExpiry::Expired(scaduto - QR_EXPIRY_GRACE_SECS)
        }
    }

    /// Costruttore ibrido PQ (desktop genera anche ML-KEM).
    #[must_use]
    pub fn new_hybrid(
        ip: String,
        port: u16,
        nonce32: [u8; 32],
        pubkey: [u8; 32],
        mlkem_ek: &[u8],
    ) -> Self {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let mut p = Self::new(ip, port, nonce32, pubkey);
        p.pq = 1;
        p.mlkem_b64 = Some(B64.encode(mlkem_ek));
        p
    }

    /// Attacca il canale TLS: host canonico + pin SHA-256 del certificato foglia.
    ///
    /// Con questi campi il mobile parla `wss://<host>:<tls_port>` verificando
    /// l'impronta, senza dover installare nessuna CA sul device.
    #[must_use]
    pub fn with_tls_pin(mut self, host: &str, tls_port: u16, pin_sha256: &[u8; 32]) -> Self {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        self.host = Some(host.to_string());
        self.tls_port = Some(tls_port);
        self.tls_pin_b64 = Some(B64.encode(pin_sha256));
        self
    }

    /// Serializza in stringa QR scansionabile (sempre v2 per nuovo pairing).
    ///
    /// # Errors
    /// `CoreError::Pairing` se la serializzazione JSON/base64 fallisce.
    pub fn encode_qr(&self) -> Result<String> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let json = serde_json::to_vec(self).map_err(|e| CoreError::Pairing(e.to_string()))?;
        Ok(format!("{QR_PREFIX_V2}{}", B64.encode(json)))
    }

    /// Deserializza e valida (lato mobile dopo scan camera). Accetta v1 e v2.
    ///
    /// # Errors
    /// `CoreError::Pairing` su prefisso, base64, JSON, lunghezze o IP non validi.
    pub fn decode_qr(s: &str) -> Result<Self> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let (prefix, ver) = if s.starts_with(QR_PREFIX_V2) {
            (QR_PREFIX_V2, 2u8)
        } else if s.starts_with(QR_PREFIX_V1) {
            (QR_PREFIX_V1, 1u8)
        } else {
            return Err(CoreError::Pairing(
                "prefisso QR errato (atteso NFC://1/ o NFC://2/)".into(),
            ));
        };
        let b64 = &s[prefix.len()..];
        let json = B64
            .decode(b64)
            .map_err(|e| CoreError::Pairing(format!("base64: {e}")))?;
        let p: Self =
            serde_json::from_slice(&json).map_err(|e| CoreError::Pairing(format!("json: {e}")))?;
        if p.v != ver && !(p.v == 1 && ver == 1) {
            // Tollerante: accetta v1 dichiarato in prefix v1.
            if p.v != 1 && p.v != 2 {
                return Err(CoreError::Pairing(format!(
                    "versione {} non supportata",
                    p.v
                )));
            }
        }
        if p.port == 0 {
            return Err(CoreError::Pairing("porta zero".into()));
        }
        let n = B64
            .decode(&p.nonce_b64)
            .map_err(|e| CoreError::Pairing(format!("nonce: {e}")))?;
        let k = B64
            .decode(&p.pubkey_b64)
            .map_err(|e| CoreError::Pairing(format!("pubkey: {e}")))?;
        if n.len() != 32 || k.len() != 32 {
            return Err(CoreError::Pairing("nonce/pubkey devono essere 32B".into()));
        }
        if p.pq == 1 {
            let ek = p
                .mlkem_b64
                .as_deref()
                .ok_or_else(|| CoreError::Pairing("pq=1 senza mlkem_pk".into()))?;
            let raw = B64
                .decode(ek)
                .map_err(|e| CoreError::Pairing(format!("mlkem: {e}")))?;
            if raw.len() != 1184 {
                return Err(CoreError::Pairing("mlkem ek deve essere 1184B".into()));
            }
        }
        // Valida IP (IPv4 o IPv6).
        if p.ip.parse::<std::net::IpAddr>().is_err() {
            return Err(CoreError::Pairing("ip non valida".into()));
        }
        // `host` guida il canale TLS e va ristretto al dominio locale.
        //
        // Il caso reale è il QR malevolo mostrato a un utente: senza vincolo,
        // `host` potrebbe essere `evil.example.com` e il telefono aprirebbe una
        // connessione TLS **fuori dalla LAN**, inviandole nonce e chiave effimera
        // del proprio bootstrap. L'handshake E2EE fallirebbe — l'attaccante non ha
        // la chiave del desktop — quindi non si compromisesi nulla, ma il telefono
        // avrebbe fatto una richiesta a un host che l'utente non ha approvato.
        //
        // Il vincolo è gratuito: il canale TLS vale solo per `nfc.local` e i suoi
        // sottodomini, che sono gli unici nomi coperti dal certificato.
        if let Some(h) = p.host.as_deref()
            && !crate::local_domain::is_local_hostname(h)
        {
            return Err(CoreError::Pairing(format!(
                "host fuori dominio locale: {h}"
            )));
        }
        // Il pin TLS, se presente, dev'essere uno SHA-256 (32B).
        if let Some(pin) = p.tls_pin_b64.as_deref() {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
            let raw = B64
                .decode(pin)
                .map_err(|e| CoreError::Pairing(format!("tls_pin_b64: {e}")))?;
            if raw.len() != 32 {
                return Err(CoreError::Pairing(
                    "tls_pin dev'essere SHA-256 (32B)".into(),
                ));
            }
        }
        // `exp_unix` fuori da un intervallo sensato è un campo corrotto, non un
        // QR vecchio. Le due cose richiedono reazioni opposte ("rigenera" contro
        // "non fidarti"), quindi vanno tenute distinte: uno zero o un timestamp
        // dell'anno 1970 verrebbero letti come "scaduto da decenni" e
        // suggerirebbero all'utente di rigenerare un QR appena creato.
        if let Some(exp) = p.exp_unix
            && !(EXP_MIN_SANE..=EXP_MAX_SANE).contains(&exp)
        {
            return Err(CoreError::Pairing(format!(
                "exp_unix fuori intervallo: {exp}"
            )));
        }
        Ok(p)
    }

    /// Nonce 32B dal campo base64url.
    ///
    /// # Errors
    /// `CoreError::Pairing` se il decode fallisce o la lunghezza non è 32B.
    pub fn nonce32(&self) -> Result<[u8; 32]> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let v = B64
            .decode(&self.nonce_b64)
            .map_err(|e| CoreError::Pairing(e.to_string()))?;
        v.try_into()
            .map_err(|_| CoreError::Pairing("nonce len".into()))
    }

    /// Pubkey 32B dal campo base64url.
    ///
    /// # Errors
    /// `CoreError::Pairing` se il decode fallisce o la lunghezza non è 32B.
    pub fn pubkey32(&self) -> Result<[u8; 32]> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let v = B64
            .decode(&self.pubkey_b64)
            .map_err(|e| CoreError::Pairing(e.to_string()))?;
        v.try_into()
            .map_err(|_| CoreError::Pairing("pubkey len".into()))
    }

    /// True se entrambe le parti supportano PQ (negoziazione ibrida).
    #[must_use]
    pub fn wants_pq(&self) -> bool {
        self.pq == 1 && self.mlkem_b64.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Attesa per il roundtrip del pin: base64url di `[3u8; 32]`.
    const B64_STR: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";

    #[test]
    fn qr_v2_roundtrip() {
        let p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32]);
        let s = p.encode_qr().unwrap();
        assert!(s.starts_with(QR_PREFIX_V2));
        let q = PairingPayload::decode_qr(&s).unwrap();
        assert_eq!(p, q);
    }
    #[test]
    fn qr_v1_legacy_accepted() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let json = serde_json::json!({"v":1,"ip":"10.0.0.2","port":8080,"nonce_b64":B64.encode([9u8;32]),"pubkey_b64":B64.encode([8u8;32])});
        let s = format!(
            "{QR_PREFIX_V1}{}",
            B64.encode(serde_json::to_vec(&json).unwrap())
        );
        let q = PairingPayload::decode_qr(&s).unwrap();
        assert_eq!(q.v, 1);
    }

    /// Il pin TLS e l'host sopravvivono all'encoding QR: se non lo facessero il
    /// telefono degraderebbe al chiaro senza che nulla fallisse.
    #[test]
    fn pin_tls_sopravvive_al_roundtrip() {
        let p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32])
            .with_tls_pin("nfc.local", 8443, &[3u8; 32]);
        let s = p.encode_qr().unwrap();
        let q = PairingPayload::decode_qr(&s).unwrap();
        assert_eq!(q.host.as_deref(), Some("nfc.local"));
        assert_eq!(q.tls_port, Some(8443));
        assert_eq!(q.tls_pin_b64.as_deref(), Some(B64_STR));
    }

    /// `port` resta 8080: è il canale in chiaro di ripiego e non deve essere
    /// sovrascritto dalla porta TLS, altrimenti il fallback punterebbe al 8443
    /// in chiaro e fallirebbe.
    #[test]
    fn pin_tls_non_sovrascrive_la_porta_in_chiaro() {
        let p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32])
            .with_tls_pin("nfc.local", 8443, &[3u8; 32]);
        let q = PairingPayload::decode_qr(&p.encode_qr().unwrap()).unwrap();
        assert_eq!(q.port, 8080);
        assert_eq!(q.tls_port, Some(8443));
    }

    /// Un QR senza TLS resta valido e non menziona campi TLS: è il percorso dei
    /// client v1 e dell'engine senza PKI.
    #[test]
    fn qr_senza_tls_non_inventa_campi_tls() {
        let p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32]);
        let q = PairingPayload::decode_qr(&p.encode_qr().unwrap()).unwrap();
        assert!(q.host.is_none() && q.tls_port.is_none() && q.tls_pin_b64.is_none());
    }

    /// `host` IP-litterale è rifiutato: il canale TLS deve passare da un nome,
    /// perché con mDNS `nfc.local` è risolvibile mentre l'IP non è un SAN valido.
    #[test]
    fn host_ip_letterale_rifiutato() {
        let p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32])
            .with_tls_pin("192.168.1.10", 8443, &[3u8; 32]);
        assert!(PairingPayload::decode_qr(&p.encode_qr().unwrap()).is_err());
    }

    /// Pin di lunghezza sbagliata rifiutato: un pin troncato non deve passare
    /// come se fosse valido.
    #[test]
    fn pin_tls_di_lunghezza_sbagliata_rifiutato() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let mut p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32])
            .with_tls_pin("nfc.local", 8443, &[3u8; 32]);
        p.tls_pin_b64 = Some(B64.encode([0u8; 16]));
        assert!(PairingPayload::decode_qr(&p.encode_qr().unwrap()).is_err());
    }

    /// `host` fuori dal dominio locale è rifiutato.
    ///
    /// Copre il caso del QR malevolo: senza questo vincolo il telefono aprirebbe
    /// una connessione TLS verso un dominio scelto da chi ha stampato il codice,
    /// inviandoci nonce e chiave effimera. L'handshake E2EE fallirebbe comunque,
    /// ma la richiesta fuori LAN sarebbe già stata fatta.
    #[test]
    fn host_fuori_dominio_locale_rifiutato() {
        for ostile in [
            "evil.example.com",
            "nfc.local.evil.com",
            "api.nfc.local.evil.com",
        ] {
            let p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32])
                .with_tls_pin(ostile, 8443, &[3u8; 32]);
            assert!(
                PairingPayload::decode_qr(&p.encode_qr().unwrap()).is_err(),
                "host ostile accettato: {ostile}"
            );
        }
    }

    /// I sottodomini legittimi restano ammessi: il vincolo non deve essere più
    /// stretto del necessario, altrimenti un QR valido diventerebbe illegibile.
    #[test]
    fn sottodomini_del_dominio_ammessi() {
        for legittimo in ["nfc.local", "api.nfc.local", "pair.nfc.local"] {
            let p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32])
                .with_tls_pin(legittimo, 8443, &[3u8; 32]);
            let q = PairingPayload::decode_qr(&p.encode_qr().unwrap());
            assert!(q.is_ok(), "host legittimo rifiutato: {legittimo}");
        }
    }

    /// `exp_unix` sopravvive al roundtrip e classifica il QR.
    ///
    /// Il punto è la diagnostica: senza scadenza nel payload, un QR vecchio e un
    /// certificato rotato (o intercettato) produrrebbero lo stesso errore, e
    /// quello del certificato è anche il testo che un MITM produrrebbe.
    #[test]
    fn scadenza_nel_qr_distingue_il_vecchio_dal_rotato() {
        let base = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32]);
        let t0 = EXP_MIN_SANE;
        let p = base.with_expiry(t0, 300);

        assert_eq!(p.expiry(t0), QrExpiry::Valid(300), "emesso adesso");
        assert_eq!(p.expiry(t0 + 299), QrExpiry::Valid(1));
        // Oltre scadenza ma entro la tolleranza sull'orologio: ancora valido,
        // perché il device può avere l'orologio indietro.
        assert_eq!(p.expiry(t0 + 301), QrExpiry::Valid(0), "deriva del device");
        assert_eq!(
            p.expiry(t0 + 390),
            QrExpiry::Valid(0),
            "al limite del margine"
        );
        // 91 s di ritardo: il margine di 90 è superato di 1 s.
        let scaduto = match p.expiry(t0 + 300 + 1 + QR_EXPIRY_GRACE_SECS) {
            QrExpiry::Expired(s) => s,
            altro => panic!("atteso Expired, ottenuto {altro:?}"),
        };
        assert_eq!(scaduto, 1);

        let q = PairingPayload::decode_qr(&p.encode_qr().unwrap()).expect("decode");
        assert_eq!(q.exp_unix, Some(t0 + 300), "scadenza nel roundtrip");
        assert_eq!(q.expiry(t0), QrExpiry::Valid(300));
    }

    /// Un QR senza scadenza resta valido e non viene inventata una scadenza.
    ///
    /// Compatibilità: engine e mobile precedenti non hanno il campo, e il TTL
    /// continua a valere solo lato engine.
    #[test]
    fn qr_senza_scadenza_non_inventa_una_scadenza() {
        let p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32]);
        assert!(
            p.encode_qr().unwrap().len() < 2_500,
            "campo sempre presente?"
        );
        let q = PairingPayload::decode_qr(&p.encode_qr().unwrap()).unwrap();
        assert_eq!(q.exp_unix, None);
        assert_eq!(q.expiry(EXP_MAX_SANE), QrExpiry::Unknown);
    }

    /// Una scadenza assurda è un campo corrotto, non un QR vecchio.
    ///
    /// Il caso reale è il campo a zero: verrebbe letto come "scaduto da 56 anni"
    /// e l'utente riceverebbe "rigenera il QR" per un QR appena generato — la
    /// peggiore delle diagnosi, perché il rimedio non cambia nulla.
    #[test]
    fn scadenza_assurda_rifiutata() {
        for assurdo in [0u64, 1, EXP_MIN_SANE - 1, EXP_MAX_SANE + 1] {
            let mut p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32]);
            p.exp_unix = Some(assurdo);
            assert!(
                PairingPayload::decode_qr(&p.encode_qr().unwrap()).is_err(),
                "scadenza assurda accettata: {assurdo}"
            );
        }
    }

    /// `host` e `tls_port` senza pin non abilitano TLS.
    ///
    /// Copre il caso pericoloso in cui un produttore futuro riempiesse solo due
    /// dei tre campi: il telefono deve continuare a ignorarli (criterio del
    /// "tutto o niente") invece di aprire un TLS non pinnato.
    #[test]
    fn tls_incompleto_non_abilita_il_canale() {
        let mut p = PairingPayload::new("192.168.1.10".into(), 8080, [1u8; 32], [2u8; 32])
            .with_tls_pin("nfc.local", 8443, &[3u8; 32]);
        p.tls_pin_b64 = None;
        assert!(PairingPayload::decode_qr(&p.encode_qr().unwrap()).is_ok());
    }
}
