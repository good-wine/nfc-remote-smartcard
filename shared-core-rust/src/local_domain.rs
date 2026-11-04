//! Dominio locale `nfc.local` + HTTPS (2026).
//! Architettura split-horizon (fondamentale per capire il resto):
//! - **Desktop/estensione** (stesso host): `nfc.local` -> `127.0.0.1` via `hosts`
//!   file. Traffico mai sulla LAN: `https://nfc.local:8443` + `wss://...` con
//!   certificato foglia firmato dalla CA locale utente.
//! - **Mobile** (stessa LAN): `nfc.local` -> IP LAN desktop via **mDNS**
//!   (hostname `nfc`, `.local` è RFC 6762). Il QR contiene comunque l'IP
//!   esplicito come fallback se la rete blocca il multicast.
//! - `.local` è riservato mDNS: NON usare DNS unicast pubblico né search-domain.
//!   Su desktop l'entry `hosts` ha precedenza su mDNS (nsswitch/files first).
//!
//! Porte 2026: `8443` HTTPS/WSS (primario, tutte le interfacce) e `8080`
//! HTTP/WS **solo loopback** (fallback dell'estensione quando il browser non si
//! fida della CA locale). La porta 443 è evitata per non richiedere
//! root/capabilities all'avvio.

use std::path::PathBuf;

/// Dominio radice locale.
pub const LOCAL_DOMAIN: &str = "nfc.local";
/// Porta HTTPS/WSS primaria (nessun root richiesto).
pub const TLS_PORT: u16 = 8443;
/// Porta HTTP/WS legacy (compat + redirect 301 -> HTTPS).
pub const PLAIN_PORT: u16 = 8080;

/// Sotto-domini serviti dallo stesso Router Axum (stesso cert wildcard).
/// `api` = REST/WS engine, `app` = UI config desktop, `pair` = pagina QR/deep-link.
pub const SUBDOMAINS: &[&str] = &["api", "app", "pair"];

/// Endpoint legacy in chiaro dell'estensione.
///
/// Vale solo sul **loopback**: il mobile non ci passa (usa `wss://` con il pin
/// del certificato contenuto nel QR) e il resto della LAN non lo raggiunge.
pub const WS_LEGACY: &str = "ws://127.0.0.1:8080/v1/extension";

/// Ambito di raggiungibilità di [`WS_LEGACY`], esposto in `/v1/status`.
///
/// È un campo a parte invece di una nota dentro l'URL: il JSON è un contratto
/// machine-readable e i consumer ci fanno match/`startsWith`, quindi infilare
/// prosa dentro la stringa li romperebbe — ed è proprio il tipo di
/// falsificazione che aveva reso `/v1/status` promettere più di quanto
/// dichiarasse.
pub const WS_LEGACY_SCOPE: &str = "loopback-only";

/// URL canonici esposti.
#[must_use]
pub fn https_base() -> String {
    format!("https://{LOCAL_DOMAIN}:{TLS_PORT}")
}
#[must_use]
pub fn wss_extension() -> String {
    format!("wss://{LOCAL_DOMAIN}:{TLS_PORT}/v1/extension")
}
#[must_use]
pub fn wss_mobile() -> String {
    format!("wss://{LOCAL_DOMAIN}:{TLS_PORT}/v1/mobile")
}

/// SAN del certificato foglia: dominio + wildcard + loopback (IP + localhost)
/// + IP di LAN del desktop.
///
/// Gli IP-SAN servono a client che validano per IP (curl, mobile fallback).
/// L'IP di LAN serve al telefono quando `nfc.local` non risolve: il DNS
/// unicast della LAN risponde NXDOMAIN per `.local` e Firefox mobile non fa
/// mDNS (a differenza di Chrome Android), quindi il percorso pulito per
/// Firefox è `https://<IP di LAN>:8443` — che senza l'IP-SAN fallirebbe la
/// verifica hostname anche con la CA installata.
#[must_use]
pub fn leaf_sans() -> Vec<String> {
    let mut v = vec![
        LOCAL_DOMAIN.to_string(),
        format!("*.{LOCAL_DOMAIN}"),
        "localhost".to_string(),
        // rcgen emette un IP-SAN (non DNS) quando la voce parsea come
        // `IpAddr`: serve a `curl https://127.0.0.1:8443` e al fallback
        // mobile su loopback, che altrimenti falliscono la verifica hostname.
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    // IP di LAN reale: stessa fonte di QR e mDNS (`crate::net::lan_ipv4`).
    // Esiste solo dov'è abilitata la feature `net` (engine desktop: la
    // webapp/wasm non genera certificati né enumera interfacce).
    // Host senza rete → `None`, lista invariata (il loopback non va duplicato).
    #[cfg(feature = "net")]
    if let Some(ip) = crate::net::lan_ipv4() {
        let s = ip.to_string();
        if !v.contains(&s) {
            v.push(s);
        }
    }
    for sub in SUBDOMAINS {
        v.push(format!("{sub}.{LOCAL_DOMAIN}"));
    }
    v
}

/// Il nome è quello del dominio locale o di uno dei suoi sotto-domini.
///
/// Serve a validare il campo `host` del QR di pairing: il canale TLS vale solo
/// per questi nomi, quindi accettarne altri aprirebbe la porta a un QR che
/// indirizza il telefono verso un host arbitrario.
///
/// Sono tollerati il maiuscolo e il punto finale (FQDN). **Non** sono
/// tollerati spazi o altri spazi bianchi: in un QR uno spazio iniziale è
/// un'anomalia, e normalizzarla nasconderebbe un payload malformato invece di
/// segnalarlo.
#[must_use]
pub fn is_local_hostname(h: &str) -> bool {
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    h == LOCAL_DOMAIN
        || SUBDOMAINS
            .iter()
            .any(|s| h == format!("{s}.{LOCAL_DOMAIN}"))
}

/// Directory profilo utente: `~/.config/nfc-remote/` (XDG) o `%APPDATA%`.
#[must_use]
pub fn profile_dir() -> PathBuf {
    dirs_fallback()
}

fn dirs_fallback() -> PathBuf {
    if let Some(v) = std::env::var_os("NFC_REMOTE_HOME") {
        return PathBuf::from(v);
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(v) = std::env::var_os("APPDATA") {
            return PathBuf::from(v).join("NFCRemote");
        }
    }
    if let Some(v) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(v).join("nfc-remote");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config").join("nfc-remote");
    }
    PathBuf::from(".nfc-remote")
}

#[must_use]
pub fn ca_cert_path() -> PathBuf {
    profile_dir().join("ca").join("nfc-local-root.pem")
}
#[must_use]
pub fn ca_key_path() -> PathBuf {
    profile_dir().join("ca").join("nfc-local-root.key")
}
#[must_use]
pub fn leaf_cert_path() -> PathBuf {
    profile_dir().join("tls").join("nfc.local.pem")
}
#[must_use]
pub fn leaf_key_path() -> PathBuf {
    profile_dir().join("tls").join("nfc.local.key")
}

/// Lockfile tenuto dall'engine in esecuzione.
#[must_use]
pub fn engine_lock_path() -> PathBuf {
    profile_dir().join("engine.lock")
}

/// `true` se c'è un engine che **dichiara** di essere in esecuzione.
///
/// Non è un test di vitalità del processo: rileva il file, non il PID. È la
/// scelta deliberata per una rotazione della CA, dove il costo di un falso
/// negativo (rotazione consentita, QR con pin incoerente) è alto, mentre un
/// falso positivo costa solo un messaggio che chiede di chiudere il desktop.
///
/// Il file contiene il PID per agevolare la diagnosi, ma non viene usato per
/// decidere: un PID riusato da un processo non imparentato renderebbe la
/// verifica peggiore che non farla.
#[must_use]
pub fn engine_lock_present() -> bool {
    engine_lock_path().exists()
}

// Lockfile engine (solo feature `lockfile` = desktop).
// Su WASM/mobile non serve: non c'è engine daemon che tenga il lock.
#[cfg(feature = "lockfile")]
mod engine_lock {
    use super::engine_lock_path;
    use std::io::Write as _;

    /// Tenta di acquisire il lockfile engine in modo atomico (flock).
    ///
    /// Restituisce `Ok(file_handle)` se il lock è acquisito — il chiamante **deve**
    /// mantenere vivo l'handle per tutta la durata dell'engine. Il lock viene
    /// rilasciato automaticamente all'uscita del processo (OS cleanup) o quando
    /// l'handle viene droppato.
    ///
    /// # Errors
    /// `std::io::Error` se il file non è scrivibile o il lock è già tenuto da un
    /// altro processo (engine già in esecuzione).
    pub fn try_acquire_engine_lock() -> std::io::Result<std::fs::File> {
        let p = engine_lock_path();
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&p)?;

        // Flock atomico cross-platform — blocca se già tenuto
        fs2::FileExt::try_lock_exclusive(&f).map_err(|_e| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("engine già in esecuzione (lockfile: {})", p.display()),
            )
        })?;

        writeln!(&mut f, "{}", std::process::id())?;
        f.flush()?;
        Ok(f)
    }
}

#[cfg(feature = "lockfile")]
pub use engine_lock::try_acquire_engine_lock;

#[cfg(not(feature = "lockfile"))]
pub fn try_acquire_engine_lock() -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "engine lock non supportato su questa piattaforma (abilita feature 'lockfile')",
    ))
}

/// Rimuove il lockfile d'engine.
///
/// # Errors
/// `std::io::Error` se il file non è cancellabile. Idempotente in sostanza: un
/// file già assente non è un errore da propagare, altrimenti un crash
/// all'avvio mascherebbe la causa reale.
pub fn clear_engine_lock() -> std::io::Result<()> {
    match std::fs::remove_file(engine_lock_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Righe `hosts` da installare (richiede admin una tantum).
/// Solo loopback: il traffico desktop non esce mai dall'host.
#[must_use]
pub fn hosts_lines() -> Vec<String> {
    let mut names = vec![LOCAL_DOMAIN.to_string()];
    for sub in SUBDOMAINS {
        names.push(format!("{sub}.{LOCAL_DOMAIN}"));
    }
    vec![
        format!("127.0.0.1\t{}", names.join(" ")),
        format!("::1\t{}", names.join(" ")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn urls_coerenti() {
        assert_eq!(https_base(), "https://nfc.local:8443");
        assert!(wss_extension().starts_with("wss://nfc.local:8443"));
        assert!(hosts_lines()[0].contains("api.nfc.local"));
    }

    #[test]
    fn solo_nomi_del_dominio_locale() {
        for ok in ["nfc.local", "api.nfc.local", "NFC.LOCAL", "pair.nfc.local."] {
            assert!(is_local_hostname(ok), "dovrebbe essere ammesso: {ok}");
        }
        for no in [
            "evil.example.com",
            "nfc.local.evil.com",
            "api.nfc.local.evil.com",
            "xnfc.local",
            "nfc.local.co",
            "127.0.0.1",
            " app.nfc.local",
            "app.nfc.local ",
            "",
        ] {
            assert!(!is_local_hostname(no), "dovrebbe essere rifiutato: {no}");
        }
    }

    #[test]
    fn leaf_sans_copre_dominio_wildcard_loopback_e_ip_di_lan() {
        let sans = leaf_sans();
        let base = [
            LOCAL_DOMAIN.to_string(),
            format!("*.{LOCAL_DOMAIN}"),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        for entry in &base {
            assert!(sans.contains(entry), "manca la SAN base {entry}");
        }
        for sub in SUBDOMAINS {
            assert!(sans.contains(&format!("{sub}.{LOCAL_DOMAIN}")));
        }
        // Il loopback non va duplicato dall'aggiunta dell'IP di LAN.
        assert_eq!(
            sans.iter().filter(|s| s.as_str() == "127.0.0.1").count(),
            1,
            "il loopback deve comparire una sola volta"
        );
        // Ogni voce è un IP o un DNS name: rcgen la classifica da sola.
        for entry in &sans {
            if entry.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            let ok = !entry.is_empty()
                && entry
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '*' || c == '-');
            assert!(ok, "SAN non valida: {entry}");
        }
        // Coerenza con la fonte: se l'host ha un IP di LAN, lì c'è.
        #[cfg(feature = "net")]
        if let Some(ip) = crate::net::lan_ipv4() {
            assert!(
                sans.contains(&ip.to_string()),
                "manca l'IP di LAN {ip} nelle SAN"
            );
        }
    }
}
