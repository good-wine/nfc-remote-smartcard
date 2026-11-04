//! Discovery mDNS/ZeroConf (2026).
//! - Servizio `_smartcard-nfc._tcp.local`, istanza `nfc-desktop`.
//! - **Hostname mDNS `nfc`** (=> `nfc.local` risolve all'IP LAN su mobile,
//!   RFC 6762): è lo split-horizon di `docs/LOCAL-DOMAIN.md` — sul desktop
//!   `/etc/hosts` ha precedenza e punta a 127.0.0.1.
//! - TXT: `v=2`, `tls=8443`, `pq=1/0`, `api=/v1`.
//! - **8080 non viene annunciata**: è bindata su loopback, quindi non è un
//!   servizio della LAN. Pubblicarla in un record mDNS sarebbe un'affermazione
//!   falsa — un client che leggesse `plain=8080` tenterebbe una porta chiusa.
//! - `discover_once` (blocking, per task dedicato) + `spawn_discover`
//!   (ponte Tokio mpsc per UI senza bloccare il runtime).

use crate::error::{CoreError, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{collections::HashMap, time::Duration};
use tokio::sync::mpsc;

pub const SERVICE_TYPE: &str = "_smartcard-nfc._tcp.local.";
pub const SERVICE_NAME: &str = "nfc-desktop";
/// Hostname mDNS: `nfc.local.` (FQDN, RFC 6762) => i peer LAN risolvono
/// `nfc.local` all'IP LAN del desktop senza toccare `/etc/hosts`.
///
/// **Deve** terminare con `.local.`: `mdns-sd` rifiuta un nome corto (`nfc`) con
/// `Hostname must end with '.local.'`. Il punto finale è parte del FQDN e non
/// compare mai nelle query.
pub const MDNS_HOSTNAME: &str = "nfc.local.";
pub const TXT_VERSION: &str = "2";

/// Indirizzo IP routable primario dell'host.
///
/// Delega a [`crate::net::lan_ipv4`]: enumera le interfacce ed esclude
/// tunnel VPN e bridge virtuali, che non sono raggiungibili dal telefono che
/// scansiona il QR. Non usare il trucco del socket UDP (rotta di default):
/// con una VPN split-tunnel attiva restituirebbe l'IP di `tun0`.
///
/// Nota: è *un* indirizzo. `mdns-sd` mantiene comunque l'elenco completo
/// (`enable_addr_auto`), quindi su host multi-interfaccia vengono annunciati
/// entrambi; questo serve a rendere l'annuncio esplicito e verificabile.
fn primary_host_ip() -> Option<std::net::IpAddr> {
    crate::net::lan_ipv4().map(std::net::IpAddr::V4)
}

/// Handle di advertising; droppandolo si rimuove il servizio.
pub struct Advertiser {
    _daemon: ServiceDaemon,
    info: ServiceInfo,
    fullname: String,
}

impl std::fmt::Debug for Advertiser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `ServiceDaemon` non implementa `Debug`: omissione intenzionale.
        f.debug_struct("Advertiser")
            .field("fullname", &self.fullname)
            .field("addresses", &self.info.get_addresses())
            .finish_non_exhaustive()
    }
}

impl Advertiser {
    /// Pubblica il servizio (chiamare dentro `spawn_blocking`: mdns-sd è sync).
    ///
    /// # Errors
    /// `CoreError::Mdns` se il demone non parte o la registrazione fallisce.
    pub fn advertise(tls_port: u16) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| CoreError::Mdns(e.to_string()))?;
        let mut props = HashMap::new();
        props.insert("v".to_string(), TXT_VERSION.to_string());
        props.insert("tls".to_string(), tls_port.to_string());
        #[cfg(feature = "pq")]
        props.insert("pq".to_string(), "1".to_string());
        #[cfg(not(feature = "pq"))]
        props.insert("pq".to_string(), "0".to_string());
        props.insert("api".to_string(), "/v1".to_string());
        // Hostname fisso `nfc.local.`: i device risolvono `nfc.local` via mDNS.
        //
        // Gli indirizzi sono passati esplicitamente **e** si tiene
        // `enable_addr_auto()`: senza indirizzi il servizio veniva registrato
        // con `addresses: {}` — scopribile ma non connettibile, perché nessun
        // device sapeva a cosa agganciarsi. `addr_auto` mantiene poi l'elenco
        // allineato se l'IP cambia (desktop su Wi-Fi/DHCP).
        // `AsIpAddrs` è implementato per `String` (non per `Option<IpAddr>` né per
        // `Vec`): stringa vuota = nessun indirizzo esplicito, e allora lavora
        // solo `addr_auto`.
        let ip = primary_host_ip().map_or_else(String::new, |a| a.to_string());
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            SERVICE_NAME,
            MDNS_HOSTNAME,
            ip,
            tls_port,
            props,
        )
        .map_err(|e| CoreError::Mdns(e.to_string()))?
        .enable_addr_auto();
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info.clone())
            .map_err(|e| CoreError::Mdns(e.to_string()))?;
        Ok(Self {
            _daemon: daemon,
            info,
            fullname,
        })
    }

    #[must_use]
    pub fn fullname(&self) -> &str {
        &self.fullname
    }

    /// Indirizzi annunciati: quello su cui i device raggiungono l'engine.
    #[must_use]
    pub fn addresses(&self) -> Vec<std::net::IpAddr> {
        self.info.get_addresses().iter().copied().collect()
    }
}

/// Peer scoperto via mDNS (con porte TLS/chiaro e supporto PQ da TXT).
#[derive(Debug, Clone)]
pub struct Peer {
    pub hostname: String,
    pub address: std::net::IpAddr,
    /// Porta HTTPS/WSS (da TXT `tls`, fallback porta servizio).
    pub tls_port: u16,
    pub pq: bool,
    pub version: String,
}

/// Cerca un peer per `timeout` (blocking: usare in `spawn_blocking`).
///
/// # Errors
/// `CoreError::Mdns` se il demone o il browse non partono (`None` = nessun peer).
pub fn discover_once(timeout: Duration) -> Result<Option<Peer>> {
    let daemon = ServiceDaemon::new().map_err(|e| CoreError::Mdns(e.to_string()))?;
    let rx = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| CoreError::Mdns(e.to_string()))?;
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remain) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(p) = peer_of(&info) {
                    return Ok(Some(p));
                }
            }
            Err(_) => break,
            Ok(_) => {}
        }
    }
    Ok(None)
}

/// Ponte Tokio: esegue il browse in un thread dedicato e invia i peer su mpsc.
/// Il Receiver è `async`: la UI mobile può selezionare il desktop senza QR.
#[must_use]
pub fn spawn_discover(buffer: usize) -> (mpsc::Receiver<Peer>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(buffer);
    let h = tokio::task::spawn_blocking(move || {
        let Ok(daemon) = ServiceDaemon::new() else {
            return;
        };
        let Ok(events) = daemon.browse(SERVICE_TYPE) else {
            return;
        };
        // Poll 1Hz: `recv` bloccherebbe per sempre trattenendo il demone,
        // così la chiusura del Receiver viene onorata entro un secondo.
        loop {
            if tx.is_closed() {
                break;
            }
            let Ok(ServiceEvent::ServiceResolved(info)) =
                events.recv_timeout(Duration::from_secs(1))
            else {
                continue;
            };
            let Some(p) = peer_of(&info) else { continue };
            if tx.blocking_send(p).is_err() {
                break;
            }
        }
    });
    // Converte JoinHandle blocking in JoinHandle Tokio (spawn_blocking già).
    (
        rx,
        tokio::spawn(async move {
            let _ = h.await;
        }),
    )
}

fn peer_of(info: &ServiceInfo) -> Option<Peer> {
    let address = info.get_addresses().iter().next().copied()?;
    let props = info.get_properties();
    let get = |k: &str| props.get(k).map(|v| v.val_str().to_string());
    Some(Peer {
        hostname: info.get_hostname().to_string(),
        address,
        tls_port: get("tls")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| info.get_port()),
        pq: get("pq").as_deref() == Some("1"),
        version: get("v").unwrap_or_else(|| "?".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L'hostname deve essere un FQDN `.local.`: con il nome corto `nfc`
    /// `mdns-sd` rifiutava la registrazione e il desktop rimaneva
    /// irraggiungibile da ogni device di rete.
    #[test]
    fn hostname_e_fqdn_local() {
        assert!(MDNS_HOSTNAME.ends_with(".local."), "non è un FQDN mDNS");
        assert!(!MDNS_HOSTNAME.contains(".."));
        // Il punto finale è parte del FQDN e non va ripetuto: `nfc.local.local.`
        assert_eq!(MDNS_HOSTNAME, "nfc.local.");
        assert!(SERVICE_TYPE.ends_with("._tcp.local."));
    }

    /// Registrazione reale: falliva con `Hostname must end with '.local.'`, e
    /// il servizio risultava senza indirizzi (`addresses: {}`), cioè
    /// scopribile ma non connettibile.
    #[test]
    fn advertise_registra_servizio() {
        let adv = Advertiser::advertise(8443).expect("registrazione mDNS");
        assert!(
            adv.fullname().starts_with(SERVICE_NAME),
            "fullname: {}",
            adv.fullname()
        );
        assert!(adv.fullname().ends_with("._tcp.local."));
        // Almeno un indirizzo non-loopback: è l'IP a cui i device si connettono.
        let addrs = adv.addresses();
        assert!(
            addrs
                .iter()
                .any(|a| !a.is_loopback() && !a.is_unspecified()),
            "nessun indirizzo utile annunciato: {addrs:?}"
        );
    }

    /// Il record TXT non deve annunciare porte loopback-only.
    ///
    /// 8080 è bindata su `127.0.0.1`: pubblicarla in un record di servizio LAN
    /// sarebbe un'affermazione falsa, perché un client che leggesse `plain=8080`
    /// tenterebbe una porta chiusa. Il TXT dichiara solo ciò che è davvero
    /// raggiungibile dalla rete.
    #[test]
    fn txt_non_annuncia_porte_loopback() {
        let adv = Advertiser::advertise(crate::local_domain::TLS_PORT).expect("registrazione mDNS");
        let chiavi: Vec<String> = adv
            .info
            .get_properties()
            .iter()
            .map(|p| p.key().to_string())
            .collect();
        assert!(
            !chiavi.iter().any(|k| k.eq_ignore_ascii_case("plain")),
            "chiavi annunciate: {chiavi:?}"
        );
        for k in &chiavi {
            assert!(
                !k.eq_ignore_ascii_case("port") && !k.eq_ignore_ascii_case("http"),
                "porta generica annunciata: {k}"
            );
        }
    }

    /// Percorso dell'app mobile: pubblico e mi cerco con la stessa libreria.
    ///
    /// `#[ignore]` di proposito: due `ServiceDaemon` **nello stesso processo**
    /// non ricevono i propri multicast di loopback, quindi il self-discovery
    /// fallirebbe anche con la rete perfettamente funzionante. La rete reale
    /// (desktop → device) è un processo diverso e riceve le annunciature.
    /// Per il loopback locale la copertura utile resta
    /// `advertise_registra_servizio`, che falliva prima del fix dell'FQDN.
    #[test]
    #[ignore = "self-discovery mDNS in-process non supportato"]
    fn advertise_poi_discover() {
        let _adv = Advertiser::advertise(8443).expect("registrazione mDNS");
        let peer = discover_once(Duration::from_secs(3))
            .expect("browse")
            .expect("nessun peer trovato via mDNS");
        assert_eq!(peer.hostname, MDNS_HOSTNAME);
        assert_eq!(peer.tls_port, 8443);
        assert_eq!(peer.version, TXT_VERSION);
    }
}
