//! Scelta dell'indirizzo IP di LAN da annunciare (QR di pairing e mDNS).
//!
//! # Perché non basta `local_ip()`
//!
//! Il trucco classico — aprire un socket UDP e far scegliere al kernel
//! l'interfaccia di uscita con un `connect()` senza inviare nulla — restituisce
//! l'IP della **rotta di default**, non quello della LAN.
//!
//! È un bug sui portatili con VPN attiva. Una VPN split-tunnel installa due
//! rotte più specifiche del default:
//!
//! ```text
//! 0.0.0.0/1  via 10.42.0.1  dev tun0      # più specifica di default
//! 128.0.0.0/1 via 10.42.0.1  dev tun0      # più specifica di default
//! default   via 192.168.188.1 dev enp10s0
//! ```
//!
//! Con quei `connect()` l'engine annunciava `10.42.0.39` (tun0) invece di
//! `192.168.188.21` (Ethernet), e il `PairingPayload` finiva nel QR con
//! l'indirizzo della VPN: il telefono in LAN non riusciva a raggiungerlo.
//!
//! # Strategia
//!
//! Enumeriamo le interfacce e ne scegliamo una **fisica**: si escludono i
//! tunnel (VPN) e i bridge virtuali (Docker, VM), che non sono raggiungibili
//! dal telefono che scansiona il QR.

use std::net::{IpAddr, Ipv4Addr};

/// Prefissi di interfaccia da escludere: tunnel VPN/overlay e bridge virtuali.
///
/// Elenco per *prefisso* e non per nome esatto: le interfacce hanno nomi
/// diversi per driver e versioni (`tun0`, `tap1`, `wg0`, `ppp0`, `ip6tnl0`,
/// `docker0`, `br-45a1b2`, `virbr0`, `veth…`).
const EXCLUDED_IFACE_PREFIXES: &[&str] = &[
    // Tethering USB: smartphone e tablet collegati per tethering condividono la
    // connessione con l'host, ma dal telefono l'host non è raggiungibile.
    "rndis", "usb", "cdc_", "enx", // device USB Ethernet / RNDIS
    "tun", "tap", "wg", "ppp", "ip6tnl", "ip6gre", "gre", "sit", "erspan", "ip_vti", "vxlan",
    "geneve", "vti", // tunnel generici
    "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "lxc", "podman", "cni", "flannel",
    "zt", // ZeroTier e simili
];

/// Un indirizzo IPv4 è un candidate valido per il QR di pairing?
fn is_usable_lan_ipv4(iface: &str, ip: Ipv4Addr) -> bool {
    is_routable_v4(ip) && !is_virtual_iface(iface)
}

/// L'IP è utilizzabile come indirizzo di un host raggiungibile?
///
/// `Ipv4Addr::is_global` è ancora instabile su questo toolchain, quindi la
/// classificazione è esplicita.
fn is_routable_v4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    // Link-local: valido solo con l'interfaccia configurata via DHCP senza
    // gateway; non è un indirizzo su cui un telefono possa fare routing.
    if ip.is_link_local() {
        return false;
    }
    // Broadcast e "questa rete" (RFC 1122): mai indirizzi di un host.
    if ip.is_broadcast() || ip.octets()[0] == 0 || ip.is_documentation() {
        return false;
    }
    // Carrier-grade NAT (100.64.0.0/10) e blocchi di protocollo: non
    // raggiungibili da un peer della rete locale.
    !is_cgnat(ip) && ip != Ipv4Addr::new(192, 0, 0, 0)
}

/// 100.64.0.0/10: NAT tra operatori, non instradabile su LAN.
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (64..128).contains(&b)
}

/// Il nome dell'interfaccia indica tunnel o bridge virtuale?
fn is_virtual_iface(iface: &str) -> bool {
    let lower = iface.to_ascii_lowercase();
    EXCLUDED_IFACE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Indirizzo IPv4 di LAN da usare nel QR di pairing e in mDNS.
///
/// Preferisce un'interfaccia fisica; se non ne trova nessuna (server, VM,
/// ambiente di test) ripiega sull'IP della rotta di default, che è comunque
/// più utile di `127.0.0.1`.
///
/// `None` solo se l'host non ha nessuna rete utilizzabile.
#[must_use]
pub fn lan_ipv4() -> Option<Ipv4Addr> {
    if let Some(ip) = physical_interface_ipv4() {
        return Some(ip);
    }
    default_route_ipv4()
}

/// Prima interfaccia fisica con un IPv4 utilizzabile.
fn physical_interface_ipv4() -> Option<Ipv4Addr> {
    let addrs = local_ip_address::list_afinet_netifas().ok()?;
    // `list_afinet_netifas` non è ordinato per rilevanza, quindi non basta la
    // prima: su un portatile con VPN si enumera per caso e si rischierebbe di
    // prendere il tunnel. Si sceglie deterministicamente l'IP privato su
    // interfaccia fisica.
    let mut best: Option<Ipv4Addr> = None;
    for (iface, ip) in addrs {
        let IpAddr::V4(v4) = ip else { continue };
        if !is_usable_lan_ipv4(&iface, v4) {
            continue;
        }
        if v4.is_private() {
            return Some(v4);
        }
        best = best.or(Some(v4));
    }
    best
}

/// IP che il kernel userebbe per raggiungere la rete (rotta di default).
fn default_route_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect("192.0.2.1:9").ok()?; // TEST-NET-1: nessun traffico inviato
    let ip = sock.local_addr().ok()?.ip();
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private() || is_routable_v4(v4) {
                Some(v4)
            } else {
                None
            }
        }
        IpAddr::V6(_) => None,
    }
}

/// IP di LAN come stringa, con `127.0.0.1` come ultima risorsa.
///
/// Non restituisce mai un indirizzo vuoto: un QR senza IP sarebbe inafferrabile,
/// e `127.0.0.1` almeno resta valido per il pairing in locale.
#[must_use]
pub fn lan_ipv4_string() -> String {
    lan_ipv4().map_or_else(|| Ipv4Addr::LOCALHOST.to_string(), |ip| ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scarta_tunnel_e_bridge() {
        for iface in [
            "tun0",
            "tunl0",
            "tap3",
            "wg0",
            "ppp0",
            "ip6tnl0",
            "docker0",
            "br-45a1b2c3d4e5",
            "veth1a2b3c4",
            "virbr0",
            "vboxnet0",
            "zt0",
            "rndis0",
            "enx001122334455",
        ] {
            assert!(
                is_virtual_iface(iface),
                "{iface} doveva essere escluso come virtuale"
            );
        }
    }

    #[test]
    fn accetta_interfacce_fisiche() {
        for iface in ["eth0", "enp10s0", "wlp2s0", "wlan0", "em1", "igb0"] {
            assert!(!is_virtual_iface(iface), "{iface} è fisica, non va esclusa");
        }
    }

    #[test]
    fn scarta_indirizzi_non_utilizzabili() {
        let lan = "eth0";
        for ip in [
            Ipv4Addr::LOCALHOST,           // 127.0.0.1
            Ipv4Addr::UNSPECIFIED,         // 0.0.0.0
            Ipv4Addr::BROADCAST,           // 255.255.255.255
            Ipv4Addr::new(169, 254, 1, 1), // link-local
            Ipv4Addr::new(224, 0, 0, 1),   // multicast
            Ipv4Addr::new(192, 0, 2, 5),   // documentation
            Ipv4Addr::new(0, 1, 2, 3),     // "questa rete"
        ] {
            assert!(
                !is_usable_lan_ipv4(lan, ip),
                "{ip} su {lan} non doveva essere accettato"
            );
        }
    }

    #[test]
    fn accetta_rfc1918_su_interfaccia_fisica() {
        for ip in [
            Ipv4Addr::new(192, 168, 188, 21),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(172, 16, 4, 9),
        ] {
            assert!(
                is_usable_lan_ipv4("eth0", ip),
                "{ip} doveva essere accettato"
            );
        }
    }

    /// Il contratto che conta: l'IP annunciato non deve mai appartenere a un
    /// tunnel, o il telefono non lo raggiunge.
    #[test]
    fn ip_annunciato_non_e_di_un_tunnel() {
        let Some(ip) = lan_ipv4() else { return }; // host senza rete: niente da verificare
        let addrs = local_ip_address::list_afinet_netifas().unwrap();
        let owners: Vec<&str> = addrs
            .iter()
            .filter(|(_, a)| *a == IpAddr::V4(ip))
            .map(|(i, _)| i.as_str())
            .collect();
        for iface in owners {
            assert!(
                !is_virtual_iface(iface),
                "lan_ipv4() ha restituito {ip}, che appartiene all'interfaccia virtuale {iface}"
            );
        }
    }

    #[test]
    fn fallback_non_e_mai_vuoto() {
        assert_ne!(lan_ipv4_string(), "", "il fallback non deve essere vuoto");
    }
}
