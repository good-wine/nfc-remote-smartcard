//! Adapter PC/SC virtuale verso demone `vpcd` (vsmartcard, 127.0.0.1:35963).
//! Framing adapter v1 (`len BE32 || cmd u8 || payload`, risposta
//! `len BE32 || status u8 || payload`) con comandi `PowerOn` (`0x10`, ATR),
//! `PowerOff` (`0x11`), `Transmit` (`0x12`, risposta carta dati+SW) e
//! `GetStatus` (`0x13`, presenza+ATR). Traduce verso il socket del `vpcd`
//! reale, confine PC/SC; tutto async Tokio con timeout e riconnessione
//! esplicita (se vpcd è giù, l'engine serve comunque WS/extension).

use nfc_core::{CoreError, Result as CoreResult};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, timeout},
};
use tracing::{info, warn};

/// Configurazione connessione vpcd.
#[derive(Debug, Clone)]
pub struct VpcdConfig {
    pub host: String,
    pub port: u16,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
}

impl Default for VpcdConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 35963,
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(8),
        }
    }
}

/// Client vpcd con riconnessione esplicita (non auto-silente per evitare
/// retry storm: il chiamante decide il backoff).
pub struct VpcdClient {
    cfg: VpcdConfig,
    stream: Option<TcpStream>,
}

impl std::fmt::Debug for VpcdClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpcdClient")
            .field("cfg", &self.cfg)
            .field("connected", &self.stream.is_some())
            .finish()
    }
}

impl VpcdClient {
    #[must_use]
    pub fn new(cfg: VpcdConfig) -> Self {
        Self { cfg, stream: None }
    }

    /// Millisecondi di un `Duration`, saturati a `u64::MAX` (mai oltre).
    #[must_use]
    fn timeout_ms(d: Duration) -> u64 {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
    }

    /// Connessione (o riconnessione) con timeout.
    ///
    /// # Errors
    /// `CoreError::Timeout` o `CoreError::Network` se il demone non risponde.
    pub async fn connect(&mut self) -> CoreResult<()> {
        let addr = format!("{}:{}", self.cfg.host, self.cfg.port);
        let s = timeout(self.cfg.connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| CoreError::Timeout(Self::timeout_ms(self.cfg.connect_timeout)))?
            .map_err(|e| CoreError::Network(format!("vpcd connect {addr}: {e}")))?;
        s.set_nodelay(true).ok();
        info!(%addr, "vpcd connesso");
        self.stream = Some(s);
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Scrive un comando tipizzato `len || cmd || payload`, legge `len || status || payload`.
    /// `status != 0` = errore applicativo vpcd (non I/O: non invalida lo stream).
    ///
    /// # Errors
    /// `CoreError::Network`/`Timeout` su I/O (invalida lo stream), `Protocol` su framing.
    async fn roundtrip(&mut self, cmd: VpcdCmd, payload: &[u8]) -> CoreResult<(u8, Vec<u8>)> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| CoreError::Network("vpcd non connesso".into()))?;
        let req = encode_request(cmd, payload)?;
        timeout(self.cfg.io_timeout, stream.write_all(&req))
            .await
            .map_err(|_| CoreError::Timeout(Self::timeout_ms(self.cfg.io_timeout)))?
            .map_err(|e| CoreError::Network(format!("vpcd write: {e}")))?;
        let mut lenb = [0u8; 4];
        timeout(self.cfg.io_timeout, stream.read_exact(&mut lenb))
            .await
            .map_err(|_| CoreError::Timeout(Self::timeout_ms(self.cfg.io_timeout)))?
            .map_err(|e| CoreError::Network(format!("vpcd read len: {e}")))?;
        let len = u32::from_be_bytes(lenb) as usize;
        if !(1..=64 * 1024).contains(&len) {
            self.stream = None; // framing corrotto -> forza reconnect
            return Err(CoreError::Protocol("framing vpcd non valido".into()));
        }
        let mut buf = vec![0u8; len + 4];
        buf[..4].copy_from_slice(&lenb);
        timeout(self.cfg.io_timeout, stream.read_exact(&mut buf[4..]))
            .await
            .map_err(|_| CoreError::Timeout(Self::timeout_ms(self.cfg.io_timeout)))?
            .map_err(|e| CoreError::Network(format!("vpcd read body: {e}")))?;
        decode_response(&buf)
    }

    /// Esegue un comando con (ri)connessione e invalidazione stream su I/O error.
    async fn exec(&mut self, cmd: VpcdCmd, payload: &[u8]) -> CoreResult<(u8, Vec<u8>)> {
        if self.stream.is_none()
            && let Err(e) = self.connect().await
        {
            warn!("vpcd reconnect fallita: {e}");
            return Err(e);
        }
        match self.roundtrip(cmd, payload).await {
            Ok(r) => Ok(r),
            Err(e @ (CoreError::Network(_) | CoreError::Timeout(_))) => {
                warn!("vpcd I/O fallito, invalido stream: {e}");
                self.stream = None;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Power-on: ritorna ATR, o errore `carta assente` se status != 0.
    ///
    /// # Errors
    /// I/O verso vpcd o `Protocol` se il demone segnala assenza/errore.
    pub async fn power_on(&mut self) -> CoreResult<Vec<u8>> {
        let (status, atr) = self.exec(VpcdCmd::PowerOn, &[]).await?;
        if status != 0 {
            return Err(CoreError::Protocol("vpcd: nessuna carta (power-on)".into()));
        }
        Ok(atr)
    }

    /// Power-off (best-effort).
    ///
    /// # Errors
    /// I/O verso vpcd o `Protocol` se il demone rifiuta.
    pub async fn power_off(&mut self) -> CoreResult<()> {
        let (status, _) = self.exec(VpcdCmd::PowerOff, &[]).await?;
        if status != 0 {
            return Err(CoreError::Protocol("vpcd power-off rifiutato".into()));
        }
        Ok(())
    }

    /// Stato lettore: `true` se carta presente (con ATR opzionale).
    ///
    /// # Errors
    /// I/O verso vpcd o `Protocol` se il demone rifiuta.
    pub async fn card_present(&mut self) -> CoreResult<(bool, Vec<u8>)> {
        let (status, payload) = self.exec(VpcdCmd::GetStatus, &[]).await?;
        if status != 0 {
            return Err(CoreError::Protocol("vpcd get-status rifiutato".into()));
        }
        Ok((
            payload.first() == Some(&1),
            payload.get(1..).unwrap_or(&[]).to_vec(),
        ))
    }

    /// Trasmette APDU grezzi; ritorna risposta carta `dati+SW1+SW2`.
    ///
    /// # Errors
    /// `Protocol` su APDU malformata, risposta senza SW o status != 0; I/O verso vpcd.
    pub async fn transmit(&mut self, apdu: &[u8]) -> CoreResult<Vec<u8>> {
        if apdu.len() < 4 || apdu.len() > 65535 {
            return Err(CoreError::Protocol("APDU len 4..65535".into()));
        }
        let (status, resp) = self.exec(VpcdCmd::Transmit, apdu).await?;
        if status != 0 {
            return Err(CoreError::Protocol(format!(
                "vpcd transmit status {status:#04x}"
            )));
        }
        if resp.len() < 2 {
            return Err(CoreError::Protocol("risposta carta senza SW".into()));
        }
        Ok(resp)
    }
}

/// Comandi adapter v1 (stabili: non rinumerare; API pubblica per fuzz/test).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpcdCmd {
    PowerOn = 0x10,
    PowerOff = 0x11,
    Transmit = 0x12,
    GetStatus = 0x13,
}

impl TryFrom<u8> for VpcdCmd {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x10 => Ok(Self::PowerOn),
            0x11 => Ok(Self::PowerOff),
            0x12 => Ok(Self::Transmit),
            0x13 => Ok(Self::GetStatus),
            _ => Err(()),
        }
    }
}

/// Codifica una richiesta `len BE32 || cmd || payload` (funzione pura, fuzzabile).
///
/// # Errors
/// `CoreError::Protocol` se il payload supera i 4GB (mai in pratica).
pub fn encode_request(cmd: VpcdCmd, payload: &[u8]) -> CoreResult<Vec<u8>> {
    let len = u32::try_from(1 + payload.len())
        .map_err(|_| CoreError::Protocol("payload vpcd oltre 4GB".into()))?;
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.push(cmd as u8);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decodifica una risposta `len BE32 || status || payload` (funzione pura, fuzzabile).
/// Rifiuta framing corto/oversize senza toccare la rete.
///
/// # Errors
/// `CoreError::Protocol` su framing troncato o incoerente.
pub fn decode_response(buf: &[u8]) -> CoreResult<(u8, Vec<u8>)> {
    if buf.len() < 5 {
        return Err(CoreError::Protocol("frame vpcd troncato".into()));
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if !(1..=64 * 1024).contains(&len) || buf.len() - 4 != len {
        return Err(CoreError::Protocol("framing vpcd non valido".into()));
    }
    Ok((buf[4], buf[5..].to_vec()))
}

/// Decodifica una richiesta `len BE32 || cmd || payload` (funzione pura,
/// lato server: il compagno `vpcd-stub` usa questa stessa funzione per non
/// derivare il protocollo dal client — unica fonte di verità).
///
/// # Errors
/// `CoreError::Protocol` su framing corrotto o comando sconosciuto.
pub fn decode_request(buf: &[u8]) -> CoreResult<(VpcdCmd, Vec<u8>)> {
    if buf.len() < 5 {
        return Err(CoreError::Protocol("frame vpcd troncato".into()));
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if !(1..=64 * 1024).contains(&len) || buf.len() - 4 != len {
        return Err(CoreError::Protocol("framing vpcd non valido".into()));
    }
    let cmd = VpcdCmd::try_from(buf[4])
        .map_err(|()| CoreError::Protocol("comando vpcd sconosciuto".into()))?;
    Ok((cmd, buf[5..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_codifica() {
        let apdu = [0x00u8, 0xA4, 0x04, 0x00];
        let req = encode_request(VpcdCmd::Transmit, &apdu).unwrap();
        assert_eq!(&req[..4], &(5u32.to_be_bytes()));
        assert_eq!(req[4], 0x12);
        assert_eq!(&req[5..], &apdu);
        // Risposta: len(3) || status 0 || SW 9000
        let resp = [0, 0, 0, 3, 0x00, 0x90, 0x00];
        let (status, payload) = decode_response(&resp).unwrap();
        assert_eq!((status, payload.as_slice()), (0x00, &[0x90, 0x00][..]));
    }

    #[test]
    fn rifiuti_framing_corrotto() {
        assert!(decode_response(&[]).is_err()); // vuoto
        assert!(decode_response(&[0, 0]).is_err()); // troncato
        assert!(decode_response(&[0, 0, 0, 5, 0x00]).is_err()); // len != body
        assert!(decode_response(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]).is_err()); // oversize
        // status != 0 passa il framing (errore applicativo, gestito dal chiamante)
        let (s, _) = decode_response(&[0, 0, 0, 1, 0x01]).unwrap();
        assert_eq!(s, 0x01);
    }

    #[test]
    fn richiesta_roundtrip_decode() {
        for cmd in [
            VpcdCmd::PowerOn,
            VpcdCmd::PowerOff,
            VpcdCmd::Transmit,
            VpcdCmd::GetStatus,
        ] {
            let payload: &[u8] = match cmd {
                VpcdCmd::Transmit => &[0x00, 0xA4, 0x04, 0x00],
                _ => &[],
            };
            let req = encode_request(cmd, payload).unwrap();
            let (c, p) = decode_request(&req).unwrap();
            assert_eq!((c, p.as_slice()), (cmd, payload));
        }
    }

    #[test]
    fn richieste_malformate_rifiutate() {
        assert!(decode_request(&[]).is_err());
        assert!(decode_request(&[0, 0, 0, 2, 0x10]).is_err()); // len != body
        assert!(decode_request(&[0xFF, 0xFF, 0xFF, 0xFF, 0x10]).is_err()); // oversize
        assert!(decode_request(&[0, 0, 0, 1, 0x99]).is_err()); // comando ignoto
    }
}
