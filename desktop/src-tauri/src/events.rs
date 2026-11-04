//! Event bus: presenza/assenza carta e stato reader.
//! Single-producer/multi-consumer via `tokio::sync::broadcast` così sia il
//! bridge vpcd sia il WS extension ricevono gli stessi eventi in tempo reale.

use nfc_core::protocol::{CardStatus, ExtEvent};
use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum EngineEvent {
    Card(CardStatus, Option<String>),
    ReaderConnected(String),
    ReaderDisconnected(String),
    /// SAS hex a 6 cifre da mostrare su entrambi gli schermi (anti-MITM).
    MobileConnected(String),
    MobileDisconnected(String),
    /// La webapp ha scansionato un QR di pairing valido (beacon informativo:
    /// conferma sul desktop che qualcuno ha inquadrato il QR dal browser).
    /// Non è un'autorizzazione: il pairing resta autorizzato dal QR + handshake.
    QrScanned,
    /// Un client locale (estensione/REST) chiede l'autorizzazione a guidare il
    /// lettore: l'UI desktop deve mostrare Consenti/Rifiuta.
    ConsentRequested {
        id: String,
        label: String,
    },
    /// Consenso risolto (ok=true approvato, false rifiutato/scaduto).
    ConsentResolved {
        id: String,
        ok: bool,
    },
}

impl EngineEvent {
    pub fn to_ext_event(&self) -> Option<ExtEvent> {
        match self {
            Self::Card(s, atr) => Some(ExtEvent::CardStatus {
                status: *s,
                atr_hex: atr.clone(),
            }),
            Self::ReaderConnected(n) => Some(ExtEvent::ReaderConnected { name: n.clone() }),
            Self::ReaderDisconnected(n) => Some(ExtEvent::ReaderDisconnected { name: n.clone() }),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct EventBus {
    tx: broadcast::Sender<EngineEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }
    pub fn publish(&self, ev: EngineEvent) {
        // Se non ci sono receiver è ok: `send` fallisce ma non è errore.
        let _ = self.tx.send(ev);
    }
    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.tx.subscribe()
    }
}
