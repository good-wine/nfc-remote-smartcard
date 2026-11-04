//! Heartbeat asincrono con tolleranza Wi-Fi.
//! Ogni peer deve rispondere `Pong` entro `dead_after`, altrimenti viene
//! marcato offline ma la sessione E2EE NON viene cancellata subito (grace 60s
//! per roaming Wi-Fi / cambio AP).

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq)]
pub enum PeerState {
    Online,
    Suspect,
    Offline,
}

#[derive(Debug)]
struct PeerInfo {
    last_pong: Instant,
    state: PeerState,
}

#[derive(Debug, Default)]
pub struct Heartbeat {
    peers: RwLock<HashMap<String, PeerInfo>>,
    pub dead_after: Duration,
    pub suspect_after: Duration,
}

impl Heartbeat {
    pub fn new(dead_after: Duration) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            dead_after,
            suspect_after: dead_after / 3,
        }
    }

    pub async fn mark_alive(&self, id: &str) {
        let mut g = self.peers.write().await;
        g.insert(
            id.into(),
            PeerInfo {
                last_pong: Instant::now(),
                state: PeerState::Online,
            },
        );
    }

    pub async fn mark_dead(&self, id: &str) {
        let mut g = self.peers.write().await;
        if let Some(p) = g.get_mut(id) {
            p.state = PeerState::Offline;
        }
    }

    /// Valuta transizioni Online->Suspect->Offline. Ritorna gli id diventati Offline.
    pub async fn sweep(&self) -> Vec<String> {
        let mut out = vec![];
        let mut g = self.peers.write().await;
        for (id, p) in g.iter_mut() {
            let e = p.last_pong.elapsed();
            if e > self.dead_after && p.state != PeerState::Offline {
                p.state = PeerState::Offline;
                out.push(id.clone());
            } else if e > self.suspect_after && p.state == PeerState::Online {
                p.state = PeerState::Suspect;
            }
        }
        out
    }
}
