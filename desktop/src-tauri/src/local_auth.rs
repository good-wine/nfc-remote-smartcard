//! Autenticazione dei client **locali** del canale plaintext (loopback).
//!
//! Il confine da difendere qui non è la rete (chiunque sia sulla macchina
//! raggiunge `127.0.0.1:8080`): è l'**autorizzazione**. Prima di questo modulo
//! bastava un fetch senza `Origin` per guidare la carta del telefono remoto
//! attraverso `/v1/transmit` o `/v1/extension`. Ora ogni client locale deve
//! presentare un token emesso **con consenso esplicito dell'utente**:
//!
//! 1. un client si connette senza token e apre una richiesta di consenso
//!    (`request_consent`), restando in attesa sul socket;
//! 2. l'UI desktop mostra il richiedente e l'utente approva (`approve`) o
//!    rifiuta (`reject`);
//! 3. `approve` emette un token a 32 byte, ne memorizza **solo lo SHA-256**
//!    (il file `pairing/clients.json` non espone credenziali riusabili) e lo
//!    consegna al socket in attesa;
//! 4. ogni connessione successiva presenta il token (`authenticate`), che viene
//!    confrontato in tempo costante sull'hash.
//!
//! La revoca (`revoke`) del client invalida il token. Il consenso scade dopo
//! `CONSENT_TTL`: il socket in attesa chiude da solo.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Quanto resta in attesa una richiesta di consenso prima di scadere.
pub const CONSENT_TTL: std::time::Duration = std::time::Duration::from_secs(120);
/// Token di test usato da `new_test()`: le prove di integrazione devono poter
/// autenticare senza passare per l'UI di consenso.
pub const TEST_TOKEN: &str = "test-token-00000000000000000000000000000000";

/// Client autorizzato, come persistito in `clients.json`. Il file contiene
/// solo lo SHA-256 del token, mai il token in chiaro.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientRecord {
    pub id: String,
    pub label: String,
    pub token_sha256: String,
    pub created_at_ms: u64,
    pub last_seen_ms: u64,
}

/// Proiezione pubblica di un client per l'UI (niente hash).
#[derive(Debug, Clone, Serialize)]
pub struct ClientInfo {
    pub id: String,
    pub label: String,
    pub last_seen_ms: u64,
}

/// Richiesta di consenso in attesa di una risposta.
#[derive(Debug)]
struct PendingConsent {
    id: String,
    label: String,
    created_at_ms: u64,
    /// Dove consegnare l'esito (token o rifiuto) al socket che ha chiesto.
    tx: tokio::sync::mpsc::Sender<ConsentOutcome>,
}

/// Proiezione pubblica di un consenso pendente per l'UI.
#[derive(Debug, Clone, Serialize)]
pub struct ConsentInfo {
    pub id: String,
    pub label: String,
    pub created_at_ms: u64,
}

/// Esito consegnato al socket in attesa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentOutcome {
    Approved { token: String },
    Rejected,
}

/// Registro client + richieste di consenso.
///
/// La persistenza è best-effort: un errore di scrittura non deve bloccare il
/// flusso (il consenso appena dato vale per la sessione; il prossimo avvio
/// richiederà di nuovo l'approvazione).
#[derive(Debug, Default)]
pub struct ClientAuth {
    path: Option<PathBuf>,
    clients: Mutex<Vec<ClientRecord>>,
    consents: Mutex<HashMap<String, PendingConsent>>,
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn new_token() -> String {
    use rand::RngCore;

    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

impl ClientAuth {
    /// Carica il registro da `profile_dir/pairing/clients.json` (se esiste).
    /// Un file corrotto viene ignorato con un warning: si riparte vuoti e il
    /// consenso andrà richiesto di nuovo — mai un behavior di fiducia implicita.
    #[must_use]
    pub fn load(profile_dir: &Path) -> Self {
        let path = profile_dir.join("pairing").join("clients.json");
        let clients = match std::fs::read_to_string(&path) {
            Ok(raw) => match serde_json::from_str::<Vec<ClientRecord>>(&raw) {
                Ok(v) => v,
                Err(e) => {
                    warn!(path = ?path, "clients.json illeggibile, riparto da zero: {e}");
                    Vec::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                warn!(path = ?path, "lettura clients.json fallita: {e}");
                Vec::new()
            }
        };
        info!(n = clients.len(), "registro client locali caricato");
        Self {
            path: Some(path),
            clients: Mutex::new(clients),
            consents: Mutex::new(HashMap::new()),
        }
    }

    /// Registro in memoria senza I/O, con il token di test già autorizzato.
    #[must_use]
    pub fn new_test() -> Self {
        Self {
            path: None,
            clients: Mutex::new(vec![ClientRecord {
                id: "test-device".into(),
                label: "test".into(),
                token_sha256: sha256_hex(TEST_TOKEN.as_bytes()),
                created_at_ms: 0,
                last_seen_ms: 0,
            }]),
            consents: Mutex::new(HashMap::new()),
        }
    }

    /// Apre una richiesta di consenso e ritorna (id, ricevitore dell'esito).
    /// Il consenso scade dopo `CONSENT_TTL` (il chiamante chiude il socket).
    #[must_use]
    pub fn request_consent(
        &self,
        label: String,
    ) -> (String, tokio::sync::mpsc::Receiver<ConsentOutcome>) {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let id = uuid::Uuid::new_v4().to_string();
        let consent = PendingConsent {
            id: id.clone(),
            label,
            created_at_ms: now_ms(),
            tx,
        };
        let mut g = self.lock_consents();
        // TTL: evita che richieste abbandonate si accumulino senza limite.
        if g.len() >= 8 {
            let oldest = g
                .iter()
                .min_by_key(|(_, c)| c.created_at_ms)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                g.remove(&k);
            }
        }
        g.insert(id.clone(), consent);
        (id, rx)
    }

    /// Approva il consenso: emette il token, lo registra e lo consegna al
    /// socket in attesa. Ritorna il token (per test e diagnostica).
    ///
    /// # Errors
    /// `String` se il consenso non esiste o è già risolto.
    pub fn approve(&self, id: &str) -> Result<String, String> {
        let consent = self
            .take_consent(id)
            .ok_or_else(|| "consenso non trovato".to_string())?;
        if (consent.created_at_ms + u64::try_from(CONSENT_TTL.as_millis()).unwrap_or(u64::MAX))
            < now_ms()
        {
            return Err("consenso scaduto".into());
        }
        let token = new_token();
        let record = ClientRecord {
            id: consent.id.clone(),
            label: consent.label,
            token_sha256: sha256_hex(token.as_bytes()),
            created_at_ms: now_ms(),
            last_seen_ms: now_ms(),
        };
        self.lock_clients()?.push(record);
        self.save();
        let _ = consent.tx.try_send(ConsentOutcome::Approved {
            token: token.clone(),
        });
        Ok(token)
    }

    /// Rifiuta il consenso e lo comunica al socket in attesa.
    pub fn reject(&self, id: &str) -> bool {
        let Some(c) = self.take_consent(id) else {
            return false;
        };
        let _ = c.tx.try_send(ConsentOutcome::Rejected);
        true
    }

    /// Rimuove un consenso senza notificare (usato allo scadere del socket).
    pub fn expire(&self, id: &str) {
        self.take_consent(id);
    }

    /// Verifica un token presentato da un client locale. Confronto in tempo
    /// costante sullo SHA-256: uguale disciplina del pin TLS, per lo stesso
    /// motivo (il compare per byte tornerebbe prima al primo carattere diverso).
    #[must_use]
    pub fn authenticate(&self, token: &str) -> bool {
        let provided = sha256_hex(token.as_bytes());
        let Ok(mut clients) = self.lock_clients() else {
            return false;
        };
        let found = clients
            .iter()
            .map(|c| c.token_sha256.as_bytes())
            .any(|expected| constant_eq(expected, provided.as_bytes()));
        if found {
            // last_seen: best-effort, non blocca mai un'autenticazione valida.
            if let Some(c) = clients
                .iter_mut()
                .find(|c| c.token_sha256.as_bytes() == provided.as_bytes())
            {
                c.last_seen_ms = now_ms();
            }
            return true;
        }
        false
    }

    /// Client autorizzati (per l'UI, senza hash).
    #[must_use]
    pub fn list_clients(&self) -> Vec<ClientInfo> {
        let Ok(g) = self.lock_clients() else {
            return Vec::new();
        };
        g.iter()
            .map(|c| ClientInfo {
                id: c.id.clone(),
                label: c.label.clone(),
                last_seen_ms: c.last_seen_ms,
            })
            .collect()
    }

    /// Revoca un client: il suo token non autentica più (persistito subito).
    pub fn revoke(&self, id: &str) -> bool {
        let Ok(mut g) = self.lock_clients() else {
            return false;
        };
        let before = g.len();
        g.retain(|c| c.id != id);
        let removed = g.len() != before;
        drop(g);
        if removed {
            self.save();
        }
        removed
    }

    /// Richieste di consenso pendenti (per l'UI).
    #[must_use]
    pub fn pending(&self) -> Vec<ConsentInfo> {
        self.lock_consents()
            .values()
            .map(|c| ConsentInfo {
                id: c.id.clone(),
                label: c.label.clone(),
                created_at_ms: c.created_at_ms,
            })
            .collect()
    }

    fn lock_clients(&self) -> Result<MutexGuard<'_, Vec<ClientRecord>>, String> {
        self.clients
            .lock()
            .map_err(|_| "registry client avvelenato".to_string())
    }

    fn lock_consents(&self) -> MutexGuard<'_, HashMap<String, PendingConsent>> {
        self.consents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Estrae e rimuove un consenso senza notifica.
    fn take_consent(&self, id: &str) -> Option<PendingConsent> {
        self.lock_consents().remove(id)
    }

    /// Persistenza best-effort dei client (0600, nella casella `pairing/`).
    fn save(&self) {
        let Some(path) = &self.path else { return };
        let _ = (|| -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let raw = serde_json::to_vec_pretty(
                &*self
                    .lock_clients()
                    .map_err(|_| std::io::Error::other("lock"))?,
            )
            .map_err(std::io::Error::other)?;
            std::fs::write(path, raw)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        })()
        .inspect_err(|e| warn!(path = %path.display(), "salvataggio clients.json fallito: {e}"));
    }
}

/// Confronto a tempo costante di due byte array della stessa lunghezza.
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consenso_approvato_emette_un_token_autenticante() {
        let auth = ClientAuth::default();
        let (id, mut rx) = auth.request_consent("amianto-browser".into());
        let token = auth.approve(&id).expect("token");
        assert!(auth.authenticate(&token), "il token approvato autentica");
        assert!(
            !auth.authenticate("token-sbagliato"),
            "token estraneo rifiutato"
        );
        assert_eq!(
            rx.try_recv().ok(),
            Some(ConsentOutcome::Approved {
                token: token.clone()
            }),
            "il socket in attesa riceve il token"
        );
        assert_eq!(auth.pending().len(), 0, "consenso consumato");
    }

    #[test]
    fn consenso_rifiutato_non_autentica_nessuno() {
        let auth = ClientAuth::default();
        let (id, mut rx) = auth.request_consent("client".into());
        assert!(auth.reject(&id));
        assert_eq!(rx.try_recv().ok(), Some(ConsentOutcome::Rejected));
        assert!(!auth.authenticate("qualsiasi-token"));
        assert_eq!(auth.list_clients().len(), 0);
    }

    #[test]
    fn approve_di_consenso_inesistente_errore() {
        let auth = ClientAuth::default();
        assert!(auth.approve("inesistente").is_err());
    }

    #[test]
    fn revoca_invalida_il_token() {
        let auth = ClientAuth::default();
        let (id, _rx) = auth.request_consent("client".into());
        let token = auth.approve(&id).expect("token");
        assert!(auth.authenticate(&token));
        assert!(auth.revoke(&id), "il client esiste");
        assert!(
            !auth.authenticate(&token),
            "dopo la revoca il token non vale più"
        );
        assert!(!auth.revoke(&id), "seconda revoca: niente da fare");
    }

    #[test]
    fn token_notificato_una_volta_sola() {
        let auth = ClientAuth::default();
        let (id, mut rx) = auth.request_consent("client".into());
        let token = auth.approve(&id).expect("token");
        assert!(
            matches!(rx.try_recv(), Ok(ConsentOutcome::Approved { token: t }) if t == token),
            "prima notifica: token"
        );
        match rx.try_recv() {
            // Sender già droppato da `take_consent` (consenso risolto): anche
            // `Disconnected` è una garanzia di "una sola notifica".
            Err(
                tokio::sync::mpsc::error::TryRecvError::Empty
                | tokio::sync::mpsc::error::TryRecvError::Disconnected,
            ) => {}
            other => panic!("nessuna seconda notifica, ottenuto {other:?}"),
        }
    }

    #[test]
    fn persistenza_roundtrip_su_disco() {
        let dir = std::env::temp_dir().join(format!("nfc-local-auth-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let auth = ClientAuth::load(&dir);
        let (id, _rx) = auth.request_consent("client-di-persistenza".into());
        let token = auth.approve(&id).expect("token");
        drop(auth);

        let ricaricato = ClientAuth::load(&dir);
        assert!(
            ricaricato.authenticate(&token),
            "il token sopravvive al riavvio via clients.json"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn caricamento_file_corrotto_riparte_vuoto() {
        let dir =
            std::env::temp_dir().join(format!("nfc-local-auth-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("pairing").join("clients.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{non-json").unwrap();
        let auth = ClientAuth::load(&dir);
        assert!(
            auth.list_clients().is_empty(),
            "un file corrotto non deve ereditare fiducia"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
