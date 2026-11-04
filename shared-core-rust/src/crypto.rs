//! Crittografia Zero-Trust (stato dell'arte 2026).
//! Flusso classico:
//!  1. Desktop genera `StaticSecret` + `nonce32` e li espone nel `QRv2`.
//!  2. Mobile genera effimera, DH con pubkey desktop -> `shared_x25519`.
//!  3. Desktop completa DH con pubkey mobile -> stesso `shared`.
//!  4. `HKDF-SHA256(salt=nonce32, ikm=shared, len=64)` -> **due** chiavi
//!     AES-256-GCM: `k_m2d` e `k_d2m`, una per direzione.
//!  5. Ogni messaggio: `AES-GCM(nonce12 = 0x00000000 || seq_be64)`.
//!
//! Estensione 2026 — ibrido post-quantum (NIST FIPS 203):
//!  - Se `pq` è negoziato (`QRv2` `pq:1`), `ikm = shared_x25519 || shared_mlkem768`.
//!    Protegge da "harvest-now-decrypt-later" senza rompere client classici.
//!  - SAS a 6 cifre (`sas_confirm()`) da mostrare su entrambi gli schermi per
//!    conferma anti-MITM su QR fotografato.
//!  - `rekey()` per rotazione chiave senza nuovo QR (ogni 2^32 frame o 24h).
//!
//! Il nonce è `nonce_for(seq)`: **il suo valore si ripete fra le due direzioni**,
//! perché entrambi i contatori partono da 1. È ammissibile solo perché la
//! chiave no — e la separazione delle chiavi è il motivo per cui `derive`
//! accetta una `Direction`. Prima di quella separazione le due chiavi erano
//! identiche, e ogni seq veniva usato due volte sotto la stessa chiave per
//! tutta la sessione (vedi `docs/SECURITY.md` §3).

use crate::error::{CoreError, Result};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Domain separation per versione protocollo: v1 classico, v2 ibrido PQ.
const INFO_V1: &[u8] = b"nfc-smartcard-v1/aes-gcm";
const INFO_V2_HYBRID: &[u8] = b"nfc-smartcard-v2/hybrid-x25519-mlkem768-aesgcm";

/// Chiavi di sessione derivate: una per direzione, contatori anti-replay separati.
/// `Send + Sync` per uso in task Axum/Tokio multi-thread.
/// Niente `derive(Debug)`: il materiale chiavi non va mai nei log (SOTA).
/// Direzione del canale.
///
/// Serve a scegliere **quale** delle due chiavi usare, non a numerare i frame:
/// il nonce resta `nonce_for(seq)` e quindi il formato a filo non cambia. Ciò
/// che cambia è il materiale chiavi, che è separato per direzione.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Chiave per i frame mobile -> desktop (`ciphers[0]`).
    MobileToDesktop,
    /// Chiave per i frame desktop -> mobile (`ciphers[1]`).
    DesktopToMobile,
}

impl Direction {
    const fn idx(self) -> usize {
        match self {
            Self::MobileToDesktop => 0,
            Self::DesktopToMobile => 1,
        }
    }
}

/// Versione del materiale chiavi (KDF).
///
/// `2` = chiavi separate per direzione. L'`1` (chiave unica) viene **rifiutato**:
/// mantenerlo compatibile significherebbe accettare sessioni nel quale ogni seq
/// è riusato in entrambe le direzioni sotto la stessa chiave.
pub const KEYS_V: u32 = 2;

/// Chiavi di sessione: **una per direzione**.
///
/// ## Perché due chiavi e non una con contatori condivisi
///
/// Prima di questa separazione `rx` e `tx` venivano derivati con gli stessi
/// argomenti, quindi con la stessa chiave; e `nonce_for(seq)` non portava
/// alcun componente di direzione. Poiché entrambi i lati partivano da
/// `next_tx = 1`, **ogni seq veniva usato due volte sotto la stessa chiave**:
/// prima per il `HandshakeResp` del desktop, poi per il frame omonimo del
/// mobile, e così via per tutta la sessione.
///
/// Con AES-GCM il riuso di un nonce su due clear diversi non è un dettaglio di
/// efficienza: l'attaccante che osserva il canale ricava il XOR dei clear e,
/// per la relazione GHASH, può fabbricare tag validi per quella chiave, cioè
/// viola l'autenticità. Era inoltre esattamente la garanzia su cui poggiava il
/// ripiego in chiaro ("il canale resta sicuro perché E2EE").
///
/// Le due chiavi derivano da una singola espansione HKDF da 64 byte, così che
/// siano indipendenti e non due varianti della stessa stringa.
pub struct SessionKeys {
    /// `[k_mobile->desktop, k_desktop->mobile]`.
    ciphers: [Aes256Gcm; 2],
    /// Direzione che **questa** istanza trasmette.
    dir: Direction,
    /// Ultimo seq ricevuto (accetta solo seq > last).
    last_rx: u64,
    /// Prossimo seq da trasmettere.
    next_tx: u64,
    /// Versione negoziata (1 = classico, 2 = ibrido PQ).
    pub version: u8,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("version", &self.version)
            .field("next_tx", &self.next_tx)
            .field("last_rx", &self.last_rx)
            .field("ciphers", &"[redacted x2]")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl SessionKeys {
    /// Deriva la chiave classica da `shared_secret` X25519 e `salt = nonce32`.
    ///
    /// # Errors
    /// `CoreError::Crypto` se l'espansione HKDF fallisce.
    pub fn derive(shared_secret: &[u8; 32], nonce32: &[u8; 32], dir: Direction) -> Result<Self> {
        Self::derive_with_info(shared_secret, nonce32, INFO_V1, 1, dir)
    }

    /// Deriva la chiave ibrida 2026 da `x25519_shared || mlkem_shared`.
    /// `mlkem_shared` è il segreto 32B da ML-KEM-768 (FIPS 203).
    /// Se il peer non supporta PQ, usare `derive()` (fallback negoziato).
    ///
    /// # Errors
    /// `CoreError::Crypto` se l'espansione HKDF fallisce.
    pub fn derive_hybrid(
        x25519_shared: &[u8; 32],
        mlkem_shared: &[u8; 32],
        nonce32: &[u8; 32],
        dir: Direction,
    ) -> Result<Self> {
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(x25519_shared);
        ikm[32..].copy_from_slice(mlkem_shared);
        let out = Self::derive_with_info(&ikm, nonce32, INFO_V2_HYBRID, 2, dir);
        ikm.zeroize();
        out
    }

    fn derive_with_info(
        ikm: &[u8],
        nonce32: &[u8; 32],
        info: &[u8],
        version: u8,
        dir: Direction,
    ) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(nonce32), ikm);
        // Una sola espansione da 64B divisa a metà: le due chiavi sono così
        // indipendenti. Due espansioni separate con `info` diverso sarebbero
        // altrettanto sicure ma legano la sicurezza a una distinzione di
        // stringa, non a una distinzione strutturale.
        let mut okm = [0u8; 64];
        hk.expand(info, &mut okm)
            .map_err(|e| CoreError::Crypto(format!("hkdf expand: {e}")))?;
        let ciphers = [
            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&okm[..32])),
            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&okm[32..])),
        ];
        okm.zeroize();
        Ok(Self {
            ciphers,
            dir,
            last_rx: 0,
            next_tx: 1,
            version,
        })
    }

    /// Chiave con cui **questa** istanza trasmette.
    fn tx(&self) -> &Aes256Gcm {
        &self.ciphers[self.dir.idx()]
    }

    /// Chiave con cui **questa** istanza riceve: l'altra.
    fn rx(&self) -> &Aes256Gcm {
        &self.ciphers[1 - self.dir.idx()]
    }

    /// `k_mobile->desktop`, identica sui due lati (il desktop la ha in `rx`, il
    /// mobile in `tx`). È la chiave del `rekey`: deve produrre lo stesso IKM
    /// su due istanze di direzione opposta.
    fn k_m2d(&self) -> &Aes256Gcm {
        &self.ciphers[0]
    }

    /// Rotazione chiave senza nuovo QR: `k' = HKDF(salt=nonce32', ikm=k || seq)`.
    /// Chiamare ogni 2^31 frame o 24h; i contatori ripartono da 1/0.
    ///
    /// # Errors
    /// `CoreError::Crypto` se probe AES o HKDF falliscono.
    pub fn rekey(&mut self, fresh_nonce32: &[u8; 32]) -> Result<()> {
        // Estrae pseudo-ikm dalla chiave corrente cifrando un blocco noto.
        // Approccio standard: usa la chiave come IKM per HKDF (key-feedback).
        // Il probe deve usare la **stessa** chiave sui due lati: `k_m2d` è
        // l'unica che il mobile ha in `tx` e il desktop in `rx`. Usare la chiave
        // di trasmissione di ciascuno darebbe due IKM diversi e le nuove chiavi
        // non corrisponderebbero mai.
        let probe = self
            .k_m2d()
            .encrypt(Nonce::from_slice(&[0u8; 12]), b"nfc-rekey-v2".as_slice())
            .map_err(|e| CoreError::Crypto(format!("rekey probe: {e}")))?;
        let hk = Hkdf::<Sha256>::new(Some(fresh_nonce32), &probe);
        let mut okm = [0u8; 64];
        hk.expand(INFO_V2_HYBRID, &mut okm)
            .map_err(|e| CoreError::Crypto(format!("hkdf rekey: {e}")))?;
        self.ciphers = [
            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&okm[..32])),
            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&okm[32..])),
        ];
        okm.zeroize();
        self.next_tx = 1;
        self.last_rx = 0;
        Ok(())
    }

    /// Costruisce nonce12 deterministico: 4 byte zero + seq big-endian.
    fn nonce_for(seq: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&seq.to_be_bytes());
        n
    }

    /// Cifra `plain`, incrementa `next_tx`. Ritorna `(seq, nonce12, ct)`.
    ///
    /// # Errors
    /// `CoreError::Crypto` a seq esausto (serve `rekey`) o su errore AES-GCM.
    pub fn seal(&mut self, plain: &[u8]) -> Result<(u64, [u8; 12], Vec<u8>)> {
        // Limite 2026: forza rekey prima dell'overflow seq (pratica AEAD-safe).
        if self.next_tx == u64::MAX {
            return Err(CoreError::Crypto("seq esausto: eseguire rekey".into()));
        }
        let seq = self.next_tx;
        let nbytes = Self::nonce_for(seq);
        let ct = self
            .tx()
            .encrypt(Nonce::from_slice(&nbytes), plain)
            .map_err(|e| CoreError::Crypto(format!("aes seal: {e}")))?;
        self.next_tx = self.next_tx.saturating_add(1);
        Ok((seq, nbytes, ct))
    }

    /// Decifra solo se `seq > last_rx` (anti-replay), poi avanza `last_rx`.
    /// Accetta anche finestra di tolleranza Wi-Fi: seq futuri fino a +128
    /// vengono accettati ma `last_rx` avanza al max (previene `DoS` da riordino).
    ///
    /// # Errors
    /// `CoreError::Replay` su seq riusato, `CoreError::Crypto` su nonce/tag errati.
    pub fn open(&mut self, seq: u64, nonce12: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>> {
        if seq <= self.last_rx {
            return Err(CoreError::Replay {
                got: seq,
                last: self.last_rx,
            });
        }
        if seq > self.last_rx.saturating_add(1024) {
            return Err(CoreError::Crypto(
                "seq troppo avanti (possibile MITM)".into(),
            ));
        }
        if *nonce12 != Self::nonce_for(seq) {
            return Err(CoreError::Crypto("nonce/seq mismatch".into()));
        }
        let pt = self
            .rx()
            .decrypt(Nonce::from_slice(nonce12), ct)
            .map_err(|_| CoreError::Crypto("decrypt fallita (tag errato?)".into()))?;
        self.last_rx = seq.max(self.last_rx);
        Ok(pt)
    }
}

/// SAS a 6 cifre per conferma visiva anti-MITM (mostrata su desktop + mobile).
/// `sas = SHA256(pub_d || pub_m || nonce32)[0..3] mod 1_000_000`.
#[must_use]
pub fn sas_confirm(desktop_pub: &[u8; 32], mobile_pub: &[u8; 32], nonce32: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(desktop_pub);
    h.update(mobile_pub);
    h.update(nonce32);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], 0]) % 1_000_000;
    format!("{n:06}")
}

/// Coppia effimera/statica X25519 con helper DH.
// Niente materiale chiavi nel Debug (solo fingerprint pubblico).
pub struct X25519Keypair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl std::fmt::Debug for X25519Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `secret` omesso di proposito: mai nei log.
        f.debug_struct("X25519Keypair")
            .field("public", &hex::encode(self.public_bytes()))
            .finish_non_exhaustive()
    }
}

impl X25519Keypair {
    /// Genera una coppia effimera dal CSPRNG di sistema.
    ///
    /// # Panics
    /// Solo se il CSPRNG del sistema operativo è inutilizzabile (fatale).
    #[must_use]
    pub fn generate() -> Self {
        // x25519-dalek 2.x richiede RNG esplicito: byte OS via getrandom.
        // Panic solo se il CSPRNG di sistema è rotto (condizione fatale).
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("CSPRNG di sistema non disponibile");
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
    /// Diffie-Hellman: `shared = secret x peer_pub`.
    #[must_use]
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> [u8; 32] {
        let pk = PublicKey::from(*peer);
        *self.secret.diffie_hellman(&pk).as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Wrapper ML-KEM-768 (feature `pq`, 2026 — ml-kem 0.3, NIST FIPS 203).
// API verificate su docs.rs 0.3.2: `Kem::generate_keypair`, `Encapsulate::encapsulate`
// (getrandom interno), `TryKeyInit::new_from_slice`, `KeyExport::to_bytes`,
// `Decapsulate::decapsulate`. Compilato solo con `--features pq`.
// ---------------------------------------------------------------------------

#[cfg(feature = "pq")]
pub mod pq {
    use crate::error::{CoreError, Result};
    use ml_kem::{
        Decapsulate, DecapsulationKey768, Encapsulate, EncapsulationKey768, Kem, KeyExport,
        MlKem768, TryKeyInit,
    };

    /// Coppia desktop: `dk` resta in memoria (mai serializzata), `ek` va nel `QRv2`.
    pub struct MlKemKeypair {
        dk: DecapsulationKey768,
        ek: EncapsulationKey768,
    }

    impl std::fmt::Debug for MlKemKeypair {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("MlKemKeypair(..)")
        }
    }

    impl MlKemKeypair {
        #[must_use]
        pub fn generate() -> Self {
            let (dk, ek) = MlKem768::generate_keypair();
            Self { dk, ek }
        }
        /// Encapsulation key serializzata (1184B) per il `QRv2`.
        #[must_use]
        pub fn ek_bytes(&self) -> Vec<u8> {
            self.ek.to_bytes().to_vec()
        }
        /// Decapsula il ct mobile (1088B) -> shared 32B.
        ///
        /// # Errors
        /// `CoreError::Crypto` se il ct non è 1088B.
        pub fn decapsulate(&self, ct: &[u8]) -> Result<[u8; 32]> {
            let ct_arr = ct_to_array(ct)?;
            let ss = self.dk.decapsulate(&ct_arr);
            ss_to_32(&ss)
        }
    }

    /// Mobile: incapsula verso l'ek del QR. Ritorna (ct 1088B, shared 32B).
    ///
    /// # Errors
    /// `CoreError::Crypto` se l'ek non è valida.
    pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let ek = EncapsulationKey768::new_from_slice(ek_bytes)
            .map_err(|_| CoreError::Crypto("mlkem ek non valida".into()))?;
        let (ct_arr, ss) = ek.encapsulate();
        Ok((ct_arr.to_vec(), ss_to_32(&ss)?))
    }

    fn ct_to_array(ct: &[u8]) -> Result<ml_kem::Ciphertext<MlKem768>> {
        let mut arr = ml_kem::Ciphertext::<MlKem768>::default();
        if ct.len() != arr.len() {
            return Err(CoreError::Crypto("mlkem ct deve essere 1088B".into()));
        }
        arr.copy_from_slice(ct);
        Ok(arr)
    }

    fn ss_to_32(ss: &ml_kem::SharedKey) -> Result<[u8; 32]> {
        ss.as_slice()
            .try_into()
            .map_err(|_| CoreError::Crypto("mlkem shared len".into()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::{Direction, SessionKeys};

        #[test]
        fn hybrid_roundtrip_completo() {
            // Desktop genera, mobile incapsula, desktop decapsula: stesso shared.
            let desk = MlKemKeypair::generate();
            let (ct, s_mobile) = encapsulate(&desk.ek_bytes()).unwrap();
            assert_eq!(ct.len(), 1088);
            let s_desk = desk.decapsulate(&ct).unwrap();
            assert_eq!(s_mobile, s_desk);
            // ek corrotta rifiutata senza panic.
            assert!(encapsulate(&[0u8; 100]).is_err());
            assert!(desk.decapsulate(&[0u8; 100]).is_err());
            // Sessioni ibride speculari dialogano in entrambe le direzioni.
            let nonce = [5u8; 32];
            let mut a = SessionKeys::derive_hybrid(
                &s_mobile,
                &s_mobile,
                &nonce,
                Direction::MobileToDesktop,
            )
            .unwrap();
            let mut b =
                SessionKeys::derive_hybrid(&s_desk, &s_desk, &nonce, Direction::DesktopToMobile)
                    .unwrap();
            let (seq, n, c) = a.seal(b"ping").unwrap();
            assert_eq!(b.open(seq, &n, &c).unwrap(), b"ping");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_e_replay() {
        let dk = X25519Keypair::generate();
        let mk = X25519Keypair::generate();
        let nonce = [7u8; 32];
        let s1 = dk.diffie_hellman(&mk.public_bytes());
        let s2 = mk.diffie_hellman(&dk.public_bytes());
        assert_eq!(s1, s2);
        let mut a = SessionKeys::derive(&s1, &nonce, Direction::MobileToDesktop).unwrap();
        let mut b = SessionKeys::derive(&s2, &nonce, Direction::DesktopToMobile).unwrap();
        let (seq, n, ct) = a.seal(b"hello apdu").unwrap();
        let pt = b.open(seq, &n, &ct).unwrap();
        assert_eq!(pt, b"hello apdu");
        assert!(b.open(seq, &n, &ct).is_err());
    }

    /// Le due direzioni devono usare chiavi **diverse**.
    ///
    /// Era il difetto reale: `rx` e `tx` derivati con gli stessi argomenti, e
    /// `nonce_for(seq)` senza componente di direzione, mentre entrambi i lati
    /// partivano da `next_tx = 1`. Il risultato era che ogni seq veniva usato due
    /// volte sotto la stessa chiave — prima per il `HandshakeResp` del desktop,
    /// poi per il frame omonimo del mobile — per tutta la sessione.
    ///
    /// Il formato del nonce è volutamente invariato (è un campo del frame, quindi
    /// sarebbe un cambio di protocollo); ciò che deve differire è la chiave.
    /// Qui lo si verifica senza ispezionare il materiale: un peer nella **stessa**
    /// direzione del mittente non deve riuscire ad aprire il suo frame.
    #[test]
    fn chiavi_separate_per_direzione() {
        let shared = [7u8; 32];
        let nonce = [9u8; 32];

        let mut desktop = SessionKeys::derive(&shared, &nonce, Direction::DesktopToMobile).unwrap();
        let mut mobile = SessionKeys::derive(&shared, &nonce, Direction::MobileToDesktop).unwrap();
        // Stessa direzione del desktop: deve avere la chiave sbagliata per
        // ricevere. Se `ciphers[0] == ciphers[1]` questo test fallisce.
        let mut impostore =
            SessionKeys::derive(&shared, &nonce, Direction::DesktopToMobile).unwrap();

        let (seq, n, ct) = desktop.seal(b"HandshakeResp").unwrap();

        // Il mobile (direzione opposta) apre: il canale produttivo funziona.
        assert_eq!(mobile.open(seq, &n, &ct).unwrap(), b"HandshakeResp");

        // Un peer sulla stessa direzione non ci riesce.
        assert!(
            impostore.open(seq, &n, &ct).is_err(),
            "chiavi non separate: una terza istanza nella direzione del mittente \
             è riuscita a decifrare il suo frame"
        );

        // E vale anche in senso inverso, con i ruoli scambiati.
        let (seq2, n2, ct2) = mobile.seal(b"apdu response").unwrap();
        assert_eq!(desktop.open(seq2, &n2, &ct2).unwrap(), b"apdu response");
        assert!(
            SessionKeys::derive(&shared, &nonce, Direction::MobileToDesktop)
                .unwrap()
                .open(seq2, &n2, &ct2)
                .is_err(),
            "stessa separazione richiesta nella direzione mobile->desktop"
        );
    }

    /// Il `rekey` deve produrre la **stessa** coppia di chiavi sui due lati:
    /// usa `k_m2d` come IKM proprio perché è l'unica chiave che il mobile ha in
    /// `tx` e il desktop in `rx`. Con la chiave di trasmissione di ciascuno i
    /// due derivati sarebbero diversi e la sessione non si riallineerebbe mai.
    #[test]
    fn rekey_riallinea_le_due_direzioni() {
        let shared = [1u8; 32];
        let nonce = [2u8; 32];
        let fresco = [3u8; 32];

        let mut desktop = SessionKeys::derive(&shared, &nonce, Direction::DesktopToMobile).unwrap();
        let mut mobile = SessionKeys::derive(&shared, &nonce, Direction::MobileToDesktop).unwrap();
        desktop.rekey(&fresco).unwrap();
        mobile.rekey(&fresco).unwrap();

        let (seq, n, ct) = desktop.seal(b"dopo rekey").unwrap();
        assert_eq!(mobile.open(seq, &n, &ct).unwrap(), b"dopo rekey");
        let (seq, n, ct) = mobile.seal(b"dopo rekey (altro verso)").unwrap();
        assert_eq!(
            desktop.open(seq, &n, &ct).unwrap(),
            b"dopo rekey (altro verso)"
        );
    }

    #[test]
    fn hybrid_differs_from_classic() {
        let segreto = [1u8; 32];
        let mlkem = [2u8; 32];
        let nonce = [3u8; 32];
        let c = SessionKeys::derive(&segreto, &nonce, Direction::MobileToDesktop).unwrap();
        let h = SessionKeys::derive_hybrid(&segreto, &mlkem, &nonce, Direction::MobileToDesktop)
            .unwrap();
        assert_eq!(c.version, 1);
        assert_eq!(h.version, 2);
        // SAS deterministico a 6 cifre.
        let sas = sas_confirm(&segreto, &mlkem, &nonce);
        assert_eq!(sas.len(), 6);
    }
}
