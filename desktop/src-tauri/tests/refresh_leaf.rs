//! `--refresh-leaf`: rigenera la **sola foglia** con le SAN attuali, firmata
//! dalla CA invariata; la guardia deve distinguere un engine vivo da un
//! lockfile relitto (stessa logica di `--rotate-ca`).
//!
//! Test di integrazione sul **binario reale** (`CARGO_BIN_EXE`), non sulla
//! libreria, per due motivi.
//!
//! Primo: quello che conta è ciò che l'utente digita. La guardia potrebbe essere
//! al posto giusto nel crate e non venire raggiunta dalla CLI, e un test sulla
//! libreria passerebbe comunque.
//!
//! Secondo: l'isolamento del profilo. `NFC_REMOTE_HOME` è una variabile
//! d'ambiente di **processo**, e il crate vieta `unsafe` (quindi niente
//! `set_var`). Impostarla su un processo figlio lo risolve: il test non tocca
//! l'ambiente del proprio, che altrimenti renderebbe instabili i test paralleli
//! che leggono il profilo vero.

use std::{net::TcpListener, path::Path, process::Command};

/// Percorso unico: nessun altro processo deve toccarlo.
fn profilo_temporaneo() -> std::path::PathBuf {
    let unico = format!(
        "nfc-refresh-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let p = std::env::temp_dir().join(unico);
    std::fs::create_dir_all(&p).expect("dir temporanea");
    p
}

fn refresh_leaf(profilo: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nfc-desktop"))
        .arg("--refresh-leaf")
        .env("NFC_REMOTE_HOME", profilo)
        .output()
        .expect("esecuzione di nfc-desktop --refresh-leaf")
}

/// Un solo test: l'ambiente del processo figlio dipende dal profilo, e test
/// paralleli con profili diversi renderebbero le asserzioni dipendenti
/// dall'ordine di esecuzione.
#[test]
fn refresh_leaf_ruota_solo_la_foglia_con_ca_invariata() {
    let profilo = profilo_temporaneo();
    let ca = profilo.join("ca").join("nfc-local-root.pem");
    let foglia = profilo.join("tls").join("nfc.local.pem");
    let lock = profilo.join("engine.lock");

    // 1. Su profilo nuovo: la PKI viene generata e la foglia rifirmata subito
    //    (il refresh parte da `ensure_pki`). CA e foglia devono esistere.
    let out = refresh_leaf(&profilo);
    assert!(
        out.status.success(),
        "--refresh-leaf su profilo nuovo deve funzionare: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(ca.exists(), "la CA deve esistere dopo il refresh");
    assert!(foglia.exists(), "la foglia deve esistere dopo il refresh");

    let ca_prima = std::fs::read(&ca).expect("lettura CA");
    let foglia_prima = std::fs::read(&foglia).expect("lettura foglia");

    // 2. Secondo refresh: la CA resta byte-per-byte identica, la foglia
    //    cambia (seriale nuovo → cert diverso).
    let out = refresh_leaf(&profilo);
    assert!(
        out.status.success(),
        "il secondo refresh deve funzionare: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ca_dopo = std::fs::read(&ca).expect("rilettura CA");
    let foglia_dopo = std::fs::read(&foglia).expect("rilettura foglia");
    assert_eq!(ca_prima, ca_dopo, "il refresh non deve toccare la CA");
    assert_ne!(
        foglia_prima, foglia_dopo,
        "la foglia deve essere rigenerata"
    );

    // 3. Lockfile **e** porta TLS occupata: c'è un engine che serve davvero,
    //    e il refresh va rifiutato senza toccare i file (stessa guardia della
    //    rotazione: il pin dei QR viene letto da disco mentre il server
    //    presenterebbe in memoria la foglia vecchia).
    let ascoltatore =
        TcpListener::bind(("127.0.0.1", 8443)).expect("8443 libera all'inizio del test");
    std::fs::write(&lock, "4242\n").expect("scrittura lockfile");
    let prima = std::fs::read(&foglia).expect("lettura foglia");

    let out = refresh_leaf(&profilo);
    assert!(
        !out.status.success(),
        "--refresh-leaf deve fallire con un engine in ascolto su 8443"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("engine è in esecuzione"),
        "il messaggio deve dire ciò che blocca, non solo rifiutare: {stderr}"
    );
    let dopo = std::fs::read(&foglia).expect("rilettura foglia");
    assert_eq!(
        prima, dopo,
        "il refresh rifiutato non deve aver toccato il certificato"
    );

    drop(ascoltatore);
    let _ = std::fs::remove_dir_all(&profilo);
}
