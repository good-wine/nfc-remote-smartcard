//! `--rotate-ca`: la guardia deve distinguere un engine vivo da un lockfile
//! relitto.
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
        "nfc-rotate-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let p = std::env::temp_dir().join(unico);
    std::fs::create_dir_all(&p).expect("dir temporanea");
    p
}

fn rotate_ca(profilo: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nfc-desktop"))
        .arg("--rotate-ca")
        .env("NFC_REMOTE_HOME", profilo)
        .output()
        .expect("esecuzione di nfc-desktop --rotate-ca")
}

/// Un solo test: l'ambiente del processo figlio dipende dal profilo, e test
/// paralleli con profili diversi renderebbero le asserzioni dipendenti
/// dall'ordine di esecuzione.
#[test]
fn rotate_ca_rifiuta_solo_con_un_engine_vivo() {
    let profilo = profilo_temporaneo();
    let foglia = profilo.join("tls").join("nfc.local.pem");
    let lock = profilo.join("engine.lock");

    // 1. Senza lock la rotazione procede e la PKI viene generata.
    let out = rotate_ca(&profilo);
    assert!(
        out.status.success(),
        "--rotate-ca senza engine deve funzionare: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(foglia.exists(), "la foglia deve esistere dopo la rotazione");

    // 2. Lockfile presente ma **porta TLS libera**: è il caso normale dopo un
    //    `systemctl stop` o un `Ctrl-C`, perché `SIGTERM` non passa da
    //    `RunEvent::Exit` e il file resta a terra. Se la rotazione si fermasse
    //    qui, ogni shutdown lascerebbe un relitto da cancellare a mano e la
    //    rotazione diventerebbe impraticabile dopo il primo spegnimento.
    std::fs::write(&lock, "4242\n").expect("scrittura lockfile");
    let out = rotate_ca(&profilo);
    assert!(
        out.status.success(),
        "un lockfile relitto non deve bloccare la rotazione: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // E il relitto va rimosso: lasciarlo consumerebbe la guardia una volta sola e
    // i relitti si accumulerebbero a ogni shutdown.
    assert!(
        !lock.exists(),
        "il lockfile relitto doveva essere ripulito dalla rotazione"
    );

    // 3. Lockfile **e** porta TLS occupata: qui c'è un engine che serve davvero,
    //    e la rotazione va rifiutata. Il listener nel processo di test sta al
    //    posto dell'engine: la guardia verifica "qualcuno è in ascolto", che è
    //    la domanda che conta.
    let ascoltatore =
        TcpListener::bind(("127.0.0.1", 8443)).expect("8443 libera all'inizio del test");
    std::fs::write(&lock, "4242\n").expect("riscrittura lockfile");
    let prima = std::fs::read(&foglia).expect("lettura foglia");

    let out = rotate_ca(&profilo);
    assert!(
        !out.status.success(),
        "--rotate-ca deve fallire con un engine in ascolto su 8443"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("engine è in esecuzione"),
        "il messaggio deve dire chiocché blocca, non solo rifiutare: {stderr}"
    );

    // 4. Il punto della protezione: i file devono essere **intatti**. Se la
    //    rotazione fosse avvenuta lo stesso, il pericolo sarebbe peggiore di
    //    prima — l'engine serve in memoria il vecchio certificato, mentre i QR
    //    nuovi porterebbero il pin di quello nuovo: ogni pairing fallirebbe con
    //    un errore che sembrerebbe un attacco, e rigenerare il QR non aiuterebbe.
    let dopo = std::fs::read(&foglia).expect("rilettura foglia");
    assert_eq!(
        prima, dopo,
        "la rotazione rifiutata non deve aver toccato il certificato"
    );

    drop(ascoltatore);
    let _ = std::fs::remove_dir_all(&profilo);
}
