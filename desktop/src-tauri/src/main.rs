//! Binario desktop (tray o --daemon headless).
//! CLI 2026:
//!  - (nessun flag): avvia la tray app / engine.
//!  - `--daemon`: headless IT/GPO.
//!  - `--setup-local-domain`: genera CA+foglia nfc.local e stampa hosts/trust, poi esce.
//!  - `--rotate-ca`: rigenera CA+foglia (ridistribuire la fiducia), poi esce.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if nfc_desktop_lib::local_tls::handle_cli() {
        return;
    }
    nfc_desktop_lib::run();
}
