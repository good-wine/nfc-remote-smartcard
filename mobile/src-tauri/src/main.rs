//! Binario mobile (Tauri 2): avvia il plugin E2EE + barcode scanner.
//! Il traffico NFC viaggia cifrato (E2EE ibrido PQ) verso il desktop engine.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    nfc_mobile_lib::run();
}
