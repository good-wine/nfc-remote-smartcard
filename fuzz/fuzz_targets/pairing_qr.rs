//! Fuzzing del QR di pairing (`decode_qr`/`encode_qr`), prefissi v1 e v2.
//! Eseguire dalla root del repo: `cargo +nightly fuzz run pairing_qr -- -max_total_time=120`
#![no_main]

use libfuzzer_sys::fuzz_target;
use nfc_core::pairing::PairingPayload;

fuzz_target!(|data: &[u8]| {
    // Il QR è testo: qualunque byte va reso in stringa lossy, mai panic.
    // `decode_qr` non valida la scadenza, quindi non serve un `now`.
    let s = String::from_utf8_lossy(data);
    if let Ok(payload) = PairingPayload::decode_qr(&s) {
        // Invariante di round-trip: encode_qr -> decode_qr deve riuscire di nuovo.
        if let Ok(qr) = payload.encode_qr() {
            assert!(
                PairingPayload::decode_qr(&qr).is_ok(),
                "round-trip QR non stabile"
            );
        }
    }
});
