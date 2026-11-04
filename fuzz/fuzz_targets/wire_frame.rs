//! Fuzzing del wire protocol: parsing di `EncryptedFrame`/`PlainFrame` (prost).
//! Eseguire dalla root del repo: `cargo +nightly fuzz run wire_frame -- -max_total_time=120`
#![no_main]

use libfuzzer_sys::fuzz_target;
use nfc_core::protocol::{decode_encrypted, decode_plain, encode_plain};

fuzz_target!(|data: &[u8]| {
    // Input arbitrario non deve mai andare in panic: i decoder prost riportano Err.
    let _ = decode_encrypted(data);

    // Invariante di round-trip: un PlainFrame decodificato deve ri-encodarsi in
    // bytes che decodificano di nuovo senza errore (prost è totale in proto3).
    if let Ok(frame) = decode_plain(data) {
        let reencoded = encode_plain(&frame);
        assert!(
            decode_plain(&reencoded).is_ok(),
            "round-trip PlainFrame non stabile"
        );
    }
});
