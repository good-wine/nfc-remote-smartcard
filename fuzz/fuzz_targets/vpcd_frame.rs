//! Fuzzing del framing vpcd (`len || cmd || payload`).
//! Eseguire dalla root del repo: `cargo +nightly fuzz run vpcd_frame -- -max_total_time=120`
#![no_main]

use libfuzzer_sys::fuzz_target;
use nfc_desktop_lib::vpcd::{decode_response, encode_request, VpcdCmd};

fuzz_target!(|data: &[u8]| {
    // Il decoder non deve mai andare in panic né allocare oltre il limite.
    let _ = decode_response(data);
    // L'encoder è totale sotto 4GB: l'assert documenta l'invariante (bug se fallisce).
    if data.len() < 65536 {
        let encoded = encode_request(VpcdCmd::Transmit, data);
        assert!(encoded.is_ok());
    }
});
