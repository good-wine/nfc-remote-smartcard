/// Build script: compila proto/smartcard.proto con prost-build.
/// Architettura: il .proto è l'unica fonte di verità per i frame E2EE mobile<->desktop.
fn main() {
    let proto = "proto/smartcard.proto";
    println!("cargo:rerun-if-changed={proto}");
    prost_build::compile_protos(&[proto], &["proto/"]).expect("prost-build fallita");
}
