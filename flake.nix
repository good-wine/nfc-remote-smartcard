# Ambiente di sviluppo riproducibile 2026: Rust stable + protoc + Node 22 +
# dipendenze Tauri desktop (webkitgtk, libpcsclite per feature `physical`).
{
  description = "NFC Remote Smartcard dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "clippy" "rustfmt" ];
        };
      in {
        devShells.default = pkgs.mkShell {
          packages = [
            rust
            pkgs.protobuf
            pkgs.pkg-config
            pkgs.nodejs_22
            pkgs.gtk3
            pkgs.webkitgtk_4_1
            pkgs.libusb1
            pkgs.pcsc-lite
            pkgs.openssl
          ];
          shellHook = ''
            echo "NFC Remote dev shell: $(rustc --version), $(node --version)"
          '';
        };
      });
}
