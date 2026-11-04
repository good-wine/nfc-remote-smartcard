#!/usr/bin/env bash
# Package estensione per store + developer mode.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)/browser-extension"
(cd "$ROOT" && npm install && npm run build)
echo "dist/ pronta per 'Load unpacked'. Zip: nfc-extension.zip"
