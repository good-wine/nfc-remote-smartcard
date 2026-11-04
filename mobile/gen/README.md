# Bridge nativi NFC (Android/iOS)

`mobile/gen/` contiene i **sorgenti nativi scritti a mano** (non generati da Tauri)
che danno al mobile accesso alla carta via NFC. Sono versionati di proposito: la
cartella generata da `tauri android init` / `tauri ios init` è `mobile/src-tauri/gen/`
(ignorata da git) e viene riscritta dai comandi Tauri — i file qui sotto sono la
fonte di verità da riapplicare dopo una rigenerazione.

## Contenuto

| File | Ruolo |
| --- | --- |
| `android/NfcIsoDepHandler.kt` | Reader-mode Android 15/16 (`enableReaderMode` + `IsoDep`): connect con ATR, `transceive` suspend (timeout 8s, controllo presenza), eventi `SharedFlow` `Inserted`/`Removed`/`Apdu`. |
| `ios/NfcBridge.swift` | CoreNFC (`NFCTagReaderSession.iso14443`): APDU raw ISO7816, `send(apdu:) async throws -> (data, sw1, sw2)`, callback `onCard`/`onLost`. |
| `../AndroidManifest.fragment.xml` | Permessi NFC/CAMERA/INTERNET + intent-filter `TECH_DISCOVERED`, da fondere nel manifest generato. |
| `../nfc_tech_filter.xml` | Filtro tecnologie (`IsoDep`, `NfcA`) per `res/xml/`. |
| `../src-tauri/Info.ios.plist` | Chiavi iOS (usage description, formati NFC, select-identifiers): Tauri lo unisce da solo all'`Info.plist` del target. |

## Contratto con il core Rust (`mobile/src-tauri/src/lib.rs`)

- **desktop → mobile**: ogni `ApduRequest` decifrata emette l'evento Tauri
  `mobile-apdu-request` con `{session_id, request_id, apdu_hex}`; il bridge la
  esegue sulla carta e risponde col comando
  `mobile_apdu_reply(session_id, request_id, data_hex, sw1, sw2)`
  (`data_hex` senza SW; `sw1`/`sw2` decimali).
- **timeout**: se la risposta non arriva entro `timeout_ms`, il core replica al
  desktop la risposta onesta `6F00` (no-card).
- **mobile → desktop**: `nfc_card_event(kind, atr_hex?, session_id?)` con
  `kind = inserted|removed|reading` inoltra l'evento cifrato.
- La UI ascolta anche `nfc-card-status` (`{status, atr_hex?}`) per il feedback
  di stato: pensato per il glue nativo.
- `mobile_transmit` è **solo** il loopback di sviluppo (mock `9000`).

Il glue di piattaforma (registrazione del listener su `mobile-apdu-request`,
chiamata a `transceive`/`send`, risposta via invoke di `mobile_apdu_reply`)
vive nel progetto nativo generato: va completato nel bootstrap, il contratto
è quello qui sopra.

## Integrazione Android

1. Genera il progetto nativo (una tantum, richiede Android SDK):
   `cd mobile && npx tauri android init` → `mobile/src-tauri/gen/android/`.
2. Copia `android/NfcIsoDepHandler.kt` nel package `it.nfcremote.mobile`
   (la cartella che contiene la `MainActivity.kt` generata:
   `app/src/main/java/it/nfcremote/mobile/`).
3. Fonda `AndroidManifest.fragment.xml` in
   `app/src/main/AndroidManifest.xml` del progetto generato.
4. Copia `nfc_tech_filter.xml` in `app/src/main/res/xml/nfc_tech_filter.xml`.

## Integrazione iOS (richiede macOS)

1. `cd mobile && npx tauri ios init` → progetto Xcode in
   `mobile/src-tauri/gen/apple/` (generato via XcodeGen da `project.yml`:
   riapplicare a mano le modifiche dopo una rigenerazione).
2. Aggiungi `ios/NfcBridge.swift` al target `<Nome>_iOS` (gruppo Sources).
3. Abilita la capability NFC e aggiorna l'entitlements del target
   (`gen/apple/<Nome>_iOS/<Nome>_iOS.entitlements`).
4. Le chiavi usage/select-identifiers sono già in `src-tauri/Info.ios.plist`,
   unito automaticamente: nessun edit a mano del plist generato.
5. Per la submission serve un `PrivacyInfo.xcprivacy` in `gen/apple/`
   (nessun tracking; vedi header di `NfcBridge.swift`).
