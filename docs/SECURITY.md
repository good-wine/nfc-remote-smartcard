# Sicurezza Zero-Trust (ed. 2026 — ibrida post-quantum)

## 0. Novità 2026 rispetto alla v1
- Handshake **negoziato**: classico `X25519` oppure **ibrido `X25519+ML-KEM-768`**
  (FIPS 203) con domain separation `v1/v2`. Il QRv2 annuncia `pq:1 + mlkem ek`.
- **SAS a 6 cifre** mostrata su desktop + mobile per conferma anti-MITM.
- **Rekey** senza nuovo QR (ogni 2^31 frame / 24h) + finestra anti-riordino Wi-Fi.
- Trasporto su **Axum + rustls**: 8443 TLS su tutte le interfacce (primario,
  anche per il mobile in LAN con **pin del certificato foglia** letto dal QR),
  8080 in chiaro **solo loopback** per il fallback dell'estensione; CORS su
  allowlist Origin; scritture loopback-only; REST reale.
- **Pin TLS invece di CA installata**: la CA locale non finisce sul telefono.
  Il QR trasporta `SHA-256(DER foglia)` (43 caratteri) e il mobile lo confronta in
  tempo costante. L'autenticazione del peer resta l'handshake E2EE: il pin
  copre il tratto LAN da chi sniffa ma non possiede la chiave privata, e
  sostituisce un trust store che sul device sarebbe impraticabile da gestire.
- **Niente downgrade su errore di verifica**: se il certificato presentato non è
  quello pinnato, il mobile **interrompe** la connessione invece di ripiegare sul
  canale in chiaro. Il ripiego è concesso solo agli errori di rete. Senza questa
  distinzione, chiunque potrebbe scegliere se la sessione viaggia cifrata,
  semplicemente rifiutando la connessione TLS: l'E2EE continuerebbe a reggere
  (quindi nessun test funzionale lo noterebbe) ma la privacy del trasporto
  diventerebbe negoziabile, in silenzio.
- **Codici di errore di pairing, non prosa**: il plugin mobile restituisce
  `{code, detail}` e il frontend localizza il codice. Serviva perché una stringa
  non è né traducibile né classificabile: per distinguere "certificato rifiutato"
  da "timeout di rete" il frontend avrebbe dovuto farne un'analisi testuale,
  fragile per costruzione. `scripts/check-pairing-codes.mjs` verifica in CI che
  i codici Rust e le chiavi i18n restino allineati, perché i due lati non
  condividono un tipo e una rinomina romperebbe la traduzione senza alcun errore
  di compilazione.
- **`host` del QR ristretto al dominio locale**: un QR malevolo non può
  indirizzare il telefono verso un dominio esterno (avrebbe aperto una
  connessione fuori LAN, pur senza compromettere l'E2EE).
- **Canale locale autenticato (token + consenso utente)**: la porta 8080 è
  loopback-only, ma ogni processo locale può raggiungerla; un sito malevolo che
  inietta richieste, un malware che gira come lo stesso utente o un profilo
  compromesso devono poter essere bloccati a livello applicativo. `/v1/extension`
  e `POST /v1/transmit` richiedono ora un **token per-client**: emesso dall'engine
  solo con **consenso esplicito** nella tray (banner Consenti/Rifiuta, TTL 120s),
  salvato **solo come SHA-256** in `clients.json` (0600). Niente token =
  `401`/`4406 LOCAL_NON_AUTENTICATO`, nessun hello e nessun APDU. Un token
  revocato viene rifiutato e non riapre mai il consenso da solo (niente
  downgrade). HTTPS resta il default dell'estensione (`requireHttps` on).
- **Nessuna rotazione della PKI sotto un engine attivo**: l'engine tiene in
  memoria il certificato foglia con cui serve il TLS, mentre il pin del QR
  sarebbe riletto da disco. Rotando a runtime, ogni QR nuovo porterebbe
  l'impronta del certificato nuovo e il server presenterebbe quello vecchio:
  ogni pairing fallirebbe con "pin non corrisponde" — l'errore di un attacco —
  e rigenerare il QR non aiuterebbe. `--rotate-ca` è rifiutato quando
  `engine.lock` è presente nel profilo.

## 1. Modello minacce
- Rete LAN ostile (ARP spoof, Evil Twin): tutto APDU è cifrato end-to-end, MITM senza nonce QR fallisce DH binding.
- Sito malevolo: allowlist Origin su extension + engine; senza autorizzazione esplicita il transmit è rifiutato (403).
- Replay Wi-Fi: nonce12 deterministico + seq monotono; riuso seq rifiutato (`Replay` error).
- Furto QR (shoulder surfing): nonce single-use, rigenerabile; handshake ha timeout 15s; chiavi effimere (forward secrecy per sessione).

## 2. Flusso accoppiamento
```
Desktop: static = X25519::random(), nonce32 = rand(32)
         QR = NFC://1/b64url({v:1, ip, port:8080, nonce_b64, pubkey_b64})
Mobile:  scan -> parse -> eph = X25519::random()
         shared = DH(eph, static)  [+ incapsulamento ML-KEM-768 se QRv2]
         okm = HKDF-SHA256(salt=nonce32, ikm=shared, info="nfc-smartcard-v1/aes-gcm", len=64)
         k_m2d = okm[0..32] ; k_d2m = okm[32..64]      <- una chiave per direzione
         -> WS /v1/mobile -> HandshakeInit{eph_pub, nonce_echo, keys_v} (seq=0 in chiaro bootstrap)
Desktop: shared' = DH(static, eph) ; stesso okm ; verifica nonce_echo == nonce32 e keys_v == 2
         -> HandshakeResp{static_pub, proto_v} cifrato con k_d2d, seq=1
Entrambi: SessionKeys{k_tx, k_rx, next_tx=1, last_rx=0}  <- k_tx != k_rx
```
- Nessuna chiave a lungo termine: a ogni `regenerate_qr` tutto ruota.
- mDNS serve solo a ritrovare IP dopo roaming; mai per chiavi.
- **Una chiave per direzione.** `rx` e `tx` non possono derivare dagli stessi
  argomenti: vedi §3 per cosa succedeva quando lo facevano.
- **`keys_v` rifiutato se assente.** L'init dichiara la versione del materiale
  chiavi; un client che non la conosce viene rifiutato prima del DH e il QR non
  viene speso, così resta rigenerabile (vedi §6).

## 3. AES-256-GCM
- Nonce12 = `00 00 00 00 || seq BE64`. Deterministico.
- **Il valore del nonce si ripete fra le due direzioni**: entrambi i contatori
  partono da `1`, quindi `seq=1` compare sia nel `HandshakeResp` del desktop sia
  nel primo frame del mobile, e così a ogni seq. Non è un problema *solo* perché
  la chiave è diversa per direzione (§2): stesso nonce con chiavi diverse è
  normale, stesso nonce con la **stessa** chiave sarebbe una rottura.
- AAD vuoto (il binding è nel nonce/seq); tag 16B verificato a ogni open.
- Max frame 128KB per evitare OOM su mobile.

### Riuso del nonce (risolto)
Prima della separazione delle chiavi, `rx` e `tx` venivano derivati con gli
stessi argomenti su **entrambi** i lati, quindi erano la stessa chiave. Con i
contatori che partivano da `1` in entrambe le direzioni, ogni seq veniva usato
due volte sotto la stessa chiave — per tutta la vita della sessione, non in un
caso limite.

Le conseguenze non sono teoriche: da due clear sotto lo stesso `(chiave, nonce)`
un attaccante che osserva il canale ricava il XOR dei clear e, per la relazione
GHASH, può fabbricare tag validi per quella chiave, cioè viola l'autenticità del
canale. E la viola proprio dove il design ci appoggiava — l'argomento del
ripiego in chiaro è "il canale resta sicuro perché E2EE", e l'anti-downgrade
costruito sulla porta 8080 fa leva su quella promessa.

La correzione è l'espansione HKDF a 64 byte divisa in due chiavi, con la
direzione scelta dal ruolo (`Direction::MobileToDesktop` / `DesktopToMobile`).
Il formato del nonce è **invariato**: è un campo del frame, quindi cambiarlo
sarebbe stato un cambio di protocollo. Cosa è cambiato invece è il materiale
chiavi, e quindi i client che non lo conoscono non decifrirebbero — è per questo
che esiste il rifiuto di §6, e non una negoziazione all'indietro.

Coperto da `chiavi_separate_per_direzione` (nfc-core, mutation-tested: unendo le
due chiavi per finta il test fallisce) e da
`handshake_completo_e_qr_single_use` (E2E su socket reale).

## 4. CIE / PACE note
- PACE/BAC avviene *dentro* il chip: il canale E2EE trasporta APDU opache, non interferisce con Secure Messaging CIE.
- Non loggare mai dati APDU (solo lunghezze + SW + latenza). Log extension troncati a 200 righe locali.
- ATR esposto solo come hex per UI; non contiene chiavi.

## 5. Hardening deployment
- **8443 (TLS) binda tutte le interfacce**: è il primario per ogni servizio e
  per il mobile in LAN, protetto da pin TLS + E2EE.
- **8080 (in chiaro) è solo loopback.** È il fallback dell'estensione sullo
  stesso desktop, non un canale di rete. Difesa in profondità: anche se il bind
  tornasse pubblico, i guard per handler tengono:
  - **letture** (`GET /v1/qr`, `GET /v1/metrics`, landing, webapp): allowlist
    Origin. Questo è il guard che blocca il vettore reale, cioè la lettura
    drive-by da una pagina web arbitraria (`fetch` cross-origin su 127.0.0.1).
  - **scritture** (`POST /v1/transmit`, `POST /v1/signal`, `POST /v1/qr`,
    upgrade WS `/v1/extension`): **loopback-only** *e* allowlist Origin. Nessun
    host di rete può impartire una transazione APDU. Dove il chiamante è un
    processo locale (extension/webapp: `/v1/extension`, `/v1/transmit`) serve in
    aggiunta il **token per-client** del §7: l'Origin identifica il browser, non
    l'entità eseguita; chi arriva da loopback può essere chiunque nel profilo.
- `/v1/status` dichiara l'ambito di 8080 in un campo dedicato
  (`ws_legacy_scope: "loopback-only"`), non come nota dentro l'URL: `/v1/status`
  è un contratto machine-readable e durante lo sviluppo mobile dichiarava un
  URL da loopback mentre il bind era pubblico.
- `POST /v1/qr` resta loopback-only: rigenera le chiavi di pairing e deve
  poter essere negato a chiunque non sia il desktop stesso.
- `/v1/mobile` raggiunge la **LAN via 8443/TLS**, non via 8080. Il peer è in LAN
  per definizione, quindi lì il guard non è il loopback ma l'E2EE con binding
  anti-MITM sulla SAS, più il pin TLS del certificato foglia.
- **CORS riflette la stessa allowlist** degli handler, mai `*`.
- vpcd resta su `127.0.0.1:35963`: mai esposto in rete.
- `nfc.local` non deve essere risolto dal DNS interno (conflitto mDNS): usare
  hosts/GPP locale o mDNS.
- CSP Tauri: `connect-src 'self' ws://localhost:8080`.
- Extension CSP: `connect-src ws://localhost:8080`.
- Headless IT: `--daemon` senza tray, log su syslog/eventlog, GPO disabilita QR (pairing solo via MDM pre-shared nonce).
- WebRTC fallback: solo host candidate, niente STUN pubblico di default.

## 6. Rifiuti dell'handshake e codici di chiusura

Prima, ogni rifiuto era una chiusura muta: il telefono vedeva soltanto
`Close`, e il suo testo di default — *"molto probabilmente il QR è già stato
usato"* — presentava un'ipotesi come diagnosi. Erano due reazioni opposte
(rigenerare il QR vs. aggiornare l'app) mascherate dalla stessa chiusura.

Ora l'engine invia un **codice stabile** nel `CloseFrame`, più il motivo in
italiano nel `reason` (che finisce nel `detail` per il log, non nel messaggio
dell'utente). Il client traduce il codice in un codice di pairing localizzato.

| Codice | Condizione | Reazione |
|---|---|---|
| 4400 | init malformato o di tipo inatteso | aggiorna entrambi |
| 4401 | QR già speso, o chiavi ruotate | rigenera il QR |
| 4402 | QR oltre la validità dell'engine | rigenera il QR |
| 4403 | nonce dell'init che non è il QR emesso | rigenera il QR |
| 4404 | `keys_v` assente o diverso | non riprovare: verifica la rete |
| 4405 | QR ibrido su build senza `pq` | allinea i due lati |
| 4406 | canale locale senza token valido (`/v1/extension`, `POST /v1/transmit`) | approva il consenso dalla tray; se il token era revocato, riapprovare esplicitamente |

4406 è il codice del **canale locale**, non del pairing mobile: chiude
l'upgrade `/v1/extension` quando il primo frame non porta un token autorizzato.
Il REST risponde `401` (JSON `{code:401}`) sullo stesso confine. Semantica
voluta: l'engine **non degrada** mai da un token invalido al flusso di consenso
— chi presenta un token revocato deve essere riautorizzato esplicitamente, mai
ricondotto a un percorso più permissivo. Coperto da
`token_sconosciuto_chiude_4406_senza_degradare` (WS reale).

Le costanti vivono in `nfc_core::protocol::close` (contratto condiviso) e il
test `ogni_codice_di_chiusura_e_tradotto` impedisce che un nuovo codice finisca
sul caso predefinito senza una traduzione.

### Perché si rifiuta invece di negoziare

`keys_v` viaggia in chiaro dentro l'init, quindi un attaccante può rimuoverlo.
La scelta è deliberata: **rifiutare**, invece di tornare al vecchio materiale
chiavi.

- Con una negoziazione all'indietro, la stessa rimozione avrebbe prodotto un
  downgrade **silenzioso** verso il canale con riuso di nonce, che è l'attacco
  che stavamo chiudendo.
- Con il rifiuto, un init alterato causa un fallimento percepibile: il mobile
  manda sempre `keys_v`, quindi ricevere 4404 significa che il campo non è
  arrivato intatto.

Il rifiuto avviene **prima** di consumare il QR: un client legacy non brucia la
single-use flag, così resta rigenerabile dopo l'aggiornamento. Coperto da
`client_legacy_rifiutato_con_codice` (E2E su socket reale).

Un mobile nuovo con un engine vecchio non decifra l'`HandshakeResp` e riceve
`decryptFailed`, il cui testo dice di **aggiornare entrambi** e di non
rigenerare il QR — che non aiuterebbe.

## 7. Canale locale: token + consenso utente

### Perché servirci di un altro strato dopo i guard di rete

La porta 8080 è loopback-only e le scritture hanno l'allowlist Origin, ma
quell'Origin è quello del **browser**, determinato dal tab di provenienza: non
distingue l'estensione (legittima) da un sito che ne riusa il canale, né da
un processo qualsiasi che gira nello stesso profilo utente. Sul desktop il
confine applicativo deve essere "il **possessore fisico** del lettore decide":
da qui il token emesso caso per caso con un consenso esplicito nella tray.

### Modello

1. Un client locale (estensione, webapp) apre `/v1/extension` e manda come
   **primo frame** `{"type":"hello","token":...}`. Il primo frame è il confine:
   nessuna statale `hello`/`card_status` prima dell'autenticazione.
2. Senza token, o con `{"type":"enroll"}`, l'engine registra una **richiesta di
   consenso** (`CONSENT_TTL = 120s`), notifica la UI (`engine-event` JSON
   `{kind:"consent",action:"requested"}`) e risponde `consent_status:pending`,
   rimanendo in attesa sul socket.
3. L'utente vede il banner **Consenti/Rifiuta** con l'etichetta del client
   (`Origin` del chiamante) e decide. `approve` genera un token casuale da 32
   byte (`rand::rng`, hex), lo consegna sul socket (`consent_status:approved`)
   e chiude pulito (1000). Dopo il primo errore/close il client riconnette e
   presenta il token.
4. **A riposo l'engine non conserva il token**: salva solo `SHA-256(token)` in
   `clients.json` dentro il profilo (`mode 0600` via `OpenOptionsExt`,
   best-effort e mai bloccante). Un dump del disco o un backup non rivelano
   un token riutilizzabile.
5. `/v1/transmit` richiede `Authorization: Bearer <token>`; il confronto avviene
   sull'hash con **tempo costante** (`subtle`, stessa disciplina del pin TLS).
6. `revoke` (UI "Revoca") toglie il client dal registro e salva subito: i token
   già distribuiti smettono di valere senza attendere l'expiry.

### Perché un token revocato non riapre il consenso

Un `hello` che **contiene** un token non valido viene rifiutato (`401` + close
`4406`); un `hello` senza token avvia il consenso. La distinzione è deliberata:
chi riusa un token vecchio non deve finire per inerzia in un percorso che
ridà accesso — al limite lo si ridà espressamente, dall'UI. Altrimenti la
revoca sarebbe aggirabile (o peggio, una finta) da chiunque avesse ancora un
token indistinto da "non ancora emesso".

### Limiti dichiarati

- La decisione è a tutto o niente per client, non per origine della richiesta
  singola: il "chi" è il token, il "da dove" resta coperto dall'Origin e dal
  loopback.
- Il fallback 8080 in chiaro resta raggiungibile da un processo locale
  privilegiato capace di sniffare il proprio loopback; è opt-in da
  `requireHttps=false`, documentato come scelta per postazioni senza CA fidata,
  e il token ne alza comunque il costo. Se la postazione lo consente, mantenere
  `requireHttps` on (default).

Coperto da `extension_auth.rs` (WS reale: consenso→token, hello con token,
4406 senza degradare) e dagli unit test di `local_auth.rs` (hash, TTL, revoca,
persistenza 0600). Le tre proprietà centrali sono state mutation-verificate
(token invalido che apre il consenso, token diverso da quello approvato):
i test falliscono con la logica rotta. Il tempo costante non è osservabile da
unit test (niente timing in-process): è un vincolo testuale, coperto dal guard
`scripts/guard-security-2026.sh` (XOR-fold di `constant_eq`), come la clausola
`tls12` spenta del grafo mobile.
