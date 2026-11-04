# Developer Local API — `https://nfc.local:8443/v1/*` (primario) + `http://127.0.0.1:8080/v1/*` (legacy)

Base: `wss://nfc.local:8443/v1/extension` (primario, fallback `ws://127.0.0.1:8080/v1/extension`)
+ `https://nfc.local:8443/v1/status` (health). Solo loopback (`127.0.0.1`).
Vedi `docs/LOCAL-DOMAIN.md` per CA/hosts/trust.

**Autenticazione del canale locale**: loopback + allowlist Origin non bastano
(un processo qualsiasi nel profilo utente parla con il loopback): ogni chiamata
che guida il lettore (`/v1/extension`, `POST /v1/transmit`) richiede un
**token per-client**, emesso dall'engine **con consenso esplicito** dell'utente
(tray, banner Consenti/Rifiuta). Senza token: `401`/close `4406`
(`LOCAL_NON_AUTENTICATO`). Meccanica in `docs/SECURITY.md` §7.

## 1. WebSocket `/v1/extension` (JSON, un messaggio per riga)

### 1.0 Autenticazione (primo frame: client -> server)

Il primo frame ricevuto determina l'esito: **mai** inviare altri messaggi prima.

```json
// Già autorizzati: hello con il token emesso in passato.
{"type":"hello","token":"<hex 32B>"}
// Mai approvati / token smarrito: l'engine apre il consenso.
{"type":"hello"}
// Ottenere esplicitamente un (nuovo) token.
{"type":"enroll"}
```

- `hello` + token valido -> si procede (§1.1).
- `hello` + token **non** valido -> `{"type":"error","code":401,...}` poi close
  `4406`. Non riapre il consenso: riautorizzazione esplicita richiesta.
- `hello` senza token / `enroll` -> l'engine notifica la tray
  (`engine-event {kind:"consent",action:"requested"}`) e risponde:
  ```json
  {"type":"consent_status","status":"pending","id":"<consent-id>"}
  ```
  Al consenso dell'utente (TTL 120s): `approved` con il **token** (poi close
  1000 — il client ricomette e lo presenta), oppure `rejected` (poi close 1000).
  ```json
  {"type":"consent_status","status":"approved","token":"<hex 32B>"}
  {"type":"consent_status","status":"rejected"}
  ```
  Scaduto: il socket si chiude senza token; il client riparte da zero.

### 1.1 Hello (server -> client, solo dopo autenticazione)
```json
{"type":"hello","engine":"nfc-desktop/0.3.0","crypto":"hybrid-ready"}
```

### 1.2 Eventi push (server -> client)
```json
{"type":"card_status","status":"inserted","atr_hex":"3B8F8001..."}
{"type":"card_status","status":"removed","atr_hex":null}
{"type":"card_status","status":"reading","atr_hex":null}
{"type":"reader_connected","name":"vpcd-0"}
{"type":"reader_disconnected","name":"vpcd-0"}
```

### 1.3 Request transmit_apdu (client -> server)
```json
{
  "type": "transmit_apdu",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "payload_hex": "00A4040007A000000247100100",
  "timeout_ms": 8000
}
```
- `payload_hex`: hex maiuscolo/minuscolo **oppure** `b64:<base64>` (per binari).
- `timeout_ms`: opzionale, 1000..30000, default 8000.
- Validazione: 4..65535B dopo decode, min 4B header ISO7816.

### 1.4 Response apdu_reply (server -> client)
```json
{
  "type": "apdu_reply",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "data_hex": "6F108408A0000002471001A503...",
  "sw1": 144,
  "sw2": 0,
  "latency_ms": 87
}
```
- `sw1/sw2`: decimali (0x90=144, 0x00=0). `data_hex` senza SW.
- `latency_ms`: tempo carta (mobile) escluso overhead WS.

### 1.5 Errori
```json
{"type":"error","code":400,"message":"type sconosciuto"}
{"type":"error","code":401,"message":"non autorizzato: ... (approva il consenso dall'app desktop)"}
{"type":"error","code":422,"message":"hex: ...","request_id":"..."}
{"type":"error","code":502,"message":"nessun lettore mobile connesso","request_id":"..."}
```
Il 401 del primo frame è seguito dal close frame con codice stabile **4406**
(`LOCAL_NON_AUTENTICATO`, `nfc_core::protocol::close`), che è il segnale
canonico per "client locale senza token valido" (vs. `lonely-ws` del mobile).

### 1.6 Ping
```json
{"type":"ping"}  ->  {"type":"pong"}
```

## 2. REST

### GET /v1/status
```bash
curl --cacert ~/.config/nfc-remote/ca/nfc-local-root.pem https://nfc.local:8443/v1/status
# {"ok":true,"engine":"nfc-desktop/0.3.0","https":"https://nfc.local:8443", ...}
# legacy: curl http://127.0.0.1:8080/v1/status
```
CORS: `Access-Control-Allow-Origin: <Origin>` se allowlist, altrimenti `*` solo per status.

### POST /v1/transmit (REST reale, stesso schema WS)
Header `Authorization: Bearer <token>` **obbligatorio** (stesso token emesso dal
consenso; senza vale `401`). Loopback + Origin allowlist come sempre.
Ritorna `apdu_reply` o `{"type":"error",...}` con status HTTP mappato
(401 token, 422 schema/APDU, 403 origin, 502 mobile offline).

### POST /v1/scan (beacon informativo dalla webapp)
La webapp lo invia quando un QR di pairing **valido** è stato scansionato da un
browser (anche remoto). NON è un'autorizzazione: il pairing resta autorizzato
dal QR + handshake E2EE. Origin allowlist come `/v1/qr`; il desktop mostra una
notifica "QR scansionato" rate-limitata (max 1 ogni 30s).
```bash
curl -sk -X POST -H "Origin: https://nfc.local:8443" https://localhost:8443/v1/scan
# {"type":"scan","ok":true}
```

### GET /v1/metrics (Prometheus, solo loopback)
```bash
curl --cacert ~/.config/nfc-remote/ca/nfc-local-root.pem https://nfc.local:8443/v1/metrics
# nfc_apdu_total{result="ok"} 12
# nfc_apdu_latency_ms_avg 87
# nfc_ws_connections_total{channel="extension"} 3
```
Nessuna label ad alta cardinalità (solo `result`, `channel`). Utile per
dashboard B2B e allarmi su `timeout`/`offline` in crescita.

### GET /pair (HTML)
Pagina di pairing autonoma (QR + `nfc://pair`) servita anche da
`https://pair.nfc.local:8443`. Il QR è single-use con TTL 5 minuti.

## 3. Web API iniettata `window.SmartCardReader`

Disponibile solo su origini autorizzate (popup per gestire allowlist).

```js
// Attendi disponibilità (navigazione SPA).
window.addEventListener("smartcardreader-ready", init);

async function init() {
  const st = await window.SmartCardReader.getStatus();
  console.log(st); // {available:true, origin:"https://..."}

  const unsub = window.SmartCardReader.onCardStatus((ev) => {
    console.log("carta:", ev.status); // inserted|removed|reading
  });

  // SELECT CIE AID.
  const r = await window.SmartCardReader.transmit("00A4040007A000000247100100", 8000);
  console.log(r.data_hex, r.sw1.toString(16), r.sw2.toString(16));
}
```

### Esempio gestionale (firma hash CIE)
```js
const select = await SmartCardReader.transmit("00A404000744454649443100");
if (select.sw1 !== 0x90) throw new Error("SELECT fallita");
// ... MSE SET + PSO SIGN secondo spec CIE (vedi docs/SECURITY.md per PACE)
```

## 4. Schema JSON (validazione server già implementata in protocol.rs)

Vedi `shared-ui-ts/schema.json`. Codici: 400 schema, 422 APDU, 502 mobile offline, 403 origin.
