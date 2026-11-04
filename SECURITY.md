# Policy di divulgazione delle vulnerabilità

Questo documento è la **policy di processo**: come segnalare un problema di
sicurezza e cosa aspettarsi in risposta.

Il **modello tecnico** (minacce, protocollo E2EE, pinning TLS, canale locale a
token/consenso, codici di chiusura) vive in [`docs/SECURITY.md`](docs/SECURITY.md)
e non viene duplicato qui. Se stai verificando se un comportamento è intenzionale,
leggi prima quello.

## Come segnalare

Usa i **GitHub Security Advisories** con il pulsante **"Report a vulnerability"**
della scheda *Security* del repository:
<https://github.com/nfc-remote/nfc-remote/security/advisories/new>

Il canale è **privato**: la segnalazione resta visibile solo a te e ai
maintainer finché non viene pubblicata (di norma dopo il fix).

**Non aprire issue pubbliche, PR o discussioni** per una vulnerabilità: una issue
pubblica descrive il problema a chiunque, prima che esista un fix.

Nella segnalazione, per quanto possibile, includi:

- componente coinvolta (`nfc-core`, `desktop`, `mobile`, `web`,
  `browser-extension`, `vpcd`, build/CI);
- versione o commit interessati (`git rev-parse HEAD`) e piattaforma;
- passi di riproduzione minimi, o un proof-of-concept che funziona davvero;
- impatto osservabile (cosa ottiene un attaccante: leggere un APDU, aprire una
  sessione, aggirare il consenso, ecc.);
- eventuale classificazione suggerita (CVSS) e se intendi pubblicare.

Un report che riproduce un problema reale è molto più utile di uno che lo
descrive soltanto. **Non incollare token, chiavi private, pin o dati di carte
reali**: se servono, allega valori generati ad hoc.

## Ambito

### In scope

- **Protocollo E2EE** (`shared-core-rust/`): derivazione delle chiavi
  (X25519 + ML-KEM-768, HKDF), separazione delle chiavi per direzione, nonce/seq,
  rekey, binding anti-MITM del nonce QR e della SAS.
- **Canale locale token + consenso** (`/v1/extension`, `POST /v1/transmit`):
  emissione del token, store `clients.json` (SHA-256, 0600), confronto in tempo
  costante, semantica del codice `4406`, assenza di downgrade su token revocato.
- **Pinning TLS** e gestione della PKI locale: verifica del pin del certificato
  foglia letto dal QR, rifiuto del downgrade, `--rotate-ca`, `engine.lock`.
- **Guard di rete**: bind del canale in chiaro su loopback, allowlist `Origin`,
  CORS, esposizione di vpcd e mDNS.
- **Validazione in ingresso**: parsing di QR di pairing, framing del wire
  protocol e delle frame vpcd, validazione APDU (inclusa la versione WASM usata
  dalla webapp e dall'estensione).
- **Supply-chain**: workflow CI/release, permessi, firma e attestazioni.

### Fuori scope

- **Fiducia nel dispositivo o nel PC**: un desktop o uno smartphone già
  compromesso o con **root/amministratore locale** può osservare traffico e
  file del proprio utente; non è un confine che questo progetto possa difendere.
- **Chi ha accesso fisico al dispositivo** mentre la sessione è attiva (incluso
  l'uso del lettore da parte di chi lo possiede).
- **App di terze parti** che l'utente installa e autorizza esplicitamente
  tramite la tray: il consenso è, per costruzione, una decisione dell'utente.
- **Vulnerabilità già note e documentate come limiti accettati** in
  `docs/SECURITY.md` (es. il fallback 8080 in chiaro con `requireHttps=false`,
  che è opt-in e dichiarato).
- **Bypass dell'autenticazione della carta** (PIN CIE, PACE/BAC): avvengono
  dentro il chip, fuori dal perimetro di questo software.
- Attacchi puramente teorici senza impatto dimostrabile sul prodotto, risultati
  di scanner automatici senza riproduzione, best-practice generiche.

## Versioni supportate

Il supporto di sicurezza segue le **release più recenti**: la linea corrente
(serie `0.3.x`) riceve fix; le versioni precedenti no. Fai riferimento ai tag
`v*` e alle release pubblicate. Se stai testando `main`, indica il commit esatto.

| Versione | Supportata |
|---|---|
| `0.3.x` (corrente) | ✅ |
| `< 0.3` | ❌ |

## Tempi di risposta attesi

Sono obiettivi best-effort di un progetto open-core, non un SLA contrattuale.

| Fase | Tempo obiettivo |
|---|---|
| Presa in carico (acknowledgement) | 3 giorni lavorativi |
| Valutazione iniziale e severità | 7 giorni lavorativi |
| Fix per problemi critici/alto impatto | 30 giorni |
| Fix per problemi medi/bassi | valutato caso per caso |

Ti terremo aggiornato nel thread dell'advisory. Quando il fix è pronto
coordiniamo la divulgazione: il credito spetta a chi segnala, salvo richiesta di
anonimato.

## Divulgazione

La policy è **coordinated disclosure**: pubblichiamo l'advisory dopo il fix (o
dopo 90 giorni dalla segnalazione se il fix non è disponibile e concordato
diversamente). Non aprire il problema in pubblico prima di allora.

## Verificare l'autenticità

Le release sono firmate e attestate dalla pipeline (vedi
`docs/DEPLOYMENT.md`). Per dubbi sull'autenticità di una release o di una
comunicazione di sicurezza, apri un advisory privato e chiedi conferma.

## Riferimenti

- Modello di sicurezza tecnico: [`docs/SECURITY.md`](docs/SECURITY.md)
- Architettura e confini dei componenti: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Guard di sicurezza e invarianti verificate in CI: `scripts/guard-security-2026.sh`
- Advisories pubblicati: <https://github.com/nfc-remote/nfc-remote/security/advisories>
