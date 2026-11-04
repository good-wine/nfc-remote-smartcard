// i18n canonico EN/IT (master: le UI desktop/mobile lo importano per path
// relativo; l'estensione ne ha un mirror in `src/shared/i18n.ts` per via del
// vincolo `rootDir` di tsc senza bundler). Chiavi stabili: non rinominare.

export type Lang = "it" | "en";

export function detectLang(): Lang {
  try {
    return (typeof navigator !== "undefined" && navigator.language.startsWith("en") ? "en" : "it");
  } catch {
    return "it";
  }
}

const STR: Record<string, Record<Lang, string>> = {
  "pair.title": { it: "Accoppia smartphone", en: "Pair smartphone" },
  "pair.regen": { it: "Rigenera QR", en: "Regenerate QR" },
  "pair.note": {
    it: "Servizi anche su https://nfc.local:8443 · pairing nfc://pair",
    en: "Also served at https://nfc.local:8443 · pairing nfc://pair",
  },
  "pair.photoHint": {
    it: "Sul telefono apri lo scanner e inquadra il QR da ~15–20 cm, riempiendo quasi tutto il riquadro: è un QR denso (post-quantum), serve essere vicini.",
    en: "On the phone, open the scanner and frame the QR from ~15–20 cm, filling most of the frame: it is a dense (post-quantum) QR, so stay close.",
  },
  "status.title": { it: "Stato", en: "Status" },
  "status.vpcd": { it: "vpcd", en: "vpcd" },
  "status.mobile": { it: "mobile", en: "mobile" },
  "status.online": { it: "online", en: "online" },
  "status.offline": { it: "offline", en: "offline" },
  "status.up": { it: "UP", en: "UP" },
  "status.down": { it: "DOWN", en: "DOWN" },
  "sas.verify": { it: "SAS da verificare sul telefono", en: "SAS to verify on the phone" },
  "log.qrRegen": { it: "QR rigenerato", en: "QR regenerated" },
  "log.mobileConnected": { it: "Telefono associato", en: "Phone paired" },
  "log.qrScanned": { it: "QR scansionato dal browser", en: "QR scanned from browser" },
  "app.title": { it: "NFC Remote", en: "NFC Remote" },
  "status.idle": { it: "Non associato", en: "Not paired" },
  "status.scanning": { it: "Scansione…", en: "Scanning…" },
  "status.session": { it: "Sessione E2EE attiva", en: "Active E2EE session" },
  "status.error": { it: "Errore", en: "Error" },
  "btn.scan": { it: "Scansiona QR PC", en: "Scan PC QR" },
  "conn.on": { it: "Engine connesso", en: "Engine connected" },
  "conn.off": { it: "Engine disconnesso", en: "Engine disconnected" },
  "conn.swDown": { it: "SW non attivo", en: "SW not running" },
  "card.label": { it: "Carta", en: "Card" },
  "card.unknown": { it: "sconosciuta", en: "unknown" },
  "test.btn": { it: "Test SELECT CIE", en: "Test SELECT CIE" },
  "origins.title": { it: "Origini autorizzate", en: "Allowed origins" },
  "log.title": { it: "Log", en: "Log" },
  "mobile.hint": {
    it: "Inquadra il QR mostrato nella tray del desktop: la sessione è E2EE ibrido post-quantum.",
    en: "Point the camera at the QR in the desktop tray: the session is hybrid post-quantum E2EE.",
  },
  "card.title": { it: "Carta", en: "Card" },
  "card.none": { it: "Nessuna carta", en: "No card" },
  "card.inserted": { it: "Carta rilevata", en: "Card detected" },
  "card.reading": { it: "Lettura in corso…", en: "Reading…" },
  "mobile.holdCard": {
    it: "Sessione avviata: appoggia la carta al retro del telefono.",
    en: "Session active: hold your card against the back of the phone.",
  },
  "reqhttps.label": { it: "Richiedi HTTPS (niente fallback)", en: "Require HTTPS (no fallback)" },

  // Consenso dei client locali: canale loopback con token emesso dall'utente.
  // Niente approvazione = niente accesso alla carta del telefono remoto.
  "consent.title": { it: "Accessi locali", en: "Local access" },
  "consent.notice": {
    it: "Se un client locale (estensione, webapp) chiede di guidare il lettore, arriva qui un banner: approva solo se riconosci il dispositivo.",
    en: "When a local client (extension, webapp) asks to drive the reader, a banner appears here: approve only if you recognize the device.",
  },
  "consent.pending": { it: "Richiede l'accesso al lettore", en: "requests reader access" },
  "consent.approve": { it: "Consenti", en: "Allow" },
  "consent.reject": { it: "Rifiuta", en: "Deny" },
  "consent.approved": { it: "Accesso concesso", en: "Access granted" },
  "consent.rejected": { it: "Richiesta rifiutata", en: "Request denied" },
  "consent.expired": { it: "Richiesta scaduta", en: "Request expired" },
  "clients.title": { it: "Clienti autorizzati", en: "Authorized clients" },
  "clients.empty": { it: "Nessun client autorizzato", en: "No authorized clients" },
  "clients.revoke": { it: "Revoca", en: "Revoke" },
  "clients.lastSeen": { it: "ultimo accesso", en: "last seen" },

  // Feedback e stati UI (2026): condivise desktop/web/mobile/estensione.
  "btn.retry": { it: "Riprova", en: "Retry" },
  "offline.banner": {
    it: "Engine non raggiungibile: controlla che il desktop sia acceso e sulla stessa rete.",
    en: "Engine unreachable: make sure the desktop is on and on the same network.",
  },
  "btn.disconnect": { it: "Disconnetti", en: "Disconnect" },
  "reader.connected": { it: "lettore connesso", en: "reader connected" },
  "qr.validFor": { it: "valido per", en: "valid for" },
  "qr.expired": { it: "SCADUTO — rigenera", en: "EXPIRED — regenerate" },
  "status.updated": { it: "aggiornato", en: "updated" },
  "consents.empty": { it: "Nessuna richiesta in attesa", en: "No pending requests" },
  "btn.newSession": { it: "Nuova sessione", en: "New session" },
  "origins.invalid": {
    it: "URL non valido — es. https://nfc.local:8443",
    en: "Invalid URL — e.g. https://nfc.local:8443",
  },

  // Errori di pairing. Le chiavi sono i codici stabili emessi dal plugin Rust
  // (`code` in `mobile/src-tauri/src/lib.rs`): rinominarne uno rompe la
  // traduzione **senza alcun errore di compilazione**, perché i due lati non
  // condividono un tipo. Ogni testo porta anche l'azione da fare: un errore di
  // sicurezza senza rimedio spinge l'utente a riprovare lo stesso gesto.
  "qrInvalid": {
    it: "QR non leggibile o incompleto. Rigenera il QR dalla tray del desktop e riscannalo.",
    en: "QR unreadable or incomplete. Regenerate it from the desktop tray and scan it again.",
  },
  "qrExpired": {
    it: "QR scaduto (vale pochi minuti). Rigenera il QR dalla tray del desktop: non serve riavviare nulla.",
    en: "QR expired (valid for a few minutes). Regenerate it from the desktop tray; nothing needs restarting.",
  },
  "pinRejected": {
    it: "Il certificato TLS non corrisponde a quello del QR: connessione interrotta di proposito. Rigenera il QR; se il problema persiste, qualcuno potrebbe essere in mezzo alla rete.",
    en: "The TLS certificate does not match the one in the QR: the connection was deliberately cut. Regenerate the QR; if it persists, someone may be intercepting the network.",
  },
  "unreachable": {
    it: "Engine non raggiungibile. Controlla che il desktop sia acceso e sulla stessa rete Wi-Fi, e che nfc.local si risolva sul telefono.",
    en: "Engine unreachable. Check the desktop is on and on the same Wi-Fi network, and that nfc.local resolves on the phone.",
  },
  "noPlainChannel": {
    it: "Questo QR non espone un canale sicuro e la porta in chiaro è raggiungibile solo dal computer stesso. Rigenera il QR dall'engine con la PKI attiva.",
    en: "This QR exposes no secure channel, and the plain port is reachable only from the computer itself. Regenerate the QR from the engine with the PKI active.",
  },
  "handshakeTimeout": {
    it: "L'engine non ha risposto all'handshake. Riavvia il desktop e riprova.",
    en: "The engine did not answer the handshake. Restart the desktop and try again.",
  },
  "peerClosed": {
    it: "L'engine ha chiuso la connessione. Molto probabilmente il QR è già stato usato: rigenera.",
    en: "The engine closed the connection. Most likely the QR was already used: regenerate it.",
  },
  "badFrame": {
    it: "Risposta inattesa dall'engine. Aggiorna il desktop e il telefono allo stesso stato.",
    en: "Unexpected reply from the engine. Bring the desktop and the phone to the same state.",
  },
  "qrUsed": {
    it: "Questo QR è già stato usato da un'altra sessione: rigeneralo dalla tray del desktop e riscannalo.",
    en: "This QR was already used by another session: regenerate it from the desktop tray and scan it again.",
  },
  // Generalizzato: prima parlava solo della chiave dell'engine, ma il motivo è
  // lo stesso anche quando l'engine rifiuta un campo dell'init che è stato
  // rimosso per strada — un'asserzione non onorata, non una chiave sbagliata.
  "peerMismatch": {
    it: "Qualcosa nell'handshake non corrisponde a quanto previsto: possibile intercettazione. Non riprovare, verifica la rete.",
    en: "Something in the handshake does not match what was expected: possible interception. Do not retry; check the network.",
  },
  "protoMismatch": {
    it: "Versioni di protocollo diverse tra telefono e desktop. Aggiorna entrambi.",
    en: "Different protocol versions on phone and desktop. Update both.",
  },
  // Non è più "rigenera il QR": rigenerare non aiuta né quando la risposta è
  // stata alterata, né quando i due lati derivano chiavi diverse (engine non
  // aggiornato a `keys_v`). Il consiglio giusto in entrambi i casi è non
  // riprovare e allineare i due lati.
  "decryptFailed": {
    it: "Impossibile autenticare la risposta dell'engine: è stata alterata in transito oppure telefono e desktop hanno versioni diverse. Non rigenerare il QR: aggiorna entrambi e verifica la rete.",
    en: "Could not authenticate the engine's reply: it was altered in transit, or the phone and desktop versions differ. Do not regenerate the QR: update both and check the network.",
  },
  "internal": {
    it: "Errore interno durante l'accoppamento.",
    en: "Internal error during pairing.",
  },
};

export function t(key: string, lang?: Lang): string {
  const l = lang ?? detectLang();
  return STR[key]?.[l] ?? STR[key]?.it ?? key;
}

/** Messaggio localizzato per un codice di pairing, con la chiave di fallback. */
export function tOr(key: string, fallback: string, lang?: Lang): string {
  const l = lang ?? detectLang();
  return STR[key]?.[l] ?? STR[key]?.it ?? fallback;
}

/** Applica `data-i18n="chiave"` (textContent) e `data-i18n-ph` (placeholder). */
export function applyI18n(lang?: Lang): void {
  const l = lang ?? detectLang();
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const k = el.getAttribute("data-i18n");
    if (k) el.textContent = t(k, l);
  });
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => {
    const k = el.getAttribute("data-i18n-ph");
    if (k) (el as HTMLInputElement).placeholder = t(k, l);
  });
  document.documentElement.lang = l;
}
