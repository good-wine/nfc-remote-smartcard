// Mirror di shared-ui-ts/src/i18n.ts (tsc senza bundler: niente import fuori rootDir).
// Mantenere sincronizzato col master. Chiavi stabili: non rinominare.
export function detectLang() {
    try {
        return (typeof navigator !== "undefined" && navigator.language.startsWith("en") ? "en" : "it");
    }
    catch {
        return "it";
    }
}
const STR = {
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
    "consent.title": { it: "Accesso locale", en: "Local access" },
    "consent.pending": {
        it: "In attesa di approvazione: rispondi al banner sulla tray app del desktop",
        en: "Awaiting approval: answer the banner in the desktop tray app",
    },
    "consent.approved": { it: "Accesso autorizzato", en: "Access authorized" },
    "consent.rejected": { it: "Richiesta rifiutata dal desktop", en: "Request denied by the desktop" },
    "consent.revoked": {
        it: "Accesso revocato: apri il desktop e approva di nuovo",
        en: "Access revoked: open the desktop and approve again",
    },
    // Feedback e stati UI (2026): mirror del master shared-ui-ts/src/i18n.ts.
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
};
export function t(key, lang) {
    const l = lang ?? detectLang();
    return STR[key]?.[l] ?? STR[key]?.it ?? key;
}
/** Applica `data-i18n="chiave"` (textContent) e `data-i18n-ph` (placeholder). */
export function applyI18n(lang) {
    const l = lang ?? detectLang();
    document.querySelectorAll("[data-i18n]").forEach((el) => {
        const k = el.getAttribute("data-i18n");
        if (k)
            el.textContent = t(k, l);
    });
    document.querySelectorAll("[data-i18n-ph]").forEach((el) => {
        const k = el.getAttribute("data-i18n-ph");
        if (k)
            el.placeholder = t(k, l);
    });
    document.documentElement.lang = l;
}
