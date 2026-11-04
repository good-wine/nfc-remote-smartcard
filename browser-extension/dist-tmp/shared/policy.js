// Policy origini: solo siti esplicitamente autorizzati possono usare
// window.SmartCardReader. Default: PA/CIE + localhost (dev). L'utente aggiunge
// origini dal popup; persistite in chrome.storage.sync.
const DEFAULT_ALLOW = new Set([
    "https://www.interno.gov.it",
    "https://cie.interno.gov.it",
    "https://spid.gov.it",
    "http://localhost:1420",
    "http://localhost:5173",
]);
export async function getAllowedOrigins() {
    const v = (await chrome.storage.sync.get({ origins: [...DEFAULT_ALLOW] }));
    return new Set(v.origins);
}
export async function isOriginAllowed(origin) {
    return (await getAllowedOrigins()).has(origin);
}
export async function setOriginAllowed(origin, allowed) {
    const cur = await getAllowedOrigins();
    if (allowed)
        cur.add(origin);
    else
        cur.delete(origin);
    await chrome.storage.sync.set({ origins: [...cur] });
}
export function originOf(url) {
    if (!url)
        return null;
    try {
        const u = new URL(url);
        return `${u.protocol}//${u.host}`;
    }
    catch {
        return null;
    }
}
