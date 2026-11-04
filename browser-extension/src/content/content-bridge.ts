// Content-script ISOLATED 2026: solo relay page <-> SW.
// L'API `window.SmartCardReader` è iniettata dichiarativamente dal manifest
// (`content_scripts[1].world = "MAIN"`), quindi qui NIENTE `<script>` dinamico:
// - CSP-strict compliant, niente `web_accessible_resources` per l'inject;
// - compatibile Chrome 131+/Edge/Firefox MV3 (Firefox ignora `world: MAIN`
//   e usa il fallback `exportFunction/cloneInto` in injected.js).
// Questo script verifica solo che l'origin sia autorizzata prima di inoltrare.

const CHANNEL = "__nfc_remote__";
let allowed = false;

chrome.storage.sync.get({ origins: [] }).then(({ origins }) => {
  try {
    const origin = `${location.protocol}//${location.host}`;
    allowed = (origins as string[]).includes(origin);
  } catch {
    allowed = false;
  }
});
chrome.storage.onChanged.addListener((chg, area) => {
  if (area !== "sync" || !chg.origins) return;
  try {
    const origin = `${location.protocol}//${location.host}`;
    allowed = (chg.origins.newValue as string[]).includes(origin);
  } catch {
    allowed = false;
  }
});

// page (MAIN world) -> SW. Accetta solo messaggi dalla stessa origin.
window.addEventListener("message", (ev) => {
  if (ev.source !== window || ev.origin !== location.origin) return;
  const d = ev.data as { [CHANNEL]?: boolean; kind?: string; payloadHex?: string; timeoutMs?: number; id?: string };
  if (!d?.[CHANNEL] || d.kind !== "transmit") return;
  if (!allowed) {
    window.postMessage({ [CHANNEL]: true, kind: "reply", id: d.id, ok: false, error: "origin non autorizzata (abilita dal popup)" }, location.origin);
    return;
  }
  chrome.runtime
    .sendMessage({ kind: "content-transmit", payloadHex: d.payloadHex, timeoutMs: d.timeoutMs })
    .then((r: { ok: boolean; reply?: unknown; error?: string }) => {
      window.postMessage({ [CHANNEL]: true, kind: "reply", id: d.id, ok: r.ok, reply: r.reply, error: r.error }, location.origin);
    })
    .catch((e: Error) => {
      window.postMessage({ [CHANNEL]: true, kind: "reply", id: d.id, ok: false, error: e.message }, location.origin);
    });
});

// SW push -> page.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.kind === "engine-event") {
    window.postMessage({ [CHANNEL]: true, kind: "event", event: msg.event }, location.origin);
  }
});
