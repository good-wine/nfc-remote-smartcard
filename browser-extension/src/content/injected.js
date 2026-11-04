// Injected script (MAIN world): definisce window.SmartCardReader.
// API pulita per webapp autorizzate (CIE/PA, gestionali):
//   await SmartCardReader.getStatus()
//   await SmartCardReader.transmit("00A40400...") -> {dataHex, sw1, sw2}
//   SmartCardReader.onCardStatus(cb)
// Sicurezza: nessuna chiave qui; ogni transmit passa per content-bridge che
// verifica l'origin contro allowlist. Questo script fa solo postMessage.
(() => {
  if (window.SmartCardReader) return; // idempotente
  const pending = new Map();
  const evHandlers = new Set();

  window.addEventListener("message", (ev) => {
    if (ev.source !== window || ev.origin !== location.origin) return;
    const d = ev.data;
    if (!d || d.__nfc_remote__ !== true) return;
    if (d.kind === "reply" && pending.has(d.id)) {
      const { res, rej } = pending.get(d.id);
      pending.delete(d.id);
      if (d.ok) res(d.reply);
      else rej(new Error(d.error ?? "transmit fallita"));
    }
    if (d.kind === "event" && d.event?.type === "card_status") {
      for (const h of evHandlers) {
        try {
          h(d.event);
        } catch {
          /* mai rompere */
        }
      }
    }
    if (d.kind === "available") {
      window.dispatchEvent(new CustomEvent("smartcardreader-ready"));
    }
  });

  function transmit(payloadHex, timeoutMs) {
    return new Promise((res, rej) => {
      // Validazione minima lato pagina (difesa in profondità).
      if (typeof payloadHex !== "string" || payloadHex.length < 8) {
        rej(new Error("payload APDU non valido"));
        return;
      }
      const id = crypto.randomUUID();
      pending.set(id, { res, rej });
      window.postMessage({ __nfc_remote__: true, kind: "transmit", id, payloadHex, timeoutMs }, location.origin);
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          rej(new Error("timeout SmartCardReader.transmit"));
        }
      }, (timeoutMs ?? 8000) + 3000);
    });
  }

  window.SmartCardReader = {
    async getStatus() {
      // Stato best-effort: se nessun evento ricevuto, unknown.
      return { available: true, origin: location.origin };
    },
    transmit,
    onCardStatus(cb) {
      evHandlers.add(cb);
      return () => evHandlers.delete(cb);
    },
  };
})();
