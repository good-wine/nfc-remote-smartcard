// Popup UI: stato engine/mobile, test APDU, gestione origini, pin HTTPS, log.
// Parla solo col Service Worker (chrome.runtime), mai diretto a localhost.
import { applyI18n, detectLang, t } from "../shared/i18n.js";

const lang = detectLang();
applyI18n(lang);
const connEl = document.getElementById("conn")!;
const cardEl = document.getElementById("card")!;
const outEl = document.getElementById("out")!;
const logEl = document.getElementById("log")!;
const originsEl = document.getElementById("origins")!;
const originInput = document.getElementById("origin") as HTMLInputElement;
const reqHttpsEl = document.getElementById("reqhttps") as HTMLInputElement;
const consentEl = document.getElementById("consent")!;

async function refresh(): Promise<void> {
  const st = (await chrome.runtime
    .sendMessage({ kind: "get-status" })
    .catch(() => null)) as {
    connected: boolean;
    lastStatus?: { type: string; status?: string };
    via?: string;
    authorized?: boolean;
    consentPending?: boolean;
  } | null;
  if (!st) {
    connEl.textContent = t("conn.swDown", lang);
    connEl.className = "badge ko";
    return;
  }
  const viaShort = st.via?.includes("nfc.local") ? "https" : st.via?.includes("127.0.0.1") ? "fallback" : "";
  connEl.textContent = st.connected ? `${t("conn.on", lang)} (${viaShort})` : t("conn.off", lang);
  connEl.className = `badge ${st.connected ? "ok" : "ko"}`;
  connEl.title = st.via ?? "";
  if (st.lastStatus?.type === "card_status") cardEl.textContent = st.lastStatus.status ?? "?";
  if (st.consentPending) {
    consentEl.textContent = t("consent.pending", lang);
    consentEl.className = "badge warn";
    consentEl.style.display = "block";
  } else if (st.authorized) {
    consentEl.textContent = t("consent.approved", lang);
    consentEl.className = "badge ok";
    consentEl.style.display = "block";
  } else {
    consentEl.style.display = "none";
  }

  const { log = [] } = (await chrome.storage.local.get({ log: [] })) as { log: string[] };
  logEl.textContent = log.slice(0, 40).join("\n");

  const { origins = [] } = (await chrome.storage.sync.get({ origins: [] })) as { origins: string[] };
  originsEl.innerHTML = "";
  for (const o of origins) {
    const li = document.createElement("li");
    li.textContent = o + " ";
    const del = document.createElement("button");
    del.textContent = "×";
    del.onclick = async () => {
      await chrome.storage.sync.set({ origins: origins.filter((x) => x !== o) });
      await refresh();
    };
    li.appendChild(del);
    originsEl.appendChild(li);
  }

  const { requireHttps = true } = (await chrome.storage.sync.get({ requireHttps: true })) as {
    requireHttps: boolean;
  };
  reqHttpsEl.checked = requireHttps;
}

reqHttpsEl.onchange = async () => {
  await chrome.storage.sync.set({ requireHttps: reqHttpsEl.checked });
  await refresh();
};

const testBtn = document.getElementById("test-select") as HTMLButtonElement;

testBtn.onclick = async () => {
  if (testBtn.disabled) return;
  // SELECT CIE AID (test connettività end-to-end, non autentica).
  const aid = "A0000002471001";
  const payloadHex = `00A4040007${aid}00`;
  testBtn.disabled = true;
  outEl.textContent = `TX ${payloadHex}…`;
  outEl.className = "";
  try {
    const r = (await chrome.runtime.sendMessage({
      kind: "transmit",
      payloadHex,
      timeoutMs: 8000,
    })) as { ok: boolean; reply?: { data_hex: string; sw1: number; sw2: number }; error?: string };
    outEl.textContent = r.ok
      ? `RX data=${r.reply!.data_hex} SW=${r.reply!.sw1.toString(16)}${r.reply!.sw2.toString(16)}`
      : `ERR ${r.error}`;
    outEl.className = r.ok ? "ok" : "ko";
  } finally {
    testBtn.disabled = false;
  }
};

const addBtn = document.getElementById("add") as HTMLButtonElement;
const originHint = document.getElementById("origin-hint")!;

/** Origine accettata: URL assoluto https (mai http/ws in chiaro). */
function validOrigin(v: string): boolean {
  try {
    return new URL(v).protocol === "https:";
  } catch {
    return false;
  }
}

addBtn.onclick = async () => {
  const v = originInput.value.trim();
  if (!v) return;
  if (!validOrigin(v)) {
    originHint.textContent = t("origins.invalid", lang);
    originHint.hidden = false;
    return;
  }
  originHint.hidden = true;
  const { origins = [] } = (await chrome.storage.sync.get({ origins: [] })) as { origins: string[] };
  if (!origins.includes(v)) origins.push(v);
  await chrome.storage.sync.set({ origins });
  originInput.value = "";
  await refresh();
};

originInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    addBtn.click();
  }
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.kind === "engine-event" && msg.event?.type === "card_status") {
    cardEl.textContent = msg.event.status;
  }
  if (msg?.kind === "consent-status") void refresh();
});

await refresh();
setInterval(refresh, 3000);
