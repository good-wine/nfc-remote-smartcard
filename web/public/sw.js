// Service worker: shell dell'app con index.html SEMPRE fresca (network-first)
// e asset statici hash-bustati in cache-first. Le API `/v1/*` sono SEMPRE rete
// (mai cache: stato carta e transazioni APDU devono essere fresche).
//
// Perché network-first per le navigazioni: se la shell venisse servita
// cache-first, dopo un deploy il browser continuerebbe a leggere l'index.html
// vecchio — che punta al bundle `index-<hash>.js` precedente — e l'utente
// "vedrebbe sempre la vecchia versione". Con network-first ogni caricamento
// recupera l'HTML corrente; la cache resta solo per l'offline.
const CACHE = "nfc-webapp-v2";
const SHELL = ["./", "./index.html", "./manifest.webmanifest", "./icon.svg"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((c) => c.addAll(SHELL))
      .then(() => self.skipWaiting())
      .catch(() => undefined),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  // Bypass esplicito per API/WS: mai cache su dati dinamici.
  if (url.pathname.startsWith("/v1/") || url.pathname.startsWith("/pair")) return;

  // Navigazione: rete prima, cache solo come fallback offline.
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((res) => {
          if (res.ok) {
            const copy = res.clone();
            void caches.open(CACHE).then((c) => c.put(request.url, copy));
          }
          return res;
        })
        .catch(() =>
          caches.match(request.url).then((hit) => {
            if (hit) return hit;
            return caches.match("./index.html") ?? Response.error();
          }),
        ),
    );
    return;
  }

  // Asset statici hash-bustati: cache-first, revalidati in background.
  event.respondWith(
    caches.match(request).then((hit) => {
      if (hit) {
        void fetch(request)
          .then((res) => res.ok && caches.open(CACHE).then((c) => c.put(request, res.clone())))
          .catch(() => undefined);
        return hit;
      }
      return fetch(request)
        .then((res) => {
          if (res.ok && url.origin === self.location.origin) {
            const copy = res.clone();
            void caches.open(CACHE).then((c) => c.put(request, copy));
          }
          return res;
        })
        .catch(() => Response.error());
    }),
  );
});