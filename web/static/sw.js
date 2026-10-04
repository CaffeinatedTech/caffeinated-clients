/* Service worker: caches the app shell and versioned static assets only.
   Authenticated HTML and all client data are NEVER cached (REQUIREMENTS F9.2). */
const VERSION = "__BUILD_VERSION__";
const CACHE = "cc-static-" + VERSION;
const ASSETS = [
  "/offline",
  "/manifest.webmanifest",
  "/static/app.css?v=" + VERSION,
  "/static/app.js?v=" + VERSION,
  "/static/theme.js?v=" + VERSION,
  "/static/htmx.min.js?v=" + VERSION,
  "/static/favicon.svg",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches
      .open(CACHE)
      .then(function (cache) {
        return cache.addAll(ASSETS);
      })
      .then(function () {
        return self.skipWaiting();
      })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches
      .keys()
      .then(function (keys) {
        return Promise.all(
          keys.map(function (key) {
            if (key !== CACHE) return caches.delete(key);
          })
        );
      })
      .then(function () {
        return self.clients.claim();
      })
  );
});

self.addEventListener("fetch", function (event) {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Navigations: network only; if it fails, show the cached offline page.
  // HTML responses are never written to the cache.
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req).catch(function () {
        return caches.match("/offline");
      })
    );
    return;
  }

  const cacheable =
    url.pathname.indexOf("/static/") === 0 ||
    url.pathname === "/manifest.webmanifest" ||
    url.pathname === "/offline";
  if (!cacheable) return;

  event.respondWith(
    caches.match(req).then(function (hit) {
      if (hit) return hit;
      return fetch(req).then(function (res) {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then(function (cache) {
            cache.put(req, copy);
          });
        }
        return res;
      });
    })
  );
});
