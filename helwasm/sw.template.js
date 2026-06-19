// sw.js is GENERATED from this template by build.sh — edit the template, not sw.js.
// LesS/KEY home-screen app: precache the shell + deterministic in-place update.
// The app makes no network calls by design ("nothing leaves your device"), so the
// worker only owns the static shell and swaps it atomically per version. Updates
// rewrite Cache Storage (code) ONLY — localStorage (your catalog) is never touched.
//
// VERSION is replaced by build.sh with a content hash of the shipped files, so the
// browser sees a byte-changed worker — and runs its update check — exactly when the
// app's bytes actually change, and never needlessly otherwise.
const VERSION = "__VERSION__";
const CACHE = `lesskey-${VERSION}`;

// App shell: every static file needed to run fully offline. Paths are relative to
// the SW scope (/sk/). Keep in sync with the build (see OQ-AU2 in the design note).
const SHELL = [
  "./",
  "./index.html",
  "./style.css",
  "./pkg/helwasm.js",
  "./pkg/helwasm_bg.wasm",
  "./assets/site.webmanifest",
  "./assets/favicon-16x16.png",
  "./assets/favicon-32x32.png",
  "./assets/favicon.ico",
  "./assets/apple-touch-icon.png",
  "./assets/icon-192.png",
  "./assets/icon-512.png",
  "./assets/enso.png",
  "./assets/fonts/Inter-400.woff2",
  "./assets/fonts/Inter-500.woff2",
  "./assets/fonts/Inter-600.woff2",
  "./assets/fonts/Poppins-600.woff2",
  "./assets/fonts/Poppins-700.woff2",
  "./assets/fonts/JetBrainsMono-400.woff2",
  "./assets/fonts/JetBrainsMono-500.woff2",
  "./assets/fonts/text-security-disc.woff2",
];

// Install: precache the whole shell under this version, then go waiting fast.
self.addEventListener("install", (e) => {
  e.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      // {cache:'reload'} bypasses the HTTP cache so we precache FRESH bytes,
      // not whatever stale copy the browser already holds.
      await cache.addAll(SHELL.map((u) => new Request(u, { cache: "reload" })));
      await self.skipWaiting();
    })(),
  );
});

// Activate: delete old version caches, take control of open clients.
self.addEventListener("activate", (e) => {
  e.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(
        keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)),
      );
      await self.clients.claim();
    })(),
  );
});

// Fetch: cache-first for same-origin GET. ignoreSearch so cache-busting query
// strings (e.g. the favicons' ?v=2) still hit the precached entry.
self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  if (new URL(req.url).origin !== self.location.origin) return;
  e.respondWith(
    (async () => {
      const hit = await caches.match(req, { ignoreSearch: true });
      if (hit) return hit;
      try {
        const res = await fetch(req);
        if (res.ok) (await caches.open(CACHE)).put(req, res.clone());
        return res;
      } catch (err) {
        if (req.mode === "navigate") {
          return caches.match("./index.html", { ignoreSearch: true });
        }
        throw err;
      }
    })(),
  );
});
