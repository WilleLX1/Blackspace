const CACHE_NAME = "blackspace-static-v0.1.0-csp1";
const CORE_ASSETS = [];

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    const assets = new Set(CORE_ASSETS);
    try {
      const response = await fetch("/.vite/manifest.json", { cache: "no-store" });
      if (response.ok) {
        const manifest = await response.json();
        for (const entry of Object.values(manifest)) {
          if (entry.file) assets.add(`/${entry.file}`);
          for (const css of entry.css ?? []) assets.add(`/${css}`);
          for (const asset of entry.assets ?? []) assets.add(`/${asset}`);
        }
      }
    } catch {
      // The development server has no build manifest.
    }
    await cache.addAll([...assets]);
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || event.request.mode === "navigate" || url.origin !== self.location.origin || url.pathname.startsWith("/v1/") || url.pathname === "/sw.js" || url.pathname === "/.vite/manifest.json") {
    return;
  }
  event.respondWith((async () => {
    const cached = await caches.match(event.request);
    if (cached) return cached;
    const response = await fetch(event.request);
    if (response.ok && url.pathname.startsWith("/assets/")) {
      const cache = await caches.open(CACHE_NAME);
      await cache.put(event.request, response.clone());
    }
    return response;
  })());
});
