import { readFile } from "node:fs/promises";

const policies = [
  "apps/pwa/nginx.conf",
  "apps/desktop-windows/src-tauri/tauri.conf.json",
];

for (const path of policies) {
  const contents = await readFile(path, "utf8");
  if (!contents.includes("script-src 'self' 'wasm-unsafe-eval'")) {
    throw new Error(`${path} must explicitly permit WebAssembly compilation.`);
  }
  if (/script-src[^;\"]*'unsafe-eval'/.test(contents)) {
    throw new Error(`${path} must not enable general JavaScript unsafe-eval.`);
  }
}

const serviceWorker = await readFile("apps/pwa/public/sw.js", "utf8");
if (!serviceWorker.includes('event.request.mode === "navigate"') || serviceWorker.includes('const CORE_ASSETS = ["/"')) {
  throw new Error("The service worker must never cache or intercept HTML navigations carrying security headers.");
}
if (!serviceWorker.includes('url.pathname.startsWith("/v1/")')) {
  throw new Error("The service worker must never cache mailbox API traffic.");
}

console.log("Browser and Tauri CSP policies allow WebAssembly without JavaScript unsafe-eval.");
