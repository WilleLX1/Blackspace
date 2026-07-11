import type { TransportMode } from "./types";

const V3_ONION = /^[a-z2-7]{56}\.onion$/;

export function isTauriRuntime(): boolean {
  return "__TAURI_INTERNALS__" in window;
}

export function deriveTransportMode(location: Pick<Location, "protocol" | "hostname">): TransportMode | null {
  if (isTauriRuntime()) return "tor-native";
  const hostname = location.hostname.toLowerCase();
  if (V3_ONION.test(hostname)) return "tor-web";
  if (location.protocol === "https:") return "https-web";
  if (location.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(hostname)) return "compatibility-web-dev";
  return null;
}

export function assertV3OnionUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "http:" || !V3_ONION.test(url.hostname.toLowerCase()) || url.port || url.username || url.password || url.search || url.hash || !["", "/"].includes(url.pathname)) {
    throw new Error("Tor modes accept only http://<56-character-v3-address>.onion");
  }
  return `http://${url.hostname.toLowerCase()}`;
}

export function modeLabel(mode: TransportMode): string {
  switch (mode) {
    case "tor-native": return "Tor Native";
    case "tor-web": return "Tor Web";
    case "https-web": return "HTTPS Web";
    case "compatibility-web-dev": return "Compatibility Web — HTTP development only";
  }
}

export function detectTransportMode(): TransportMode {
  return deriveTransportMode(window.location) ?? "compatibility-web-dev";
}

export function validateServerUrl(value: string, mode: TransportMode): string {
  if (mode === "tor-native" || mode === "tor-web") return assertV3OnionUrl(value);
  const url = new URL(value);
  if (mode === "https-web" && url.protocol === "https:" && !url.username && !url.password && !url.hash && !url.search) return url.origin;
  if (mode === "compatibility-web-dev" && url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname)) return url.origin;
  throw new Error("The server origin is not permitted in the active transport mode.");
}
