const encoder = new TextEncoder();

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function fillRandom(bytes: Uint8Array): void {
  for (let offset = 0; offset < bytes.length; offset += 65_536) {
    crypto.getRandomValues(bytes.subarray(offset, Math.min(offset + 65_536, bytes.length)));
  }
}

export function randomCapability(): string {
  const bytes = new Uint8Array(32);
  fillRandom(bytes);
  return base64Url(bytes);
}

export function randomCiphertext(size = 4096): string {
  const bytes = new Uint8Array(size);
  fillRandom(bytes);
  return base64Url(bytes);
}

export async function capabilityVerifier(
  purpose: "read" | "admin" | "deposit",
  capability: string,
): Promise<string> {
  const raw = capability.replaceAll("-", "+").replaceAll("_", "/");
  const padded = raw + "=".repeat((4 - (raw.length % 4)) % 4);
  const decoded = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  if (decoded.length !== 32 || base64Url(decoded) !== capability) {
    throw new Error("Capability must be canonical unpadded base64url for 32 bytes.");
  }
  const domain = encoder.encode(`blackspace:v1:${purpose}:`);
  const input = new Uint8Array(domain.length + decoded.length);
  input.set(domain);
  input.set(decoded, domain.length);
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", input)));
}
