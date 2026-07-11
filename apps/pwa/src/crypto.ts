import type {
  ContactInvitation,
  DepositTarget,
  JoinInvitation,
} from "./model";

export const base64Url = (bytes: Uint8Array): string => {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
};

export const fromBase64Url = (value: string): Uint8Array => {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
};

export function randomCapability(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function capabilityVerifier(kind: "read" | "admin" | "deposit", capability: string): Promise<string> {
  const domain = new TextEncoder().encode(`blackspace:v1:${kind}:`);
  const raw = fromBase64Url(capability);
  const input = new Uint8Array(domain.length + raw.length);
  input.set(domain);
  input.set(raw, domain.length);
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", input)));
}

function strictOnionOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "http:" || !/^[a-z2-7]{56}\.onion$/.test(url.hostname) || url.port || url.username || url.password || url.pathname !== "/") {
    throw new Error("The invitation does not contain a canonical Tor v3 onion origin.");
  }
  return url.origin;
}

function optionalHttps(value: string | null): string | undefined {
  if (!value) return undefined;
  const url = new URL(value);
  // A non-default port is permitted so an operator can leave 443 to another
  // service and expose Blackspace's HTTPS gateway elsewhere (e.g. :8443). The
  // rest of the origin stays locked down: https only, no embedded credentials,
  // and no path/query/fragment smuggled through the invitation. url.origin
  // preserves the explicit port when present and omits it for the default 443.
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/") {
    throw new Error("The HTTPS gateway in the invitation is invalid.");
  }
  return url.origin;
}

export function parseJoinInvitation(value: string): JoinInvitation {
  const url = new URL(value.trim());
  if (url.protocol !== "blackspace:" || url.hostname !== "join" || url.pathname !== "/v1") throw new Error("This is not a Blackspace server invitation.");
  const fragment = new URLSearchParams(url.hash.slice(1));
  const token = fragment.get("token") ?? "";
  if (fromBase64Url(token).length !== 32) throw new Error("The registration token is invalid.");
  return {
    onionOrigin: strictOnionOrigin(url.searchParams.get("onion") ?? ""),
    httpsOrigin: optionalHttps(url.searchParams.get("https")),
    token,
  };
}

export function parseContactInvitation(value: string): ContactInvitation {
  const url = new URL(value.trim());
  if (url.protocol !== "blackspace:" || url.hostname !== "contact" || url.pathname !== "/v1") throw new Error("This is not a Blackspace contact invitation.");
  const fragment = new URLSearchParams(url.hash.slice(1));
  const capability = fragment.get("cap") ?? "";
  const identityPublicKey = fragment.get("identity") ?? "";
  const inviteId = fragment.get("invite") ?? "";
  if (fromBase64Url(capability).length !== 32 || fromBase64Url(identityPublicKey).length !== 32 || !/^[0-9a-f-]{36}$/i.test(inviteId)) {
    throw new Error("The contact invitation contains invalid key material.");
  }
  return {
    onionOrigin: strictOnionOrigin(url.searchParams.get("onion") ?? ""),
    httpsOrigin: optionalHttps(url.searchParams.get("https")),
    capability,
    identityPublicKey,
    inviteId,
  };
}

export function formatContactInvitation(target: DepositTarget, identityPublicKey: string, inviteId: string): string {
  const url = new URL("blackspace://contact/v1");
  url.searchParams.set("onion", target.onion_url);
  url.searchParams.set("https", target.https_url ?? "");
  url.hash = new URLSearchParams({ cap: target.deposit_capability, identity: identityPublicKey, invite: inviteId }).toString();
  return url.toString();
}

export interface MlsBootstrapPacket { kind: "mls_bootstrap"; welcome: string; firstMessage: string }
export interface MlsPacket { kind: "mls"; hint: string; message: string }
export type OpaquePacket = MlsBootstrapPacket | MlsPacket;

export interface SecureContent {
  version: 1;
  type: "text" | "delivery_receipt" | "profile" | "session_reset";
  messageId: string;
  sentAt: number;
  senderIdentity: string;
  body?: string;
  deliveredIds?: string[];
  displayName?: string;
  replyInvitation?: string;
}

export function envelopeForPacket(packet: OpaquePacket): { version: number; envelope_id: string; expires_at: number; size_class: number; ciphertext: string } {
  const payload = new TextEncoder().encode(JSON.stringify(packet));
  const sizeClass = [1024, 4096, 16384, 65536, 262144].find((size) => size >= payload.length + 4);
  if (!sizeClass) throw new Error("The encrypted message is too large.");
  const padded = crypto.getRandomValues(new Uint8Array(sizeClass));
  new DataView(padded.buffer).setUint32(0, payload.length);
  padded.set(payload, 4);
  return { version: 1, envelope_id: crypto.randomUUID(), expires_at: Math.floor(Date.now() / 1000) + 14 * 24 * 60 * 60, size_class: sizeClass, ciphertext: base64Url(padded) };
}

export function packetFromEnvelope(ciphertext: string): OpaquePacket {
  const bytes = fromBase64Url(ciphertext);
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
  if (length < 20 || length > bytes.length - 4) throw new Error("Malformed opaque envelope.");
  return JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + length))) as OpaquePacket;
}
