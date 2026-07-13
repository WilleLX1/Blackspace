// Floating-primary multi-device crypto. Every enrolled device is a full device
// sharing one logical MLS client whose serialized state lives as an encrypted,
// versioned blob on the mailbox server (see plans/multi-device-floating.md).
//
// Two independent secrets ride here:
//  - the account ROOT SECRET, from which the blob-encryption key is derived; it is
//    shared with every device at enrollment and never leaves the encrypted channel.
//  - per-enrollment EPHEMERAL P-256 keys used to seal the one-time enrollment
//    parcel to a brand-new device (the enrollment QR carries only a public key and
//    a one-time claim bearer, never a long-term secret).

import { base64Url, fromBase64Url, randomBytes } from "./crypto";

const enc = new TextEncoder();
const dec = new TextDecoder();

// Mirrors MLS_STATE_SIZE_CLASSES in blackspace-protocol; the server rejects any
// blob whose length is not exactly one of these.
export const MLS_STATE_SIZE_CLASSES = [4_096, 16_384, 65_536, 262_144, 1_048_576, 3_145_728] as const;
const PARCEL_SIZE_CLASSES = [1_024, 4_096, 16_384, 65_536, 262_144] as const;

const BLOB_INFO = enc.encode("blackspace:mls-blob:v1");
const BLOB_AAD_PREFIX = "blackspace:mls-blob:v1:";
const ENROLL_INFO = enc.encode("blackspace:enroll:v1:parcel");

export function randomRootSecret(): string {
  return base64Url(randomBytes(32));
}

// ---- Shared MLS-state blob ----

async function blobKey(rootSecret: string, mailboxId: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", fromBase64Url(rootSecret) as BufferSource, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode(mailboxId), info: BLOB_INFO },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function chooseClass(minimumBytes: number, classes: readonly number[]): number {
  const chosen = classes.find((size) => size >= minimumBytes);
  if (!chosen) throw new Error("The encrypted payload is too large for this device channel.");
  return chosen;
}

export interface SealedBlob {
  size_class: number;
  ciphertext: string;
}

// Seals the serialized MLS client state into a fixed-size-class blob:
//   nonce(12) ‖ AES-GCM( u32 length ‖ plaintext ‖ random pad ).
// A random nonce (not a counter) is used because several devices may write the
// same blob key; the write count over a blob's life is tiny, far below the
// birthday bound for 96-bit GCM nonces.
export async function sealMlsState(rootSecret: string, mailboxId: string, state: string): Promise<SealedBlob> {
  const key = await blobKey(rootSecret, mailboxId);
  const plaintext = enc.encode(state);
  const sizeClass = chooseClass(12 + 16 + 4 + plaintext.length, MLS_STATE_SIZE_CLASSES);
  const innerSize = sizeClass - 12 - 16;
  const inner = randomBytes(innerSize);
  new DataView(inner.buffer).setUint32(0, plaintext.length);
  inner.set(plaintext, 4);
  const nonce = randomBytes(12);
  const gcm = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce as BufferSource, additionalData: enc.encode(BLOB_AAD_PREFIX + mailboxId) as BufferSource },
    key,
    inner as BufferSource,
  ));
  const blob = new Uint8Array(sizeClass);
  blob.set(nonce, 0);
  blob.set(gcm, 12);
  return { size_class: sizeClass, ciphertext: base64Url(blob) };
}

export async function openMlsState(rootSecret: string, mailboxId: string, sealed: SealedBlob): Promise<string> {
  const key = await blobKey(rootSecret, mailboxId);
  const blob = fromBase64Url(sealed.ciphertext);
  if (blob.length !== sealed.size_class || blob.length < 12 + 16 + 4) throw new Error("The shared state blob is malformed.");
  const nonce = blob.subarray(0, 12);
  const inner = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce as BufferSource, additionalData: enc.encode(BLOB_AAD_PREFIX + mailboxId) as BufferSource },
    key,
    blob.subarray(12) as BufferSource,
  ));
  const length = new DataView(inner.buffer, inner.byteOffset, inner.byteLength).getUint32(0);
  if (length > inner.length - 4) throw new Error("The shared state blob length is invalid.");
  return dec.decode(inner.subarray(4, 4 + length));
}

// ---- One-scan enrollment ----

export interface EnrollmentBundle {
  rootSecret: string;
  readCapability: string;
  adminCapability: string;
  identityPublicKey: string;
  mailboxId: string;
  onionOrigin: string;
  httpsOrigin?: string;
  displayName: string;
  instanceName: string;
  deviceId: string;
}

export interface EnrollmentOffer {
  parcelId: string;
  claimSecret: string;
  privateKey: CryptoKey;
  nPub: string;
  qr: string;
}

interface OfferPayload { v: 1; parcelId: string; nPub: string; claimSecret: string }

async function ephemeral(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

async function publicRaw(key: CryptoKey): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.exportKey("raw", key)));
}

async function importPublic(value: string): Promise<CryptoKey> {
  const bytes = fromBase64Url(value);
  if (bytes.length !== 65) throw new Error("The enrollment public key is invalid.");
  return crypto.subtle.importKey("raw", bytes as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
}

async function sharedKey(privateKey: CryptoKey, peerPublic: string, parcelId: string): Promise<{ key: CryptoKey; raw: Uint8Array }> {
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: await importPublic(peerPublic) }, privateKey, 256));
  const hkdf = await crypto.subtle.importKey("raw", bits as BufferSource, "HKDF", false, ["deriveBits", "deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode(parcelId), info: ENROLL_INFO },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const raw = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: enc.encode(parcelId), info: enc.encode("blackspace:enroll:v1:sas") }, hkdf, 256));
  return { key, raw };
}

// 64-emoji alphabet → 4 emoji = 24 bits of short-authentication-string. Compared
// by a human across the two screens to defeat a swapped-QR man-in-the-middle.
const SAS_EMOJI = [..."🍎🍋🍇🍉🍒🍑🥝🥑🌽🥕🍄🌰🐬🐢🦋🐝🦉🦅🦆🐳🐙🦀🐞🕷️🌵🌻🌴🍀🌙⭐☀️❄️🔥💧🌈⚡🎈🎁🎨🎧🎸🎺🥁🚀✈️⛵🚲🏰⚓🔑🔔💎🧭📚✏️🧵🪁🧩♟️🎲🧦🧢👑💡"];

function sasFrom(raw: Uint8Array): string {
  return [raw[0] & 63, raw[1] & 63, raw[2] & 63, raw[3] & 63].map((index) => SAS_EMOJI[index]).join(" ");
}

// New (unenrolled) device: generate the offer shown as a single QR.
export async function createEnrollmentOffer(onionOrigin: string, httpsOrigin: string | undefined): Promise<EnrollmentOffer> {
  const keys = await ephemeral();
  const parcelId = crypto.randomUUID();
  const claimSecret = base64Url(randomBytes(32));
  const nPub = await publicRaw(keys.publicKey);
  const payload: OfferPayload = { v: 1, parcelId, nPub, claimSecret };
  const url = new URL("blackspace://enroll/v1");
  url.searchParams.set("onion", onionOrigin);
  url.searchParams.set("https", httpsOrigin ?? "");
  url.hash = new URLSearchParams({ d: base64Url(enc.encode(JSON.stringify(payload))) }).toString();
  return { parcelId, claimSecret, privateKey: keys.privateKey, nPub, qr: url.toString() };
}

export function parseEnrollmentOffer(value: string): { parcelId: string; nPub: string; claimSecret: string; onionOrigin: string; httpsOrigin?: string } {
  const url = new URL(value.trim());
  if (url.protocol !== "blackspace:" || url.hostname !== "enroll" || url.pathname !== "/v1") throw new Error("This is not a Blackspace device-enrollment code.");
  const encoded = new URLSearchParams(url.hash.slice(1)).get("d") ?? "";
  if (!encoded || encoded.length > 4_096) throw new Error("The enrollment code is invalid.");
  const payload = JSON.parse(dec.decode(fromBase64Url(encoded))) as Partial<OfferPayload>;
  if (payload.v !== 1 || !/^[0-9a-f-]{36}$/i.test(payload.parcelId ?? "") || fromBase64Url(payload.nPub ?? "").length !== 65 || fromBase64Url(payload.claimSecret ?? "").length !== 32) {
    throw new Error("The enrollment code is invalid.");
  }
  return {
    parcelId: payload.parcelId!,
    nPub: payload.nPub!,
    claimSecret: payload.claimSecret!,
    onionOrigin: url.searchParams.get("onion") ?? "",
    httpsOrigin: url.searchParams.get("https") || undefined,
  };
}

export interface SealedParcel {
  parcel_verifier: string;
  eph_pub: string;
  nonce: string;
  size_class: number;
  ciphertext: string;
  expires_at: number;
}

// Trusted (enrolled) device: seal the enrollment bundle to the new device's key.
export async function sealEnrollmentParcel(
  offer: { parcelId: string; nPub: string; claimSecret: string },
  bundle: EnrollmentBundle,
): Promise<{ parcel: SealedParcel; sas: string }> {
  const keys = await ephemeral();
  const ePub = await publicRaw(keys.publicKey);
  const { key, raw } = await sharedKey(keys.privateKey, offer.nPub, offer.parcelId);
  const plaintext = enc.encode(JSON.stringify(bundle));
  const sizeClass = chooseClass(12 + 16 + 4 + plaintext.length, PARCEL_SIZE_CLASSES);
  const inner = randomBytes(sizeClass - 16);
  new DataView(inner.buffer).setUint32(0, plaintext.length);
  inner.set(plaintext, 4);
  const nonce = randomBytes(12);
  const aad = enc.encode(`blackspace:enroll:v1:${offer.parcelId}:${offer.nPub}:${ePub}`);
  const gcm = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource }, key, inner as BufferSource));
  return {
    parcel: {
      parcel_verifier: await capabilityVerifierEnroll(offer.claimSecret),
      eph_pub: ePub,
      nonce: base64Url(nonce),
      size_class: sizeClass,
      ciphertext: base64Url(gcm),
      expires_at: Math.floor(Date.now() / 1000) + 60 * 60,
    },
    sas: sasFrom(raw),
  };
}

// New device: open the claimed parcel with its ephemeral private key.
export async function openEnrollmentParcel(
  offer: EnrollmentOffer,
  claimed: { eph_pub: string; nonce: string; size_class: number; ciphertext: string },
): Promise<{ bundle: EnrollmentBundle; sas: string }> {
  const { key, raw } = await sharedKey(offer.privateKey, claimed.eph_pub, offer.parcelId);
  const gcm = fromBase64Url(claimed.ciphertext);
  if (gcm.length !== claimed.size_class) throw new Error("The enrollment parcel is malformed.");
  const aad = enc.encode(`blackspace:enroll:v1:${offer.parcelId}:${offer.nPub}:${claimed.eph_pub}`);
  const inner = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(claimed.nonce) as BufferSource, additionalData: aad as BufferSource }, key, gcm as BufferSource));
  const length = new DataView(inner.buffer, inner.byteOffset, inner.byteLength).getUint32(0);
  if (length > inner.length - 4) throw new Error("The enrollment parcel length is invalid.");
  return { bundle: JSON.parse(dec.decode(inner.subarray(4, 4 + length))) as EnrollmentBundle, sas: sasFrom(raw) };
}

// The claim bearer's verifier, domain-separated for the Enroll capability kind
// (mirrors the server's CapabilityKind::Enroll).
async function capabilityVerifierEnroll(claimSecret: string): Promise<string> {
  const domain = enc.encode("blackspace:v1:enroll:");
  const rawSecret = fromBase64Url(claimSecret);
  const input = new Uint8Array(domain.length + rawSecret.length);
  input.set(domain);
  input.set(rawSecret, domain.length);
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", input)));
}
