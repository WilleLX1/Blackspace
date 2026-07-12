import { base64Url, fromBase64Url } from "./crypto";

const enc = new TextEncoder();
const dec = new TextDecoder();
const PAIR_INFO = enc.encode("blackspace:link:v1:pair");

export interface PairingBundle {
  readCapability: string;
  downlinkCap: string;
  downlinkCapId: string;
  uplinkCap: string;
  uplinkCapId: string;
  linkSecret: string;
  onionOrigin: string;
  httpsOrigin?: string;
  identityPublicKey: string;
  displayName: string;
  instanceName: string;
}

interface Qr1 { v: 1; pairingId: string; ecPub: string; nonce: string }
interface Qr2 { v: 1; pairingId: string; epPub: string; nonce: string; ct: string }

export interface CompanionPairingOffer {
  pairingId: string;
  privateKey: CryptoKey;
  ecPub: string;
  qr: string;
}

export interface PrimaryPairingResponse {
  pairingId: string;
  qr: string;
  sas: string;
}

function qr(kind: "offer" | "response", value: Qr1 | Qr2): string {
  const url = new URL("blackspace://link/v1");
  url.hash = new URLSearchParams({ d: base64Url(enc.encode(JSON.stringify({ kind, ...value }))) }).toString();
  return url.toString();
}

function parse<T>(value: string, kind: "offer" | "response"): T {
  const url = new URL(value.trim());
  if (url.protocol !== "blackspace:" || url.hostname !== "link" || url.pathname !== "/v1" || url.search) throw new Error("This is not a Blackspace device-link code.");
  const encoded = new URLSearchParams(url.hash.slice(1)).get("d") ?? "";
  if (!encoded || encoded.length > 16_384) throw new Error("The device-link code is invalid.");
  const parsed = JSON.parse(dec.decode(fromBase64Url(encoded))) as T & { kind?: string; v?: number; pairingId?: string };
  if (parsed.kind !== kind || parsed.v !== 1 || !/^[0-9a-f-]{36}$/i.test(parsed.pairingId ?? "")) throw new Error("The device-link code is invalid.");
  return parsed;
}

async function ephemeral(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

async function publicRaw(key: CryptoKey): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.exportKey("raw", key)));
}

async function importPublic(value: string): Promise<CryptoKey> {
  const bytes = fromBase64Url(value);
  if (bytes.length !== 65) throw new Error("The pairing public key is invalid.");
  return crypto.subtle.importKey("raw", bytes as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
}

async function pairKey(privateKey: CryptoKey, peerPublic: string, pairingId: string): Promise<Uint8Array> {
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: await importPublic(peerPublic) }, privateKey, 256));
  const hkdf = await crypto.subtle.importKey("raw", shared as BufferSource, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: enc.encode(pairingId), info: PAIR_INFO }, hkdf, 256));
}

async function sas(pairingId: string, ecPub: string, epPub: string, key: Uint8Array): Promise<string> {
  const material = enc.encode(`${pairingId}|${ecPub}|${epPub}|${base64Url(key)}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", material));
  const value = ((digest[0] << 16) | (digest[1] << 8) | digest[2]) % 1_000_000;
  return value.toString().padStart(6, "0");
}

export async function createCompanionPairingOffer(): Promise<CompanionPairingOffer> {
  const keys = await ephemeral();
  const pairingId = crypto.randomUUID();
  const ecPub = await publicRaw(keys.publicKey);
  const value: Qr1 = { v: 1, pairingId, ecPub, nonce: base64Url(crypto.getRandomValues(new Uint8Array(16))) };
  return { pairingId, privateKey: keys.privateKey, ecPub, qr: qr("offer", value) };
}

export async function createPrimaryPairingResponse(offerCode: string, bundle: PairingBundle): Promise<PrimaryPairingResponse> {
  const offer = parse<Qr1>(offerCode, "offer");
  const keys = await ephemeral();
  const epPub = await publicRaw(keys.publicKey);
  const keyBytes = await pairKey(keys.privateKey, offer.ecPub, offer.pairingId);
  const key = await crypto.subtle.importKey("raw", keyBytes as BufferSource, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = enc.encode(`blackspace:link:v1:bundle:${offer.pairingId}:${offer.ecPub}:${epPub}`);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource }, key, enc.encode(JSON.stringify(bundle))));
  const response: Qr2 = { v: 1, pairingId: offer.pairingId, epPub, nonce: base64Url(nonce), ct: base64Url(ct) };
  return { pairingId: offer.pairingId, qr: qr("response", response), sas: await sas(offer.pairingId, offer.ecPub, epPub, keyBytes) };
}

export async function openPrimaryPairingResponse(offer: CompanionPairingOffer, responseCode: string): Promise<{ bundle: PairingBundle; sas: string }> {
  const response = parse<Qr2>(responseCode, "response");
  if (response.pairingId !== offer.pairingId) throw new Error("The pairing response belongs to another session.");
  const keyBytes = await pairKey(offer.privateKey, response.epPub, offer.pairingId);
  const key = await crypto.subtle.importKey("raw", keyBytes as BufferSource, { name: "AES-GCM" }, false, ["decrypt"]);
  const aad = enc.encode(`blackspace:link:v1:bundle:${offer.pairingId}:${offer.ecPub}:${response.epPub}`);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(response.nonce) as BufferSource, additionalData: aad as BufferSource }, key, fromBase64Url(response.ct) as BufferSource);
  return { bundle: JSON.parse(dec.decode(plaintext)) as PairingBundle, sas: await sas(offer.pairingId, offer.ecPub, response.epPub, keyBytes) };
}
