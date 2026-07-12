// Device-sync channel between a primary and its linked companion. Sync payloads
// ride the existing opaque mailbox as ordinary self-deposited envelopes, so they
// MUST be encrypted here: the outer `envelopeForPacket` only pads, it does not
// encrypt, and any read-cap holder can see the packet header. Confidentiality and
// authenticity come from a per-pairing `linkSecret` that is independent of MLS and
// of the identity key. See docs plan "Multi-device via a Linked Companion".

import { base64Url, fromBase64Url, type LinkPacket } from "./crypto";
import type { ContactProjection, DeliveryState, MessageRecord } from "./model";

export type { LinkPacket };

const enc = new TextEncoder();
const dec = new TextDecoder();

const DIRECTION_INFO = {
  down: "blackspace:link:v1:downlink",
  up: "blackspace:link:v1:uplink",
} as const;

async function directionKey(linkSecret: string, pairingId: string, dir: "down" | "up"): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", fromBase64Url(linkSecret) as BufferSource, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode(pairingId), info: enc.encode(DIRECTION_INFO[dir]) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// Deterministic 96-bit nonce = 4 zero bytes ‖ 64-bit big-endian seq. Safe because
// each direction has exactly one writer; the seq is persisted before use so a
// crash/restore cannot roll it back into reuse.
function nonceForSeq(seq: number): Uint8Array {
  const nonce = new Uint8Array(12);
  const view = new DataView(nonce.buffer);
  view.setUint32(4, Math.floor(seq / 2 ** 32));
  view.setUint32(8, seq >>> 0);
  return nonce;
}

function additionalData(dir: "down" | "up", pairingId: string, seq: number): Uint8Array {
  return enc.encode(`blackspace:link:v1:${dir}:${pairingId}:${seq}`);
}

export async function sealLinkEvent(
  linkSecret: string,
  pairingId: string,
  dir: "down" | "up",
  seq: number,
  body: unknown,
): Promise<LinkPacket> {
  const key = await directionKey(linkSecret, pairingId, dir);
  const nonce = nonceForSeq(seq);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce as BufferSource, additionalData: additionalData(dir, pairingId, seq) },
    key,
    enc.encode(JSON.stringify(body)),
  ));
  return { kind: "link", dir, pid: pairingId, seq, nonce: base64Url(nonce), ct: base64Url(ciphertext) };
}

export async function openLinkEvent<T = unknown>(linkSecret: string, packet: LinkPacket): Promise<T> {
  const key = await directionKey(linkSecret, packet.pid, packet.dir);
  // Derive the nonce from the authenticated seq rather than trusting packet.nonce.
  const nonce = nonceForSeq(packet.seq);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce as BufferSource, additionalData: additionalData(packet.dir, packet.pid, packet.seq) },
    key,
    fromBase64Url(packet.ct) as BufferSource,
  );
  return JSON.parse(dec.decode(plaintext)) as T;
}

// Ack dispatch. Runs BEFORE any packet parse so a device never ack-deletes an
// envelope it does not own. Invariant: downlink is acked only by the companion;
// uplink + real inbound only by the primary; their ack classes never overlap.
export type LinkAction = "mls" | "applyUplink" | "applyDownlink" | "skip";

export interface LinkCapIds {
  downlinkCapId: string;
  uplinkCapId: string;
}

export function classify(
  depositCapabilityId: string,
  role: "primary" | "companion",
  link: LinkCapIds | undefined,
): { action: LinkAction; ack: boolean } {
  if (role === "companion") {
    if (link && depositCapabilityId === link.downlinkCapId) return { action: "applyDownlink", ack: true };
    // Strict allowlist: never ack real inbound (can't decrypt it) or own uplink.
    return { action: "skip", ack: false };
  }
  if (link && depositCapabilityId === link.downlinkCapId) return { action: "skip", ack: false };
  if (link && depositCapabilityId === link.uplinkCapId) return { action: "applyUplink", ack: true };
  // Catch-all drain: real inbound AND any unknown/stale cap-id belong to the primary.
  return { action: "mls", ack: true };
}

// Wire payloads carried inside the encrypted `ct`. Every payload has an id so a
// receiver can dedupe (pull is non-destructive; an envelope can arrive repeatedly
// before its ack deletes it) and a `ts` for display.
export interface SnapshotPayload {
  displayName: string;
  instanceName: string;
  identityPublicKey: string;
  contacts: ContactProjection[];
  messages: MessageRecord[];
}

export type DownlinkEvent =
  | { type: "snapshot"; eventId: string; ts: number; index: number; total: number; payload: SnapshotPayload }
  | { type: "message"; eventId: string; ts: number; contactId: string; message: MessageRecord }
  | { type: "delivery"; eventId: string; ts: number; messageId: string; delivery: DeliveryState; error?: string }
  | { type: "contact"; eventId: string; ts: number; contact: ContactProjection; removed?: boolean }
  | { type: "profile"; eventId: string; ts: number; contactId?: string; displayName?: string; verified?: boolean }
  | { type: "relay_result"; eventId: string; ts: number; commandId: string; messageId?: string; result: "sent" | "failed"; error?: string };

export type UplinkCommand =
  | { type: "hello"; commandId: string; ts: number; label?: string; downLastApplied: number }
  | { type: "send_text"; commandId: string; ts: number; contactId: string; body: string; clientSentAt: number }
  | { type: "accept_request"; commandId: string; ts: number; contactId: string }
  | { type: "block_contact"; commandId: string; ts: number; contactId: string }
  | { type: "set_verified"; commandId: string; ts: number; contactId: string }
  | { type: "retry_message"; commandId: string; ts: number; messageId: string }
  | { type: "request_resnapshot"; commandId: string; ts: number; reason: string };
