import { envelopeForPacket } from "./crypto";
import { sealLinkEvent, type DownlinkEvent, type SnapshotPayload, type UplinkCommand } from "./link";
import type { AccountState, CompanionAccountState, ContactProjection, MessageRecord, PendingEnvelope } from "./model";

const HISTORY_PER_CONVERSATION = 200;
const EVENT_DEDUPE_LIMIT = 2_000;

export function projectContact(contact: AccountState["contacts"][number]): ContactProjection {
  const { id, identityPublicKey, displayName, localName, status, verified, unread, draft, lastMessageAt } = contact;
  return { id, identityPublicKey, displayName, localName, status, verified, unread, draft, lastMessageAt };
}

export function buildSnapshot(state: AccountState): SnapshotPayload {
  const allowed = new Set<string>();
  for (const contact of state.contacts) {
    state.messages.filter((message) => message.contactId === contact.id).slice(-HISTORY_PER_CONVERSATION).forEach((message) => allowed.add(message.id));
  }
  const candidates = state.messages.filter((message) => allowed.has(message.id)).sort((a, b) => b.sentAt - a.sentAt);
  const messages: MessageRecord[] = []; let encodedBytes = 0;
  for (const message of candidates) {
    const projected = { ...message, pendingEnvelope: undefined };
    const size = new TextEncoder().encode(JSON.stringify(projected)).length;
    if (encodedBytes + size > 180_000) continue;
    messages.push(projected); encodedBytes += size;
  }
  messages.sort((a, b) => a.sentAt - b.sentAt);
  return {
    displayName: state.displayName,
    instanceName: state.instanceName,
    identityPublicKey: state.identityPublicKey,
    onionOrigin: state.onionOrigin,
    httpsOrigin: state.httpsOrigin,
    contacts: state.contacts.map(projectContact),
    messages,
  };
}

export function applyDownlinkEvent(state: CompanionAccountState, event: DownlinkEvent): { state: CompanionAccountState; gap: boolean; applied: boolean } {
  const next = structuredClone(state);
  const ids = next.link.appliedEventIds ?? [];
  if (ids.includes(event.eventId)) return { state: next, gap: false, applied: false };
  ids.push(event.eventId);
  next.link.appliedEventIds = ids.slice(-EVENT_DEDUPE_LIMIT);
  let gap = false;

  if (event.type === "snapshot" || event.type === "snapshot_chunk") {
    next.displayName = event.payload.displayName;
    next.instanceName = event.payload.instanceName;
    next.identityPublicKey = event.payload.identityPublicKey;
    if (event.payload.onionOrigin) next.onionOrigin = event.payload.onionOrigin;
    next.httpsOrigin = event.payload.httpsOrigin;
    next.contacts = event.payload.contacts;
    next.messages = event.payload.messages;
  } else if (event.type === "message") {
    if (!next.messages.some((message) => message.id === event.message.id)) next.messages.push(event.message);
    const pending = next.link.pendingDeliveries?.[event.message.id];
    if (pending) {
      const message = next.messages.find((item) => item.id === event.message.id);
      if (message) message.delivery = pending;
      delete next.link.pendingDeliveries?.[event.message.id];
    }
  } else if (event.type === "delivery") {
    const message = next.messages.find((item) => item.id === event.messageId);
    if (message) { message.delivery = event.delivery; message.error = event.error; }
    else (next.link.pendingDeliveries ??= {})[event.messageId] = event.delivery;
  } else if (event.type === "contact") {
    const index = next.contacts.findIndex((contact) => contact.id === event.contact.id);
    if (event.removed) { if (index >= 0) next.contacts.splice(index, 1); }
    else if (index >= 0) next.contacts[index] = event.contact;
    else next.contacts.push(event.contact);
  } else if (event.type === "profile") {
    if (event.contactId) {
      const contact = next.contacts.find((item) => item.id === event.contactId);
      if (contact) { if (event.displayName) contact.displayName = event.displayName; if (event.verified !== undefined) contact.verified = event.verified; }
    } else if (event.displayName) next.displayName = event.displayName;
  } else if (event.type === "relay_result" && event.messageId) {
    const message = next.messages.find((item) => item.id === event.messageId);
    if (message) { message.delivery = event.result === "sent" ? "server-accepted" : "failed"; message.error = event.error; }
  }
  next.link.lastDownlinkAt = Date.now();
  return { state: next, gap, applied: true };
}

export async function sealNextUplink(
  state: CompanionAccountState,
  command: UplinkCommand,
  persistSequence: (state: CompanionAccountState) => Promise<void>,
): Promise<{ state: CompanionAccountState; envelope: PendingEnvelope }> {
  const next = structuredClone(state);
  next.link.upSeq += 1;
  await persistSequence(next);
  const packet = await sealLinkEvent(next.link.linkSecret, next.link.pairingId, "up", next.link.upSeq, command);
  return { state: next, envelope: envelopeForPacket(packet) };
}

export async function sealNextDownlink(
  state: AccountState,
  event: DownlinkEvent,
  persistSequence: (state: AccountState) => Promise<void>,
): Promise<{ state: AccountState; envelope: PendingEnvelope }> {
  if (!state.companionLink?.active) throw new Error("No active companion link.");
  const next = structuredClone(state);
  next.companionLink!.downSeq += 1;
  await persistSequence(next);
  const packet = await sealLinkEvent(next.companionLink!.linkSecret, next.companionLink!.pairingId, "down", next.companionLink!.downSeq, event);
  return { state: next, envelope: envelopeForPacket(packet) };
}

export const newMessage = (contactId: string, body: string, id = crypto.randomUUID()): MessageRecord => ({
  id, contactId, direction: "outgoing", body, sentAt: Date.now(), delivery: "queued",
});
