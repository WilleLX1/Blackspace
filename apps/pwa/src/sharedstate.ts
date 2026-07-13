// The authoritative, cross-device conversation state carried inside the CAS blob
// (see plans/multi-device-floating.md). Every enrolled device downloads this,
// operates on it, and compare-and-swaps it back, so all devices converge on one
// history with no device required to stay online.
//
// Split of concerns:
//  - SHARED (here, in the encrypted blob): the MLS ratchet, contacts, and message
//    history — everything that must look identical on every device.
//  - DEVICE-LOCAL (stays in the vault, never in the blob): access secrets
//    (root/admin/read caps, mailboxId), this device's identity in the registry
//    (deviceId), the last-committed blob version, and per-contact compose drafts.

import type { AccountState, ContactRecord, MessageRecord } from "./model";

// A contact as stored in the shared blob: identical to ContactRecord minus the
// device-local `draft` the user is currently typing on one device.
export type SharedContact = Omit<ContactRecord, "draft">;

export interface SharedState {
  mlsClientState: string;
  availableKeyPackages: number;
  displayName: string;
  instanceName: string;
  identityPublicKey: string;
  onionOrigin: string;
  httpsOrigin?: string;
  contacts: SharedContact[];
  messages: MessageRecord[];
}

// Keep the serialized blob comfortably under the top MLS size class (3_145_728).
// If history ever grows past this, the oldest messages are trimmed from the blob
// (each device still keeps whatever it already cached locally).
const MAX_BLOB_BYTES = 2_800_000;

export function extractShared(account: AccountState): SharedState {
  return {
    mlsClientState: account.mlsClientState,
    availableKeyPackages: account.availableKeyPackages,
    displayName: account.displayName,
    instanceName: account.instanceName,
    identityPublicKey: account.identityPublicKey,
    onionOrigin: account.onionOrigin,
    httpsOrigin: account.httpsOrigin,
    contacts: account.contacts.map(({ draft: _draft, ...rest }) => rest),
    messages: account.messages,
  };
}

// Fold freshly-committed shared state back into the local vault account, preserving
// every device-local field: access secrets, deviceId, the blob version, and the
// per-contact compose draft the user may be mid-typing on this device.
export function applyShared(local: AccountState, shared: SharedState): AccountState {
  const draftById = new Map(local.contacts.map((contact) => [contact.id, contact.draft]));
  return {
    ...local,
    displayName: shared.displayName,
    instanceName: shared.instanceName,
    identityPublicKey: shared.identityPublicKey,
    onionOrigin: shared.onionOrigin,
    httpsOrigin: shared.httpsOrigin,
    mlsClientState: shared.mlsClientState,
    availableKeyPackages: shared.availableKeyPackages,
    contacts: shared.contacts.map((contact) => ({ ...contact, draft: draftById.get(contact.id) ?? "" })),
    messages: shared.messages,
  };
}

export function serializeShared(shared: SharedState): string {
  let candidate = shared;
  let encoded = JSON.stringify(candidate);
  // Trim oldest messages until the blob fits its largest size class.
  while (new TextEncoder().encode(encoded).length > MAX_BLOB_BYTES && candidate.messages.length > 0) {
    const trimmed = candidate.messages.slice(Math.ceil(candidate.messages.length / 10));
    candidate = { ...candidate, messages: trimmed };
    encoded = JSON.stringify(candidate);
  }
  return encoded;
}

export function parseShared(value: string): SharedState {
  const parsed = JSON.parse(value) as SharedState;
  if (typeof parsed.mlsClientState !== "string" || !Array.isArray(parsed.contacts) || !Array.isArray(parsed.messages)) {
    throw new Error("The shared device state is malformed.");
  }
  return parsed;
}
