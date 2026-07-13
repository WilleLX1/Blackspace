import { describe, expect, it } from "vitest";
import type { AccountState, ContactRecord, MessageRecord } from "./model";
import { applyShared, extractShared, parseShared, serializeShared } from "./sharedstate";

function contact(id: string, draft: string): ContactRecord {
  return {
    id, identityPublicKey: `id-${id}`, displayName: `C${id}`, status: "accepted", verified: false,
    unread: 2, draft, target: { onion_url: "http://x.onion", deposit_capability: "cap" }, lastMessageAt: 5,
  };
}

function message(id: string): MessageRecord {
  return { id, contactId: "1", direction: "incoming", body: `body-${id}`, sentAt: Number(id), delivery: "delivered" };
}

function account(): AccountState {
  return {
    version: 1, displayName: "Me", instanceName: "Pi", mailboxId: "m", onionOrigin: "http://x.onion",
    readCapability: "read", adminCapability: "admin", identityPublicKey: "id", mlsClientState: "RATCHET",
    availableKeyPackages: 20, contacts: [contact("1", "half-typed"), contact("2", "")], messages: [message("1"), message("2")],
    createdAt: 0, rootSecret: "root", deviceId: "dev", mlsStateVersion: 3,
  };
}

describe("shared state extraction and merge", () => {
  it("omits device-local drafts from the shared blob", () => {
    const shared = extractShared(account());
    expect(shared.contacts.every((entry) => !("draft" in entry))).toBe(true);
    expect(shared.mlsClientState).toBe("RATCHET");
    expect(shared.messages).toHaveLength(2);
  });

  it("round-trips shared state through JSON", () => {
    const shared = extractShared(account());
    expect(parseShared(serializeShared(shared))).toEqual(shared);
  });

  it("preserves device-local fields and this device's drafts when applying shared state", () => {
    const local = account();
    // Simulate state committed by another device: renamed, contact 1 read, a new message.
    const incoming = extractShared(account());
    incoming.displayName = "Renamed";
    incoming.contacts[0].unread = 0;
    incoming.messages = [...incoming.messages, message("3")];

    const merged = applyShared(local, incoming);
    // Shared fields adopted:
    expect(merged.displayName).toBe("Renamed");
    expect(merged.contacts[0].unread).toBe(0);
    expect(merged.messages).toHaveLength(3);
    // Device-local fields preserved:
    expect(merged.rootSecret).toBe("root");
    expect(merged.adminCapability).toBe("admin");
    expect(merged.mlsStateVersion).toBe(3);
    // This device's in-progress draft is not clobbered by the remote state:
    expect(merged.contacts[0].draft).toBe("half-typed");
    // A contact with no local draft defaults to empty:
    expect(merged.contacts[1].draft).toBe("");
  });

  it("trims oldest messages when the blob would exceed its size ceiling", () => {
    const shared = extractShared(account());
    shared.messages = Array.from({ length: 4_000 }, (_unused, index) => ({
      id: String(index), contactId: "1", direction: "incoming", body: "x".repeat(1_000), sentAt: index, delivery: "delivered",
    }));
    const trimmed = parseShared(serializeShared(shared));
    expect(trimmed.messages.length).toBeLessThan(4_000);
    // The most recent messages survive; the oldest are dropped first.
    expect(trimmed.messages.at(-1)!.id).toBe("3999");
  });

  it("rejects malformed shared state", () => {
    expect(() => parseShared(JSON.stringify({ mlsClientState: 5 }))).toThrow();
  });
});
