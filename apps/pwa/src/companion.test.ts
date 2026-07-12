import { describe, expect, it } from "vitest";
import { applyDownlinkEvent, buildSnapshot } from "./companion";
import type { AccountState, CompanionAccountState } from "./model";

const companion = (): CompanionAccountState => ({ version: 1, role: "companion", displayName: "A", instanceName: "B", mailboxId: crypto.randomUUID(), onionOrigin: `http://${"a".repeat(56)}.onion`, createdAt: Date.now(), readCapability: "r", identityPublicKey: "i", contacts: [], messages: [], link: { pairingId: crypto.randomUUID(), linkSecret: "s", downlinkCapId: "d", uplinkCap: "u", uplinkCapId: "ui", downLastApplied: 0, upSeq: 0, uplinkOutbox: [], confirmed: true } });

describe("companion projection", () => {
  it("deduplicates events and reconciles delivery before message", () => {
    let state = companion();
    state = applyDownlinkEvent(state, { type: "delivery", eventId: "delivery", ts: 1, messageId: "m", delivery: "delivered" }).state;
    const event = { type: "message" as const, eventId: "message", ts: 2, contactId: "c", message: { id: "m", contactId: "c", direction: "outgoing" as const, body: "hi", sentAt: 1, delivery: "queued" as const } };
    state = applyDownlinkEvent(state, event).state;
    expect(state.messages[0].delivery).toBe("delivered");
    expect(applyDownlinkEvent(state, event).applied).toBe(false);
  });

  it("caps snapshot history per conversation", () => {
    const primary = { contacts: [{ id: "c" }], messages: Array.from({ length: 205 }, (_, index) => ({ id: String(index), contactId: "c" })) } as unknown as AccountState;
    expect(buildSnapshot(primary).messages).toHaveLength(200);
  });
});
