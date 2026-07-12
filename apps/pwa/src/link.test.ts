import { describe, expect, it } from "vitest";
import { classify, openLinkEvent, sealLinkEvent } from "./link";
import type { LinkPacket } from "./crypto";
import { envelopeForPacket, packetFromEnvelope, randomCapability } from "./crypto";

const linkSecret = randomCapability();
const pairingId = "123e4567-e89b-42d3-a456-426614174000";

describe("device-sync link channel", () => {
  it("round-trips an encrypted event per direction", async () => {
    for (const dir of ["down", "up"] as const) {
      const packet = await sealLinkEvent(linkSecret, pairingId, dir, 1, { type: "hello", value: dir });
      expect(packet.kind).toBe("link");
      expect(await openLinkEvent(linkSecret, packet)).toEqual({ type: "hello", value: dir });
    }
  });

  it("is direction-keyed: a downlink packet cannot be opened as uplink", async () => {
    const down = await sealLinkEvent(linkSecret, pairingId, "down", 5, { hi: true });
    const forged: LinkPacket = { ...down, dir: "up" };
    await expect(openLinkEvent(linkSecret, forged)).rejects.toBeTruthy();
  });

  it("binds pairingId and seq into the AAD", async () => {
    const packet = await sealLinkEvent(linkSecret, pairingId, "down", 7, { n: 7 });
    await expect(openLinkEvent(linkSecret, { ...packet, pid: "00000000-0000-4000-8000-000000000000" })).rejects.toBeTruthy();
    await expect(openLinkEvent(linkSecret, { ...packet, seq: 8 })).rejects.toBeTruthy();
  });

  it("rejects a nonce that is not the canonical encoding of seq", async () => {
    const packet = await sealLinkEvent(linkSecret, pairingId, "down", 9, { ok: 1 });
    await expect(openLinkEvent(linkSecret, { ...packet, nonce: randomCapability() })).rejects.toThrow();
  });

  it("rejects unsafe sequence values before nonce construction", async () => {
    await expect(sealLinkEvent(linkSecret, pairingId, "down", 1.5, { bad: true })).rejects.toThrow();
    await expect(sealLinkEvent(linkSecret, pairingId, "down", Number.MAX_SAFE_INTEGER + 1, { bad: true })).rejects.toThrow();
  });

  it("rejects a foreign linkSecret", async () => {
    const packet = await sealLinkEvent(linkSecret, pairingId, "down", 1, { x: 1 });
    await expect(openLinkEvent(randomCapability(), packet)).rejects.toBeTruthy();
  });

  it("frames through the opaque padded envelope onto a valid size class", async () => {
    const packet = await sealLinkEvent(linkSecret, pairingId, "down", 3, { type: "message", body: "hello" });
    const envelope = envelopeForPacket(packet);
    expect([1024, 4096, 16384, 65536, 262144]).toContain(envelope.size_class);
    expect(packetFromEnvelope(envelope.ciphertext)).toMatchObject({ kind: "link", dir: "down", seq: 3 });
  });

  it("dispatches acks so neither device deletes the other's envelopes", () => {
    const link = { downlinkCapId: "down-cap", uplinkCapId: "up-cap" };
    expect(classify("down-cap", "primary", link)).toEqual({ action: "skip", ack: false });
    expect(classify("up-cap", "primary", link)).toEqual({ action: "applyUplink", ack: true });
    expect(classify("contact-cap", "primary", link)).toEqual({ action: "mls", ack: true });
    expect(classify("unknown-stale-cap", "primary", link)).toEqual({ action: "mls", ack: true });
    expect(classify("down-cap", "companion", link)).toEqual({ action: "applyDownlink", ack: true });
    expect(classify("up-cap", "companion", link)).toEqual({ action: "skip", ack: false });
    expect(classify("contact-cap", "companion", link)).toEqual({ action: "skip", ack: false });
  });
});
