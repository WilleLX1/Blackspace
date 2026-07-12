import { describe, expect, it } from "vitest";
import {
  capabilityVerifier, envelopeForPacket, formatContactInvitation, fromBase64Url,
  packetFromEnvelope, parseContactInvitation, randomCapability,
} from "./crypto";

const onion = `http://${"a".repeat(56)}.onion`;

describe("private-alpha client framing", () => {
  it("round-trips strict contact invitations without putting secrets in HTTP paths", () => {
    const capability = randomCapability();
    const identity = randomCapability();
    const invitation = formatContactInvitation(
      { onion_url: onion, https_url: "https://example.com", deposit_capability: capability },
      identity,
      "123e4567-e89b-42d3-a456-426614174000",
    );
    expect(new URL(invitation).pathname).toBe("/v1");
    expect(new URL(invitation).hash).toContain(capability);
    expect(parseContactInvitation(invitation)).toMatchObject({ capability, identityPublicKey: identity, onionOrigin: onion });
  });

  it("accepts a custom HTTPS gateway port and preserves it", () => {
    const capability = randomCapability();
    const identity = randomCapability();
    const invitation = formatContactInvitation(
      { onion_url: onion, https_url: "https://gateway.example.com:8443", deposit_capability: capability },
      identity,
      "123e4567-e89b-42d3-a456-426614174000",
    );
    expect(parseContactInvitation(invitation).httpsOrigin).toBe("https://gateway.example.com:8443");
  });

  it("still normalizes the default HTTPS port away", () => {
    const invitation = formatContactInvitation(
      { onion_url: onion, https_url: "https://gateway.example.com:443", deposit_capability: randomCapability() },
      randomCapability(),
      "123e4567-e89b-42d3-a456-426614174000",
    );
    expect(parseContactInvitation(invitation).httpsOrigin).toBe("https://gateway.example.com");
  });

  it("still rejects HTTPS gateways carrying a path or credentials", () => {
    const identity = randomCapability();
    for (const https_url of ["https://gateway.example.com/mailbox", "https://user:pass@gateway.example.com", "http://gateway.example.com:8443", "https://gateway.example.com/?query=1", "https://gateway.example.com/#fragment"]) {
      const invitation = formatContactInvitation(
        { onion_url: onion, https_url, deposit_capability: randomCapability() },
        identity,
        "123e4567-e89b-42d3-a456-426614174000",
      );
      expect(() => parseContactInvitation(invitation)).toThrow();
    }
  });

  it("uses purpose-separated capability verifiers", async () => {
    const capability = randomCapability();
    expect(fromBase64Url(capability)).toHaveLength(32);
    await expect(capabilityVerifier("read", capability)).resolves.not.toBe(await capabilityVerifier("admin", capability));
  });

  it("pads opaque packets to an exact transport size class", () => {
    const packet = { kind: "mls" as const, hint: "0123456789abcdef", message: randomCapability() };
    const envelope = envelopeForPacket(packet);
    expect([1024, 4096, 16384, 65536, 262144]).toContain(envelope.size_class);
    expect(fromBase64Url(envelope.ciphertext)).toHaveLength(envelope.size_class);
    expect(packetFromEnvelope(envelope.ciphertext)).toEqual(packet);
  });
});
