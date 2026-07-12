import { describe, expect, it } from "vitest";
import { randomCapability } from "./crypto";
import { createCompanionPairingOffer, createPrimaryPairingResponse, openPrimaryPairingResponse, type PairingBundle } from "./pairing";

const bundle = (): PairingBundle => ({
  readCapability: randomCapability(), downlinkCap: randomCapability(), downlinkCapId: crypto.randomUUID(),
  uplinkCap: randomCapability(), uplinkCapId: crypto.randomUUID(), linkSecret: randomCapability(),
  onionOrigin: `http://${"a".repeat(56)}.onion`, identityPublicKey: randomCapability(), displayName: "Alice", instanceName: "Blackspace",
});

describe("hardened companion pairing", () => {
  it("round-trips an encrypted bundle and matching SAS", async () => {
    const offer = await createCompanionPairingOffer();
    const response = await createPrimaryPairingResponse(offer.qr, bundle());
    const opened = await openPrimaryPairingResponse(offer, response.qr);
    expect(opened.sas).toBe(response.sas);
    expect(opened.bundle.displayName).toBe("Alice");
    expect(new URL(offer.qr).pathname).toBe("/v1");
    expect(offer.qr).not.toContain(opened.bundle.linkSecret);
    expect(response.qr).not.toContain(opened.bundle.readCapability);
  });

  it("rejects a response from another ephemeral pairing", async () => {
    const first = await createCompanionPairingOffer();
    const second = await createCompanionPairingOffer();
    const response = await createPrimaryPairingResponse(second.qr, bundle());
    await expect(openPrimaryPairingResponse(first, response.qr)).rejects.toThrow();
  });
});
