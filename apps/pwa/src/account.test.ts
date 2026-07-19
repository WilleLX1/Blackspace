import { describe, expect, it } from "vitest";
import { capabilityVerifier, fromBase64Url } from "./crypto";
import {
  MLS_STATE_SIZE_CLASSES,
  createEnrollmentOffer,
  enrollmentSas,
  finalizeEnrollmentParcel,
  openEnrollmentParcel,
  openMlsState,
  parseEnrollmentOffer,
  randomRootSecret,
  prepareEnrollmentParcel,
  sealMlsState,
  type EnrollmentBundle,
} from "./account";

const onion = `http://${"a".repeat(56)}.onion`;

function sampleBundle(): EnrollmentBundle {
  return {
    rootSecret: randomRootSecret(),
    readCapability: randomRootSecret(),
    adminCapability: randomRootSecret(),
    identityPublicKey: randomRootSecret(),
    mailboxId: crypto.randomUUID(),
    onionOrigin: onion,
    httpsOrigin: "https://blackspace.example.com:8443",
    displayName: "Alex",
    instanceName: "Home Pi",
    deviceId: crypto.randomUUID(),
  };
}

describe("shared MLS-state blob", () => {
  it("round-trips an arbitrary state string through a padded size class", async () => {
    const root = randomRootSecret();
    const mailboxId = crypto.randomUUID();
    const state = JSON.stringify({ ratchet: "x".repeat(5_000), groups: [1, 2, 3] });
    const sealed = await sealMlsState(root, mailboxId, state);
    expect(MLS_STATE_SIZE_CLASSES).toContain(sealed.size_class);
    expect(fromBase64Url(sealed.ciphertext).length).toBe(sealed.size_class);
    expect(await openMlsState(root, mailboxId, sealed)).toBe(state);
  });

  it("does not leak plaintext length below the chosen bucket", async () => {
    const root = randomRootSecret();
    const mailboxId = crypto.randomUUID();
    const small = await sealMlsState(root, mailboxId, "hi");
    const bigger = await sealMlsState(root, mailboxId, "y".repeat(3_000));
    // Both fit the smallest 4096 bucket, so their on-wire sizes are identical.
    expect(small.size_class).toBe(4_096);
    expect(bigger.size_class).toBe(4_096);
  });

  it("fills state buckets larger than the Web Crypto per-call entropy limit", async () => {
    const root = randomRootSecret();
    const mailboxId = crypto.randomUUID();
    const state = JSON.stringify({ ratchet: "x".repeat(70_000) });
    const sealed = await sealMlsState(root, mailboxId, state);
    expect(sealed.size_class).toBe(262_144);
    expect(await openMlsState(root, mailboxId, sealed)).toBe(state);
  });

  it("rejects a tampered blob and the wrong root secret", async () => {
    const root = randomRootSecret();
    const mailboxId = crypto.randomUUID();
    const sealed = await sealMlsState(root, mailboxId, "secret state");
    const bytes = fromBase64Url(sealed.ciphertext);
    bytes[20] ^= 0xff;
    const tampered = { size_class: sealed.size_class, ciphertext: btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "") };
    await expect(openMlsState(root, mailboxId, tampered)).rejects.toThrow();
    await expect(openMlsState(randomRootSecret(), mailboxId, sealed)).rejects.toThrow();
  });
});

describe("confirmed enrollment", () => {
  it("shows a matching SAS before sealing a bundle the new device can open", async () => {
    const offer = await createEnrollmentOffer(onion, "https://blackspace.example.com:8443");
    const parsed = parseEnrollmentOffer(offer.qr);
    expect(parsed.parcelId).toBe(offer.parcelId);
    expect(parsed.nPub).toBe(offer.nPub);

    const bundle = sampleBundle();
    const prepared = await prepareEnrollmentParcel(parsed);
    const newDeviceSas = await enrollmentSas(offer, prepared.ePub);
    expect(newDeviceSas).toBe(prepared.sas);

    const parcel = await finalizeEnrollmentParcel(prepared, bundle);
    const claimed = { eph_pub: prepared.ePub, ...parcel };
    const opened = await openEnrollmentParcel(offer, claimed);
    expect(opened.bundle).toEqual(bundle);
    expect(opened.sas).toBe(prepared.sas);
    expect(opened.sas.split(" ")).toHaveLength(4);
  });

  it("derives the parcel verifier exactly as the enroll capability kind does", async () => {
    const offer = await createEnrollmentOffer(onion, undefined);
    const parsed = parseEnrollmentOffer(offer.qr);
    const prepared = await prepareEnrollmentParcel(parsed);
    expect(prepared.request.parcel_verifier).toBe(await capabilityVerifier("enroll", parsed.claimSecret));
  });

  it("parks no account secret or ciphertext before explicit confirmation", async () => {
    const offer = await createEnrollmentOffer(onion, undefined);
    const prepared = await prepareEnrollmentParcel(parseEnrollmentOffer(offer.qr));
    const parked = JSON.stringify(prepared.request);
    const bundle = sampleBundle();

    expect(Object.keys(prepared.request).sort()).toEqual(["eph_pub", "expires_at", "parcel_verifier"]);
    expect(parked).not.toContain(bundle.rootSecret);
    expect(parked).not.toContain("ciphertext");
  });

  it("fails to open when the ephemeral key does not match (MITM/QR swap)", async () => {
    const realOffer = await createEnrollmentOffer(onion, undefined);
    const attackerOffer = await createEnrollmentOffer(onion, undefined);
    // Trusted device prepares against the attacker's swapped QR, so the security
    // code on the real new device cannot match and approval must stop here.
    const prepared = await prepareEnrollmentParcel(parseEnrollmentOffer(attackerOffer.qr));
    const realSas = await enrollmentSas(realOffer, prepared.ePub);
    expect(realSas).not.toBe(prepared.sas);

    // Even if a user ignores the mismatch and finalizes, the real device cannot decrypt it.
    const parcel = await finalizeEnrollmentParcel(prepared, sampleBundle());
    await expect(openEnrollmentParcel(realOffer, { eph_pub: prepared.ePub, ...parcel })).rejects.toThrow();
  });

  it("rejects a malformed enrollment code", () => {
    expect(() => parseEnrollmentOffer("blackspace://enroll/v1#d=not-base64!!")).toThrow();
    expect(() => parseEnrollmentOffer("https://example.com")).toThrow();
  });
});
