# Security policy

Blackspace v0.1.0 is an unaudited private alpha. It implements real encrypted one-to-one messaging and a standard OpenMLS core, but it has not received an independent security or cryptographic review. Do not use it for high-risk communications.

Report suspected vulnerabilities privately to the repository owner. Do not include real identities, capabilities, onion private keys, recovery kits, plaintext, or production database extracts in a report.

## Current assurance boundaries

- Tor Native fails closed and accepts canonical v3 onion origins only.
- Tor Web depends on the browser and served application code; cross-origin requests reveal the PWA origin to recipient servers.
- HTTPS Web preserves message-content encryption but reveals the source IP and connection metadata to the HTTPS gateway.
- Local encrypted storage does not defend against malware already executing as the user. Browser and SSD storage cannot guarantee physical erasure of old encrypted pages.
- Recovery kits are user-held encrypted exports. Blackspace servers cannot recover a lost identity or passphrase.

No mode protects content after an authorized endpoint is compromised or while the vault is unlocked on a hostile system.

## Linked companion boundary

A linked companion is a revocable mirror, not a second MLS member. The primary remains the only holder of the Ed25519 identity key, administrator capability, OpenMLS state, and contact deposit targets. The companion stores an encrypted projection of contacts and messages, a shared mailbox read capability, an uplink deposit capability, and a per-pairing link secret.

Pairing uses ephemeral P-256 ECDH, an encrypted bundle, and a six-digit short-authentication string. Confirm the same code on both devices. Neither QR contains a reusable secret in plaintext, but an attacker who captures and actively substitutes both codes during the live pairing ceremony remains a residual risk.

The link channel uses direction-separated HKDF keys and AES-256-GCM with persisted monotonic sequence nonces. The link secret has no forward secrecy: anyone who later obtains it and previously recorded link ciphertext can decrypt that traffic. Unlinking rotates the mailbox read capability, revokes both link deposit capabilities, and deletes the primary's copy of the link secret.

A companion necessarily sees mailbox timing, size classes and deposit-capability identifiers. Because the current server read capability also authorizes acknowledgement, a compromised companion can delete queued envelopes even though the honest client only acknowledges downlink envelopes. Treat linked companions as trusted devices and unlink a lost or suspect device immediately.

Sync deposits add two server-visible deposit capabilities and traffic correlated with ordinary messages. Blackspace pads envelopes, limits retained snapshot history, coalesces state into snapshots, and prunes an inactive companion's downlink backlog, but it does not hide that a mailbox is using device linking.

## Multi-device (floating primary) boundary

The floating-primary model lets any enrolled device send and receive on its own, with no device required to stay online. It keeps a single logical OpenMLS client (contacts see no protocol change) by storing the serialized MLS client state as one **shared, client-encrypted, versioned blob** on the mailbox server. Every device downloads the blob, runs its MLS operation, and writes the result back under a compare-and-swap on the version counter, so concurrent devices can never fork the ratchet: a losing write is discarded and retried, and an envelope is deposited or acknowledged only after the state it depends on has committed.

This model deliberately accepts two boundary changes versus the single-device and linked-companion designs, and they must be understood before enabling it:

- **The identity key now lives on every enrolled device.** Previously only one device held the Ed25519 identity key. A stolen, unlocked device is therefore an identity compromise regardless of which device it is. Messaging can be healed after a compromise (rotate capabilities; an MLS self-update commit advances the ratchet with post-compromise security), but the identity key itself cannot be rotated without contacts re-verifying the fingerprint.
- **An encrypted copy of the MLS ratchet now sits on the server.** In the single-device design the ratchet never left the device; a server compromise never yielded ratchet state. Here the server holds the blob. It is encrypted with AES-256-GCM under a key derived (HKDF) from an account root secret that never reaches the server, and only the latest version is retained (older ratchet states are overwritten, so a server that does not deliberately hoard versions cannot reconstruct history). The blob is gated by the administrator capability, never the read capability, so a read-capability holder — including the blunt read-capability rotation used as a panic button — never sees it. The residual risk is a server that both retains blob versions and later obtains the blob key; for the intended self-hosted deployment (an operator protecting against seizure of their own Pi) the encrypted-at-rest blob with a key that never touches the server yields nothing on seizure.

Enrollment is one-scan: a new device shows a single QR carrying only an ephemeral public key and a one-time claim bearer — never a long-term secret. An already-enrolled device seals an enrollment bundle to that ephemeral key and parks it as a one-time, short-lived parcel; the new device claims it once and derives the same short-authentication emoji string, which the operator compares across both screens to defeat a substituted-QR man-in-the-middle. A device photographed from across a room gains only ciphertext it cannot decrypt.

Device revocation is currently coarse: the secure action is rotating the mailbox read capability, which forces every device to re-enroll. Surgical per-device revocation (re-keying the shared secrets and the blob and redistributing them to the surviving devices, plus an MLS self-update commit for post-compromise security) is a planned follow-up; until it lands, treat every enrolled device as fully trusted and re-key all devices if any one is lost.
