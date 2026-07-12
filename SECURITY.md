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
