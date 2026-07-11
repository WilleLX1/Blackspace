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
