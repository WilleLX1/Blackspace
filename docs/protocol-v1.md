# Blackspace protocol v1 private alpha

The mailbox is an untrusted queue. It stores capability verifiers, public signed key packages, opaque fixed-size envelopes, expiry, and acknowledgement tokens. Identity private keys, contact names, plaintext, and raw mailbox capabilities remain client-side.

## Registration

Operators mint a single-use registration URI with `blackspace-mailbox invite create`. The URI secret is in its fragment. `POST /v1/mailboxes` consumes it using `Authorization: BlackspaceRegistration <token>` and atomically stores the client-generated mailbox verifiers, public identity key, initial deposit verifier, and signed key-package pool.

## Contact invitation

```text
blackspace://contact/v1?onion=<encoded-origin>&https=<optional-origin>#cap=<deposit-capability>&identity=<public-key>&invite=<uuid>
```

The onion origin is mandatory. HTTPS is optional. Tor Native and Tor Web use onion directly; HTTPS Web requires the advertised HTTPS origin. The deposit capability is write-only and never appears in an HTTP path.

## Key packages and conversations

`POST /v1/deposit/key-packages/claim` atomically claims one unexpired signed package using `BlackspaceDeposit`. Clients verify the package identity and signature against the invitation before creating a two-member secure session. Pools target 20 packages, replenish below 5, and expire after 30 days.

Application records are versioned, validated CBOR values protected as OpenMLS application messages. Supported private-alpha records are text, profile/reply target, delivery receipt, and recovery session reset. Display names and message identifiers never appear in the outer envelope.

## Delivery

`POST /v1/deposit/envelopes` uses `BlackspaceDeposit` and `application/blackspace-envelope+json`. Envelopes use exact 1, 4, 16, 64, or 256 KiB classes. Pull and acknowledgement use `BlackspaceRead`; capability administration, key-package publication, and recovery use `BlackspaceAdmin`.

Only server information, key-package claim, and deposit permit credentialless browser CORS. Read, acknowledgement, registration, administration, and recovery are same-origin. Errors remain static and non-enumerating.

## Recovery

Recovery kits are encrypted client exports, not server backups. Mailbox takeover rotates read/admin/deposit capabilities, revokes old deposit capabilities, purges queued envelopes and key packages, and installs fresh packages. Clients reset secure sessions rather than resuming stale sending state.
