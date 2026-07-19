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

## Full-device enrollment

Full-device enrollment is a staged, one-scan exchange. `POST /v1/enroll/parcels` parks only the trusted device's ephemeral public key and the one-time parcel verifier. A claimant polling `POST /v1/enroll/parcels/claim` receives `pending_confirmation` plus that public key and can derive the same short-authentication string, but no reusable account secret is present yet. After the operator compares both screens and explicitly approves, the trusted device encrypts the padded account bundle and uploads it with `PUT /v1/enroll/parcels/{parcel_id}`. The next claim returns `ready` and atomically consumes the parcel.

## Secure device reset

Protocol v1 full devices share mailbox capabilities and the account-root key, so removing one device safely must sign out all other full devices. `POST /v1/mailbox/devices/secure-reset` is administrator-authenticated and atomically compares the MLS-state version, rotates the read and administrator verifiers, installs a blob encrypted under a fresh client root, revokes all registered devices except `current_device_id`, and optionally revokes linked-companion deposit capabilities. A version conflict changes nothing and the client must re-read, re-encrypt, and retry.
