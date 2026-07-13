-- Floating-primary multi-device: a shared, client-encrypted MLS-state blob with a
-- compare-and-swap version, one-time enrollment parcels, and a device registry.

-- One row per mailbox. `version` is the CAS counter; only the latest state is kept
-- (older ratchet states are overwritten to limit at-rest forward-secrecy exposure).
CREATE TABLE mls_state_blobs (
    mailbox_id uuid PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
    version bigint NOT NULL CHECK (version > 0),
    size_class integer NOT NULL CHECK (size_class IN (4096, 16384, 65536, 262144, 1048576, 3145728)),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) = size_class),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- One-time parcels an enrolled device parks for a new device. The ciphertext is
-- sealed to the new device's ephemeral public key; the server stores opaque bytes.
CREATE TABLE enrollment_parcels (
    id uuid PRIMARY KEY,
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    verifier bytea NOT NULL UNIQUE CHECK (octet_length(verifier) = 32),
    eph_pub text NOT NULL,
    nonce text NOT NULL,
    size_class integer NOT NULL CHECK (size_class IN (1024, 4096, 16384, 65536, 262144)),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) = size_class),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    claimed_at timestamptz
);

CREATE INDEX enrollment_parcels_expiry_idx ON enrollment_parcels(expires_at);

-- Registry of enrolled devices, for listing and (future surgical) revocation.
CREATE TABLE mailbox_devices (
    id uuid PRIMARY KEY,
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    label text NOT NULL CHECK (octet_length(label) <= 128),
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE INDEX mailbox_devices_mailbox_idx ON mailbox_devices(mailbox_id);
