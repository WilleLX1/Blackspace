CREATE TABLE registration_invitations (
    id uuid PRIMARY KEY,
    verifier bytea NOT NULL UNIQUE CHECK (octet_length(verifier) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz
);

CREATE INDEX registration_invitations_available_idx
    ON registration_invitations(expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

ALTER TABLE mailboxes
    ADD COLUMN identity_public_key text,
    ADD COLUMN recovered_at timestamptz;

CREATE UNIQUE INDEX mailboxes_identity_public_key_idx
    ON mailboxes(identity_public_key)
    WHERE identity_public_key IS NOT NULL;

CREATE TABLE key_packages (
    package_id uuid PRIMARY KEY,
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    protocol_version smallint NOT NULL CHECK (protocol_version = 1),
    ciphersuite text NOT NULL,
    identity_public_key text NOT NULL,
    key_package bytea NOT NULL CHECK (octet_length(key_package) BETWEEN 32 AND 65536),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    claimed_at timestamptz
);

CREATE INDEX key_packages_available_idx
    ON key_packages(mailbox_id, created_at)
    WHERE claimed_at IS NULL;

CREATE TABLE mailbox_recoveries (
    id uuid PRIMARY KEY,
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    recovered_at timestamptz NOT NULL DEFAULT now(),
    purged_envelopes bigint NOT NULL,
    revoked_deposit_capabilities bigint NOT NULL
);

ALTER TABLE envelopes
    ADD COLUMN deposit_capability_id uuid REFERENCES deposit_capabilities(id) ON DELETE SET NULL;
