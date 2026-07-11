CREATE TABLE mailboxes (
    id uuid PRIMARY KEY,
    read_capability_verifier bytea NOT NULL UNIQUE CHECK (octet_length(read_capability_verifier) = 32),
    admin_capability_verifier bytea NOT NULL UNIQUE CHECK (octet_length(admin_capability_verifier) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

CREATE TABLE deposit_capabilities (
    id uuid PRIMARY KEY,
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    verifier bytea NOT NULL UNIQUE CHECK (octet_length(verifier) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    revoked_at timestamptz
);

CREATE INDEX deposit_capabilities_mailbox_idx ON deposit_capabilities(mailbox_id);

CREATE TABLE envelopes (
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    envelope_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    expires_at timestamptz NOT NULL,
    size_class integer NOT NULL CHECK (size_class IN (1024, 4096, 16384, 65536, 262144)),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) = size_class),
    acknowledgement_token text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (mailbox_id, envelope_id)
);

CREATE INDEX envelopes_pull_idx ON envelopes(mailbox_id, created_at);
CREATE INDEX envelopes_expiry_idx ON envelopes(expires_at);

