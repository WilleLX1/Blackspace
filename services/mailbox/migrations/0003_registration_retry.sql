ALTER TABLE registration_invitations
    ADD COLUMN mailbox_id uuid REFERENCES mailboxes(id) ON DELETE SET NULL,
    ADD COLUMN initial_deposit_capability_id uuid REFERENCES deposit_capabilities(id) ON DELETE SET NULL;

