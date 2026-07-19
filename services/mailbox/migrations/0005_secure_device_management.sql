-- Secure enrollment is a two-stage ceremony. The trusted device first parks only
-- its ephemeral public key so both screens can derive and compare the SAS. The
-- encrypted account bundle is uploaded only after the trusted user confirms it.
ALTER TABLE enrollment_parcels
    ALTER COLUMN nonce DROP NOT NULL,
    ALTER COLUMN size_class DROP NOT NULL,
    ALTER COLUMN ciphertext DROP NOT NULL,
    ADD COLUMN finalized_at timestamptz;

-- A finalized parcel must contain the complete fixed-size encrypted payload, while
-- a pending parcel must contain none of it.
ALTER TABLE enrollment_parcels
    ADD CONSTRAINT enrollment_parcels_stage_check CHECK (
        (finalized_at IS NULL AND nonce IS NULL AND size_class IS NULL AND ciphertext IS NULL)
        OR
        (finalized_at IS NOT NULL AND nonce IS NOT NULL AND size_class IS NOT NULL AND ciphertext IS NOT NULL)
    );
