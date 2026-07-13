ALTER TABLE broker_outbox DROP CONSTRAINT IF EXISTS broker_outbox_lease_pair;
DROP INDEX IF EXISTS broker_outbox_claimable_idx;

ALTER TABLE broker_outbox
    DROP COLUMN IF EXISTS dead_lettered_at,
    DROP COLUMN IF EXISTS lease_expires_at,
    DROP COLUMN IF EXISTS lease_owner,
    DROP COLUMN IF EXISTS available_at;

CREATE INDEX broker_outbox_pending_idx
    ON broker_outbox (sequence)
    WHERE published_at IS NULL;
