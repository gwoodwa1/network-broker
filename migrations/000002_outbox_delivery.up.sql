ALTER TABLE broker_outbox
    ADD COLUMN available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN lease_owner TEXT,
    ADD COLUMN lease_expires_at TIMESTAMPTZ,
    ADD COLUMN dead_lettered_at TIMESTAMPTZ;

DROP INDEX broker_outbox_pending_idx;

CREATE INDEX broker_outbox_claimable_idx
    ON broker_outbox (available_at, sequence)
    WHERE published_at IS NULL AND dead_lettered_at IS NULL;

ALTER TABLE broker_outbox
    ADD CONSTRAINT broker_outbox_lease_pair CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL) OR
        (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    );
