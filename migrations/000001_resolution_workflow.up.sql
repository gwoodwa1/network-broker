CREATE TABLE broker_resolutions (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'received', 'resolving_targets', 'planning', 'queued', 'complete',
        'partial', 'denied', 'failed', 'cancelled', 'expired'
    )),
    target_count INTEGER NOT NULL DEFAULT 0 CHECK (target_count >= 0),
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT NOT NULL CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (char_length(idempotency_key) <= 128),
    CHECK (char_length(request_digest) <= 128),
    CHECK (updated_at >= created_at)
);

CREATE INDEX broker_resolutions_tenant_state_idx
    ON broker_resolutions (tenant_id, state, updated_at);

CREATE TABLE broker_resolution_idempotency (
    tenant_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    resolution_id TEXT NOT NULL REFERENCES broker_resolutions(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, actor_id, idempotency_key),
    CHECK (char_length(idempotency_key) <= 128),
    CHECK (char_length(request_digest) <= 128)
);

CREATE TABLE broker_outbox (
    sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT
);

CREATE INDEX broker_outbox_pending_idx
    ON broker_outbox (sequence)
    WHERE published_at IS NULL;
