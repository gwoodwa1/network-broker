CREATE TABLE broker_dead_letter_actions (
    action_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    outbox_sequence BIGINT NOT NULL REFERENCES broker_outbox(sequence) ON DELETE RESTRICT,
    event_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    spiffe_id TEXT NOT NULL,
    identity_revision TEXT NOT NULL,
    action TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    prior_dead_lettered_at TIMESTAMPTZ NOT NULL,
    attempts_at_action INTEGER NOT NULL,
    last_error_at_action TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    available_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT broker_dead_letter_action_replay CHECK (action = 'replay'),
    CONSTRAINT broker_dead_letter_action_attempts_nonnegative CHECK (attempts_at_action >= 0),
    CONSTRAINT broker_dead_letter_action_reason_length CHECK (char_length(reason) BETWEEN 1 AND 512),
    CONSTRAINT broker_dead_letter_action_idempotency_length CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    UNIQUE (tenant_id, actor_id, idempotency_key)
);

CREATE INDEX broker_outbox_dead_letter_tenant_idx
    ON broker_outbox (tenant_id, sequence DESC)
    WHERE dead_lettered_at IS NOT NULL AND published_at IS NULL;

CREATE INDEX broker_dead_letter_action_event_idx
    ON broker_dead_letter_actions (tenant_id, outbox_sequence, requested_at);

CREATE FUNCTION broker_reject_dead_letter_action_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'dead-letter action records are append-only';
END;
$$;

CREATE TRIGGER broker_dead_letter_actions_append_only
    BEFORE UPDATE OR DELETE ON broker_dead_letter_actions
    FOR EACH ROW EXECUTE FUNCTION broker_reject_dead_letter_action_mutation();
