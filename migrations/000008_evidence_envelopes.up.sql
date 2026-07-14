ALTER TABLE broker_collector_tasks
    ADD CONSTRAINT broker_collector_tasks_tenant_task UNIQUE (tenant_id, id);

CREATE TABLE broker_evidence_envelopes (
    evidence_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    accepted_attempt_id TEXT NOT NULL,
    fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
    target_id TEXT NOT NULL,
    recipe_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    document BYTEA NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 16777216),
    document_digest TEXT NOT NULL CHECK (document_digest ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT broker_evidence_envelopes_identity CHECK (
        char_length(evidence_id) BETWEEN 1 AND 512 AND
        char_length(tenant_id) BETWEEN 1 AND 512 AND
        char_length(task_id) BETWEEN 1 AND 512 AND
        char_length(accepted_attempt_id) BETWEEN 1 AND 512 AND
        char_length(target_id) BETWEEN 1 AND 512 AND
        char_length(recipe_id) BETWEEN 1 AND 512
    ),
    CONSTRAINT broker_evidence_envelopes_validity CHECK (valid_until > observed_at),
    CONSTRAINT broker_evidence_envelopes_task FOREIGN KEY (tenant_id, task_id)
        REFERENCES broker_collector_tasks (tenant_id, id) ON DELETE RESTRICT,
    UNIQUE (tenant_id, evidence_id),
    UNIQUE (tenant_id, task_id, evidence_id),
    UNIQUE (tenant_id, task_id, accepted_attempt_id)
);

CREATE INDEX broker_evidence_envelopes_tenant_target_time_idx
    ON broker_evidence_envelopes (tenant_id, target_id, observed_at DESC, evidence_id);

ALTER TABLE broker_collector_tasks
    ADD CONSTRAINT broker_collector_tasks_accepted_evidence
    FOREIGN KEY (tenant_id, id, accepted_evidence_id)
    REFERENCES broker_evidence_envelopes (tenant_id, task_id, evidence_id)
    ON DELETE RESTRICT NOT VALID;

CREATE FUNCTION broker_reject_evidence_envelope_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'evidence envelopes are immutable';
END;
$$;

CREATE TRIGGER broker_evidence_envelopes_immutable
    BEFORE UPDATE OR DELETE ON broker_evidence_envelopes
    FOR EACH ROW EXECUTE FUNCTION broker_reject_evidence_envelope_mutation();
