CREATE TABLE broker_execution_grant_consumptions (
    grant_id TEXT PRIMARY KEY,
    nonce_digest TEXT NOT NULL UNIQUE CHECK (nonce_digest ~ '^[0-9a-f]{64}$'),
    grant_digest TEXT NOT NULL CHECK (grant_digest ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    collector_spiffe_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    recipe_id TEXT NOT NULL,
    recipe_version TEXT NOT NULL,
    fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
    grant_expires_at TIMESTAMPTZ NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT broker_execution_grant_consumptions_identity CHECK (
        char_length(grant_id) BETWEEN 1 AND 512 AND
        char_length(tenant_id) BETWEEN 1 AND 512 AND
        char_length(task_id) BETWEEN 1 AND 512 AND
        char_length(collector_spiffe_id) BETWEEN 1 AND 512 AND
        char_length(target_id) BETWEEN 1 AND 512 AND
        char_length(recipe_id) BETWEEN 1 AND 512 AND
        char_length(recipe_version) BETWEEN 1 AND 512
    ),
    CONSTRAINT broker_execution_grant_consumptions_validity CHECK (
        requested_at < grant_expires_at AND consumed_at < grant_expires_at
    ),
    CONSTRAINT broker_execution_grant_consumptions_task FOREIGN KEY (tenant_id, task_id)
        REFERENCES broker_collector_tasks (tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX broker_execution_grant_consumptions_task_idx
    ON broker_execution_grant_consumptions (tenant_id, task_id, fencing_token, consumed_at);

CREATE FUNCTION broker_reject_execution_grant_consumption_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'execution grant consumptions are append-only';
END;
$$;

CREATE TRIGGER broker_execution_grant_consumptions_immutable
    BEFORE UPDATE OR DELETE ON broker_execution_grant_consumptions
    FOR EACH ROW EXECUTE FUNCTION broker_reject_execution_grant_consumption_mutation();
