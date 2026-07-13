CREATE TABLE broker_collector_tasks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    resolution_id TEXT NOT NULL,
    claim_fingerprint TEXT NOT NULL,
    target_snapshot_id TEXT NOT NULL,
    target_snapshot_hash TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_endpoint TEXT,
    recipe_id TEXT NOT NULL,
    recipe_version TEXT NOT NULL,
    trigger_decision_id TEXT NOT NULL,
    planning_decision_id TEXT NOT NULL,
    execution_decision_id TEXT,
    execution_grant_id TEXT,
    approval_grant_id TEXT,
    compatibility_hash TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    lease_owner TEXT,
    lease_expiry TIMESTAMPTZ,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    accepted_attempt_id TEXT,
    accepted_evidence_id TEXT,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT broker_collector_tasks_state CHECK (state IN (
        'queued', 'leased', 'executing', 'committing', 'succeeded', 'retry_wait',
        'failed', 'denied', 'cancelled', 'expired', 'dead_letter'
    )),
    CONSTRAINT broker_collector_tasks_attempt_count CHECK (attempt_count >= 0),
    CONSTRAINT broker_collector_tasks_fencing_token CHECK (fencing_token >= 0),
    CONSTRAINT broker_collector_tasks_required_identity CHECK (
        char_length(id) BETWEEN 1 AND 512 AND
        char_length(tenant_id) BETWEEN 1 AND 512 AND
        char_length(resolution_id) BETWEEN 1 AND 512 AND
        char_length(claim_fingerprint) BETWEEN 1 AND 512 AND
        char_length(target_snapshot_id) BETWEEN 1 AND 512 AND
        char_length(target_snapshot_hash) BETWEEN 1 AND 512 AND
        char_length(target_id) BETWEEN 1 AND 512 AND
        char_length(recipe_id) BETWEEN 1 AND 512 AND
        char_length(recipe_version) BETWEEN 1 AND 512 AND
        char_length(trigger_decision_id) BETWEEN 1 AND 512 AND
        char_length(planning_decision_id) BETWEEN 1 AND 512 AND
        char_length(compatibility_hash) BETWEEN 1 AND 512
    ),
    CONSTRAINT broker_collector_tasks_optional_identity CHECK (
        (target_endpoint IS NULL OR char_length(target_endpoint) BETWEEN 1 AND 2048) AND
        (execution_decision_id IS NULL OR char_length(execution_decision_id) BETWEEN 1 AND 512) AND
        (execution_grant_id IS NULL OR char_length(execution_grant_id) BETWEEN 1 AND 512) AND
        (approval_grant_id IS NULL OR char_length(approval_grant_id) BETWEEN 1 AND 512) AND
        (lease_owner IS NULL OR char_length(lease_owner) BETWEEN 1 AND 512) AND
        (accepted_attempt_id IS NULL OR char_length(accepted_attempt_id) BETWEEN 1 AND 512) AND
        (accepted_evidence_id IS NULL OR char_length(accepted_evidence_id) BETWEEN 1 AND 512)
    ),
    CONSTRAINT broker_collector_tasks_authority_pair CHECK (
        (execution_decision_id IS NULL) = (execution_grant_id IS NULL)
    ),
    CONSTRAINT broker_collector_tasks_accepted_pair CHECK (
        (accepted_attempt_id IS NULL) = (accepted_evidence_id IS NULL)
    ),
    CONSTRAINT broker_collector_tasks_succeeded_result CHECK (
        (state = 'succeeded') = (accepted_attempt_id IS NOT NULL)
    ),
    CONSTRAINT broker_collector_tasks_active_lease CHECK (
        state NOT IN ('leased', 'executing', 'committing') OR
        (lease_owner IS NOT NULL AND lease_expiry IS NOT NULL AND fencing_token > 0)
    ),
    CONSTRAINT broker_collector_tasks_available_lease CHECK (
        state NOT IN ('queued', 'retry_wait') OR
        (lease_owner IS NULL AND lease_expiry IS NULL)
    ),
    CONSTRAINT broker_collector_tasks_last_error CHECK (
        last_error IS NULL OR char_length(last_error) BETWEEN 1 AND 2048
    ),
    CONSTRAINT broker_collector_tasks_time_order CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX broker_collector_tasks_accepted_attempt_idx
    ON broker_collector_tasks (accepted_attempt_id)
    WHERE accepted_attempt_id IS NOT NULL;

CREATE UNIQUE INDEX broker_collector_tasks_accepted_evidence_idx
    ON broker_collector_tasks (accepted_evidence_id)
    WHERE accepted_evidence_id IS NOT NULL;

CREATE INDEX broker_collector_tasks_available_idx
    ON broker_collector_tasks (state, lease_expiry, tenant_id, id)
    WHERE state IN ('queued', 'retry_wait', 'leased', 'executing', 'committing');

CREATE INDEX broker_collector_tasks_resolution_idx
    ON broker_collector_tasks (tenant_id, resolution_id, id);
