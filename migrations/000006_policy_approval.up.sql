CREATE TABLE broker_policy_bundles (
    bundle_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    scope TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    document JSONB NOT NULL,
    document_digest TEXT NOT NULL CHECK (char_length(document_digest) = 64),
    signing_key_ref TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    signature BYTEA NOT NULL CHECK (octet_length(signature) > 0),
    stored_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (bundle_id, version)
);

CREATE TABLE broker_policy_activations (
    scope TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_by TEXT NOT NULL,
    CONSTRAINT broker_policy_activation_bundle FOREIGN KEY (bundle_id, version)
        REFERENCES broker_policy_bundles (bundle_id, version) ON DELETE RESTRICT
);

CREATE TABLE broker_policy_activation_events (
    sequence BIGSERIAL PRIMARY KEY,
    scope TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    actor_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT broker_policy_activation_event_bundle FOREIGN KEY (bundle_id, version)
        REFERENCES broker_policy_bundles (bundle_id, version) ON DELETE RESTRICT
);

CREATE TABLE broker_policy_decisions (
    decision_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('trigger', 'candidate', 'execution', 'disclosure')),
    scope TEXT NOT NULL,
    recipe_id TEXT NOT NULL,
    target_class TEXT NOT NULL,
    input_digest TEXT NOT NULL CHECK (char_length(input_digest) = 64),
    bundle_id TEXT NOT NULL,
    bundle_version BIGINT NOT NULL,
    bundle_digest TEXT NOT NULL CHECK (char_length(bundle_digest) = 64),
    allow BOOLEAN NOT NULL,
    requires_approval BOOLEAN NOT NULL,
    denials JSONB NOT NULL,
    obligations JSONB NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT broker_policy_decision_bundle FOREIGN KEY (bundle_id, bundle_version)
        REFERENCES broker_policy_bundles (bundle_id, version) ON DELETE RESTRICT
);

CREATE INDEX broker_policy_decisions_tenant_time_idx
    ON broker_policy_decisions (tenant_id, evaluated_at DESC, decision_id);

CREATE TABLE broker_approval_grants (
    grant_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    recipe_id TEXT NOT NULL,
    target_subset_hash TEXT NOT NULL,
    max_uses INTEGER NOT NULL CHECK (max_uses > 0),
    used INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0 AND used <= max_uses),
    expires_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    policy_decision_id TEXT NOT NULL REFERENCES broker_policy_decisions (decision_id) ON DELETE RESTRICT,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE broker_approval_consumptions (
    consumption_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES broker_approval_grants (grant_id) ON DELETE RESTRICT,
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    grant_version BIGINT NOT NULL CHECK (grant_version > 1),
    UNIQUE (grant_id, task_id)
);

CREATE FUNCTION broker_reject_governance_history_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'governance history is append-only';
END;
$$;

CREATE TRIGGER broker_policy_bundles_immutable
    BEFORE UPDATE OR DELETE ON broker_policy_bundles
    FOR EACH ROW EXECUTE FUNCTION broker_reject_governance_history_mutation();
CREATE TRIGGER broker_policy_activation_events_append_only
    BEFORE UPDATE OR DELETE ON broker_policy_activation_events
    FOR EACH ROW EXECUTE FUNCTION broker_reject_governance_history_mutation();
CREATE TRIGGER broker_policy_decisions_append_only
    BEFORE UPDATE OR DELETE ON broker_policy_decisions
    FOR EACH ROW EXECUTE FUNCTION broker_reject_governance_history_mutation();
CREATE TRIGGER broker_approval_consumptions_append_only
    BEFORE UPDATE OR DELETE ON broker_approval_consumptions
    FOR EACH ROW EXECUTE FUNCTION broker_reject_governance_history_mutation();
