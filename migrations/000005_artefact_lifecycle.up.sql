CREATE TABLE broker_artefact_lifecycle (
    tenant_id TEXT NOT NULL,
    artefact_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    retain_until TIMESTAMPTZ,
    legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, artefact_id),
    CONSTRAINT broker_artefact_lifecycle_artefact FOREIGN KEY (tenant_id, artefact_id)
        REFERENCES broker_artefacts (tenant_id, artefact_id) ON DELETE RESTRICT,
    CONSTRAINT broker_artefact_lifecycle_state CHECK (state IN ('active', 'pending_deletion', 'deleted')),
    CONSTRAINT broker_artefact_lifecycle_version CHECK (version > 0),
    CONSTRAINT broker_artefact_lifecycle_deleted_hold CHECK (state <> 'deleted' OR legal_hold = FALSE)
);

CREATE TABLE broker_artefact_lifecycle_events (
    event_sequence BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    artefact_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    action TEXT NOT NULL,
    previous_state TEXT,
    next_state TEXT NOT NULL,
    previous_retain_until TIMESTAMPTZ,
    next_retain_until TIMESTAMPTZ,
    previous_legal_hold BOOLEAN,
    next_legal_hold BOOLEAN NOT NULL,
    actor_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT broker_artefact_lifecycle_event_parent FOREIGN KEY (tenant_id, artefact_id)
        REFERENCES broker_artefacts (tenant_id, artefact_id) ON DELETE RESTRICT,
    CONSTRAINT broker_artefact_lifecycle_event_version CHECK (version > 0),
    CONSTRAINT broker_artefact_lifecycle_event_action CHECK (
        action IN ('created', 'retain', 'place_hold', 'release_hold', 'request_deletion', 'confirm_deletion')
    ),
    CONSTRAINT broker_artefact_lifecycle_event_reason CHECK (char_length(reason) BETWEEN 1 AND 512),
    UNIQUE (tenant_id, artefact_id, version)
);

CREATE INDEX broker_artefact_lifecycle_reconciliation_idx
    ON broker_artefact_lifecycle (state, updated_at, tenant_id, artefact_id);

CREATE FUNCTION broker_reject_artefact_lifecycle_event_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'artefact lifecycle events are append-only';
END;
$$;

CREATE TRIGGER broker_artefact_lifecycle_events_append_only
    BEFORE UPDATE OR DELETE ON broker_artefact_lifecycle_events
    FOR EACH ROW EXECUTE FUNCTION broker_reject_artefact_lifecycle_event_mutation();

INSERT INTO broker_artefact_lifecycle (tenant_id, artefact_id)
SELECT tenant_id, artefact_id FROM broker_artefacts
ON CONFLICT DO NOTHING;

INSERT INTO broker_artefact_lifecycle_events (
    tenant_id, artefact_id, version, action, previous_state, next_state,
    previous_legal_hold, next_legal_hold, actor_id, reason
)
SELECT tenant_id, artefact_id, 1, 'created', NULL, 'active', NULL, FALSE,
       'system:migration', 'initial lifecycle state'
FROM broker_artefacts
ON CONFLICT DO NOTHING;
