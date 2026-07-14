ALTER TABLE broker_evidence_envelopes
    ADD COLUMN execution_grant_id TEXT;

UPDATE broker_evidence_envelopes
SET execution_grant_id = convert_from(document, 'UTF8')::jsonb ->> 'ExecutionGrantID';

ALTER TABLE broker_evidence_envelopes
    ALTER COLUMN execution_grant_id SET NOT NULL,
    ADD CONSTRAINT broker_evidence_envelopes_execution_grant_identity CHECK (
        char_length(execution_grant_id) BETWEEN 1 AND 512
    );

CREATE INDEX broker_evidence_envelopes_reconciliation_idx
    ON broker_evidence_envelopes (
        tenant_id, task_id, fencing_token, execution_grant_id, recorded_at, evidence_id
    );
