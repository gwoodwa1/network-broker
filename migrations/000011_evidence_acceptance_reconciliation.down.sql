DROP INDEX IF EXISTS broker_evidence_envelopes_reconciliation_idx;
ALTER TABLE broker_evidence_envelopes
    DROP CONSTRAINT IF EXISTS broker_evidence_envelopes_execution_grant_identity,
    DROP COLUMN IF EXISTS execution_grant_id;
