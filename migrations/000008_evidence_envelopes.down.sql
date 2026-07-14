ALTER TABLE broker_collector_tasks
    DROP CONSTRAINT IF EXISTS broker_collector_tasks_accepted_evidence;
DROP TRIGGER IF EXISTS broker_evidence_envelopes_immutable ON broker_evidence_envelopes;
DROP FUNCTION IF EXISTS broker_reject_evidence_envelope_mutation();
DROP INDEX IF EXISTS broker_evidence_envelopes_tenant_target_time_idx;
DROP TABLE IF EXISTS broker_evidence_envelopes;
ALTER TABLE broker_collector_tasks
    DROP CONSTRAINT IF EXISTS broker_collector_tasks_tenant_task;
