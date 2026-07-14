DROP TRIGGER IF EXISTS broker_execution_grant_consumptions_immutable
    ON broker_execution_grant_consumptions;
DROP FUNCTION IF EXISTS broker_reject_execution_grant_consumption_mutation();
DROP INDEX IF EXISTS broker_execution_grant_consumptions_task_idx;
DROP TABLE IF EXISTS broker_execution_grant_consumptions;
