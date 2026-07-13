DROP TRIGGER IF EXISTS broker_artefacts_immutable ON broker_artefacts;
DROP FUNCTION IF EXISTS broker_reject_artefact_mutation();
DROP INDEX IF EXISTS broker_artefacts_object_key_idx;
DROP INDEX IF EXISTS broker_artefacts_tenant_created_idx;
DROP TABLE IF EXISTS broker_artefacts;
