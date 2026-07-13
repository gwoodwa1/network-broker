CREATE TABLE broker_artefacts (
    artefact_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    class TEXT NOT NULL,
    uri TEXT NOT NULL UNIQUE,
    object_key TEXT NOT NULL,
    sha256_digest TEXT NOT NULL,
    byte_count BIGINT NOT NULL,
    media_type TEXT NOT NULL,
    transport TEXT,
    attempt_id TEXT,
    encryption_key_ref TEXT,
    parent_artefact_id TEXT,
    parent_digest TEXT,
    transformation_manifest JSONB,
    manifest_digest TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT broker_artefacts_tenant_id UNIQUE (tenant_id, artefact_id),
    CONSTRAINT broker_artefacts_class CHECK (class IN ('captured', 'sanitised')),
    CONSTRAINT broker_artefacts_digest CHECK (sha256_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT broker_artefacts_byte_count CHECK (byte_count BETWEEN 1 AND 16777216),
    CONSTRAINT broker_artefacts_uri CHECK (uri = 'artefact://' || artefact_id),
    CONSTRAINT broker_artefacts_class_metadata CHECK (
        (class = 'captured' AND transport IS NOT NULL AND attempt_id IS NOT NULL
            AND encryption_key_ref IS NOT NULL AND parent_artefact_id IS NULL
            AND parent_digest IS NULL AND transformation_manifest IS NULL AND manifest_digest IS NULL)
        OR
        (class = 'sanitised' AND transport IS NULL AND attempt_id IS NULL
            AND encryption_key_ref IS NULL AND parent_artefact_id IS NOT NULL
            AND parent_digest ~ '^[0-9a-f]{64}$' AND transformation_manifest IS NOT NULL
            AND manifest_digest ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT broker_artefacts_parent FOREIGN KEY (tenant_id, parent_artefact_id)
        REFERENCES broker_artefacts (tenant_id, artefact_id) ON DELETE RESTRICT
);

CREATE INDEX broker_artefacts_tenant_created_idx
    ON broker_artefacts (tenant_id, created_at DESC, artefact_id);

CREATE INDEX broker_artefacts_object_key_idx
    ON broker_artefacts (object_key);

CREATE FUNCTION broker_reject_artefact_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'artefact metadata records are immutable';
END;
$$;

CREATE TRIGGER broker_artefacts_immutable
    BEFORE UPDATE OR DELETE ON broker_artefacts
    FOR EACH ROW EXECUTE FUNCTION broker_reject_artefact_mutation();
