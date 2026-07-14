CREATE TABLE broker_disclosure_decisions (
    decision_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    document BYTEA NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 1048576),
    document_digest TEXT NOT NULL CHECK (document_digest ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT broker_disclosure_decisions_evidence FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES broker_evidence_envelopes (tenant_id, evidence_id) ON DELETE RESTRICT,
    CONSTRAINT broker_disclosure_decisions_identity CHECK (
        char_length(decision_id) BETWEEN 1 AND 512 AND
        char_length(tenant_id) BETWEEN 1 AND 512 AND
        char_length(actor_id) BETWEEN 1 AND 512 AND
        char_length(evidence_id) BETWEEN 1 AND 512
    ),
    CONSTRAINT broker_disclosure_decisions_validity CHECK (expires_at > evaluated_at),
    UNIQUE (tenant_id, decision_id, evidence_id, actor_id)
);

CREATE INDEX broker_disclosure_decisions_lookup_idx
    ON broker_disclosure_decisions (tenant_id, actor_id, evidence_id, expires_at DESC);

CREATE TABLE broker_disclosure_receipts (
    receipt_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    disclosure_decision_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    delivered_payload_digest TEXT NOT NULL CHECK (delivered_payload_digest ~ '^[0-9a-f]{64}$'),
    delivered_at TIMESTAMPTZ NOT NULL,
    schema_version TEXT NOT NULL CHECK (schema_version IN (
        'network-broker-disclosure-receipt/v1',
        'network-broker-disclosure-receipt/v2',
        'network-broker-disclosure-receipt/v3'
    )),
    document BYTEA NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 1048576),
    document_digest TEXT NOT NULL CHECK (document_digest ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT broker_disclosure_receipts_decision FOREIGN KEY (
        tenant_id, disclosure_decision_id, evidence_id, actor_id
    ) REFERENCES broker_disclosure_decisions (
        tenant_id, decision_id, evidence_id, actor_id
    ) ON DELETE RESTRICT,
    CONSTRAINT broker_disclosure_receipts_identity CHECK (
        char_length(receipt_id) BETWEEN 1 AND 512 AND
        char_length(tenant_id) BETWEEN 1 AND 512 AND
        char_length(evidence_id) BETWEEN 1 AND 512 AND
        char_length(actor_id) BETWEEN 1 AND 512 AND
        char_length(disclosure_decision_id) BETWEEN 1 AND 512 AND
        char_length(request_id) BETWEEN 1 AND 512
    ),
    UNIQUE (tenant_id, actor_id, request_id)
);

CREATE INDEX broker_disclosure_receipts_evidence_time_idx
    ON broker_disclosure_receipts (tenant_id, evidence_id, delivered_at DESC, receipt_id);

CREATE FUNCTION broker_reject_disclosure_record_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'disclosure decisions and receipts are append-only';
END;
$$;

CREATE TRIGGER broker_disclosure_decisions_immutable
    BEFORE UPDATE OR DELETE ON broker_disclosure_decisions
    FOR EACH ROW EXECUTE FUNCTION broker_reject_disclosure_record_mutation();
CREATE TRIGGER broker_disclosure_receipts_immutable
    BEFORE UPDATE OR DELETE ON broker_disclosure_receipts
    FOR EACH ROW EXECUTE FUNCTION broker_reject_disclosure_record_mutation();
