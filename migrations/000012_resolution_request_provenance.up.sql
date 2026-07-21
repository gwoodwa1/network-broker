ALTER TABLE broker_resolutions
    ADD COLUMN request_document BYTEA;

ALTER TABLE broker_resolutions
    ADD CONSTRAINT broker_resolutions_request_document_size
    CHECK (request_document IS NULL OR octet_length(request_document) <= 65536);

COMMENT ON COLUMN broker_resolutions.request_document IS
    'Exact canonical server-validated v1 JSON bytes; NULL only for workflows created before migration 000012.';
