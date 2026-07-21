ALTER TABLE broker_resolutions
    DROP CONSTRAINT IF EXISTS broker_resolutions_request_document_size,
    DROP COLUMN IF EXISTS request_document;
