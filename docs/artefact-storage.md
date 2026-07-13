# Durable artefact storage

The durable artefact path separates immutable lineage metadata from immutable bytes:

- PostgreSQL stores tenant ownership, class, digest, media type, capture attribution, encryption-key reference, transformation manifest and parent lineage.
- S3-compatible storage holds bounded content-addressed objects.
- Evidence envelopes retain immutable artefact references and never embed captured bytes.

`artefacts.PipelineStore` is the evidence-pipeline boundary. The existing memory store implements it for local workflows. Production deployments can compose `PostgresRepository`, `S3BlobStore` and `DurableStore` without changing evidence assembly.

## Identity and object layout

Each lineage record receives a stable identifier derived from its tenant, class, attempt or parent identity, digest and transformation manifest. Its URI has this form:

```text
artefact://artefact-<stable-id>
```

The object key is separately content-addressed:

```text
tenants/<base64url-tenant>/<captured|sanitised>/sha256/<digest-prefix>/<sha256-digest>
```

Encoding the tenant prevents path injection and makes the isolation boundary explicit. Captured and sanitised bytes use different key namespaces. Multiple lineage records may safely reference the same immutable content object.

## Write semantics

Writes are limited to 16 MiB and follow this sequence:

1. Validate tenant, media type, class-specific metadata and byte bounds.
2. Compute SHA-256 locally and derive the tenant-scoped object key.
3. Upload with `If-None-Match: *` and record the digest as object metadata.
4. If the key already exists, accept it only when its recorded size and digest match.
5. Insert the immutable PostgreSQL metadata record.
6. On an idempotent retry, require every metadata field to match the existing record.

S3-compatible providers must support conditional `PutObject`. Configure the SDK client with TLS verification, bounded retries, workload credentials and a private endpoint. `S3BlobOptions.SSEKMSKeyID` can request SSE-KMS; otherwise the deployment must enforce encryption through bucket policy and default bucket encryption. Public buckets and ACL-based access are not supported deployment patterns.

Object upload and PostgreSQL insertion cannot share one atomic transaction. A failed metadata insertion can therefore leave an unreachable content-addressed object. Lifecycle reconciliation should remove objects that have no metadata reference after a conservative safety interval; it must never overwrite or mutate a referenced object.

## Read semantics

Retrieval first loads metadata using both tenant and artefact URI. Cross-tenant and missing records are therefore indistinguishable. The object body is bounded to the maximum artefact size, its exact byte count is checked, and SHA-256 is recomputed. A mismatch returns an integrity failure and no trusted payload.

Captured-to-sanitised lineage is enforced in both application code and the database. A sanitised record must reference a captured record belonging to the same tenant and must carry a manifest whose original and output sizes match the parent and derivative objects.

## Immutability and operations

Migration `000004_artefact_metadata` rejects `UPDATE` and `DELETE` for artefact metadata. Retention, legal hold and deletion workflows should therefore be represented by separate lifecycle records in a later migration rather than mutating evidence history.

Operational monitoring should alert on conditional-write conflicts, integrity failures, orphan reconciliation, storage latency, KMS failures and lifecycle-policy drift. Object keys, payloads and transformation contents must not be used as metric labels or written to ordinary logs.
