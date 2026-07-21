# Resolution idempotency contract

Resolution creation scopes an idempotency key to the authenticated tenant and actor. The HTTP adapter validates
and canonicalises the v1 request, then computes its SHA-256 digest; callers do not supply digest authority. The
repository commits the exact canonical request bytes, digest, resolution, idempotency record and creation event
atomically.

## Outcomes

| Condition | Service result | Caller action |
|---|---|---|
| Key has not been used in the tenant-and-actor scope | New resolution with `Created=true` | Store the resolution identifier. |
| Key exists with the same request digest | Existing resolution with `Created=false` | Treat as a successful replay; do not submit another operation. |
| Key exists with a different request digest | `ErrIdempotencyConflict` and code `IDEMPOTENCY_KEY_REUSED` | Do not retry different content with that key. Investigate caller key reuse or intentionally create a new operation with a new key. |

The service never replaces the original digest or redirects an existing key to another resolution. Concurrent
identical submissions converge on one resolution; concurrent submissions with different digests cannot both
succeed under the same scope and key.

## Retry guidance

- After a timeout or lost response, retry the identical canonical request with the same key.
- Retry the same request semantics. Claim and target arrays are sorted by the server, so their input order does
  not change the canonical request digest.
- A conflict is non-retryable with the same key and different content.
- Do not automatically generate a new key after a conflict: that can turn a caller bug into a duplicate operation.
- Query the resolution returned by an identical replay rather than assuming the original attempt failed.

## HTTP mapping

The resolution creation endpoint maps `ErrIdempotencyConflict` to
`409 Conflict` with a stable, secret-safe body:

```json
{
  "error": {
    "code": "IDEMPOTENCY_KEY_REUSED",
    "message": "idempotency key was reused for different request content",
    "retryable": false
  }
}
```

The response must not disclose the original request, original digest, another tenant's data or whether the key
exists outside the authenticated tenant-and-actor scope. Malformed keys and request documents remain validation errors,
not idempotency conflicts. Dead-letter replay has a separate tenant-and-actor-scoped contract documented in
[`dead-letter-operations.md`](dead-letter-operations.md).

See the complete [resolution creation API contract](resolution-create-api.md).
