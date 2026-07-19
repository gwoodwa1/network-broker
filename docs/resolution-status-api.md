# Resolution status API

The control plane exposes a first network-facing, read-only workflow endpoint:

```text
GET /v1/resolutions/{resolution_id}
```

This endpoint reports durable resolution status without triggering collection
or disclosing evidence. It is a bounded increment toward the complete public
resolution, watch, QueryContext and retrieval APIs; it does not claim those
remaining surfaces are implemented.

## Authentication and authority

The route is registered only when the control plane has its complete mTLS
server and client trust configuration. TLS must have verified the peer chain.
The application then requires exactly one SPIFFE URI SAN matching:

```text
spiffe://<trust-domain>/tenant/<tenant>/role/agent/workload/<name>
```

The `agent` role receives only the `resolutions:read` scope for this surface.
The tenant is derived from the verified identity and is never accepted from a
header, query parameter, URL segment or request body. Repository lookup always
uses both that tenant and the requested resolution ID.

The current control-plane listener uses `SERVER_TLS_CERT_FILE`,
`SERVER_TLS_KEY_FILE`, `OPERATOR_CLIENT_CA_FILE` and
`OPERATOR_SPIFFE_TRUST_DOMAIN` to enable authenticated routes. The CA may issue
different workload roles, but each route independently accepts only its exact
role and scope. A future split gateway may use separate listeners and trust
bundles; it must preserve the same server-derived tenant rule.

## Successful response

```json
{
  "schema_version": "v1",
  "resolution_id": "res_0123456789abcdef",
  "state": "queued",
  "target_count": 3,
  "completed": false,
  "version": 4,
  "created_at": "2026-07-19T09:00:00Z",
  "updated_at": "2026-07-19T09:00:02Z"
}
```

Responses are marked `Cache-Control: no-store`. The representation deliberately
omits tenant ID, originating actor, idempotency key and request digest. Evidence
and disclosed fields remain behind the independent retrieval/disclosure
boundary.

## Errors

Errors have one version-independent JSON shape:

```json
{"code":"RESOLUTION_NOT_FOUND"}
```

| HTTP status | Code | Meaning |
|---|---|---|
| 400 | `INVALID_RESOLUTION_ID` | The identifier is empty, oversized or contains forbidden separators, whitespace or control characters. |
| 401 | `AUTHENTICATION_REQUIRED` | No accepted verified workload identity was presented. |
| 403 | `RESOLUTION_READ_DENIED` | The authenticated identity lacks `resolutions:read`. |
| 404 | `RESOLUTION_NOT_FOUND` | No resolution exists in the authenticated tenant. Cross-tenant IDs produce this same response. |
| 429 | `RESOLUTION_STATUS_BUSY` | The process-wide bounded read capacity is exhausted. |
| 500 | `RESOLUTION_STATUS_FAILED` | The authoritative repository failed. Internal details are logged, not returned. |

Authentication and scope checks occur before identifier validation or database
access. This prevents unauthenticated callers from using validation differences
as an identifier oracle. Missing and cross-tenant records are deliberately
indistinguishable.

## Operational bounds

- At most 64 status reads execute concurrently per process.
- Resolution IDs are limited to 128 bytes.
- The server's existing header, read and write timeouts apply.
- The endpoint performs one tenant-scoped PostgreSQL read and has no collection
  side effect.

Deployment admission control and per-actor/per-tenant rate limiting remain open
hardening work; process concurrency alone is not a complete abuse-control
strategy.

## Verification

Handler tests prove that:

- the authenticated tenant, rather than request input, scopes repository access;
- internal authority fields are absent from a successful response;
- missing identity and missing scope fail before repository access;
- a cross-tenant identifier receives the same not-found response as an absent
  identifier; and
- malformed identifiers are rejected before repository access.

PostgreSQL repository tests separately verify tenant-scoped reads. A supported
deployment must add end-to-end TLS tests through the real listener and
side-channel measurements under representative load.
