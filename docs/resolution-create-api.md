# Resolution creation API

The control plane exposes an authenticated asynchronous creation endpoint:

```text
POST /v1/resolutions
```

It creates or idempotently replays a durable resolution in `received` state.
Creation does not itself contact a device. Target resolution, policy, planning,
approval and collection remain later authority transitions.

## Authentication and authority

The route is registered only with the complete control-plane mTLS
configuration. TLS verifies the peer chain, then the application requires one
SPIFFE URI SAN matching:

```text
spiffe://<trust-domain>/tenant/<tenant>/role/agent/workload/<name>
```

The route-specific binding grants the `agent` role only
`resolutions:create`. Actor and tenant are derived from that verified identity;
neither is accepted in the request.

## Request

`Content-Type: application/json` and an `Idempotency-Key` header are required.

```json
{
  "schema_version": "v1",
  "claims": [
    "interface.name",
    "interface.operational_state"
  ],
  "target_ids": [
    "router-1",
    "router-2"
  ],
  "maximum_age_seconds": 300
}
```

The v1 limits are:

- request body: 64 KiB;
- idempotency key: 1–128 bytes with no whitespace or control characters;
- claims: 1–32 unique values, each at most 128 bytes using lower-case letters,
  digits, `.`, `_` and `-`, and beginning with a letter;
- target IDs: 1–1,000 unique bounded identifiers; and
- maximum age: 1–604,800 seconds.

Unknown fields, trailing JSON documents, duplicate claims/targets and values
outside these bounds fail before authoritative state is written. Claim and
target order is not semantically significant: the server sorts both arrays and
serializes one canonical v1 document.

## Durable provenance and idempotency

The server computes `sha256:<hex>` over the exact canonical document. It stores
both the bytes and digest in the resolution transaction; callers cannot submit
their own digest. The same transaction stores the actor-and-tenant-scoped
idempotency record and a `resolution.received` outbox event containing the
canonical request and digest.

Migration `000012_resolution_request_provenance` stores the exact JSON bytes as
`BYTEA`, not `JSONB`, so PostgreSQL cannot reformat the digested representation.
The column is nullable only to preserve workflows created before this migration.
All new service-created resolutions require valid JSON whose digest matches the
stored bytes.

Retry outcomes:

| Condition | Result |
|---|---|
| New key in this tenant-and-actor scope | One resolution and one creation event; `created` is `true`. |
| Same key and same canonical request | Original resolution; `created` is `false`; no second event. |
| Same key and different canonical request | `409 IDEMPOTENCY_KEY_REUSED`; original state is unchanged. |

## Accepted response

New and idempotently replayed requests return `202 Accepted`, a `Location`
header pointing at the status resource, `Cache-Control: no-store`, and:

```json
{
  "schema_version": "v1",
  "resolution_id": "res-0123456789abcdef",
  "state": "received",
  "version": 1,
  "created": true
}
```

The response does not expose tenant, actor, request digest, canonical request or
idempotency key. Poll the [resolution status API](resolution-status-api.md)
using the returned location.

## Errors

Errors use a stable envelope:

```json
{
  "error": {
    "code": "IDEMPOTENCY_KEY_REUSED",
    "message": "idempotency key was reused for different request content",
    "retryable": false
  }
}
```

| HTTP status | Code | Retryable |
|---|---|---|
| 400 | `INVALID_IDEMPOTENCY_KEY` | No |
| 400 | `INVALID_REQUEST` | No |
| 401 | `AUTHENTICATION_REQUIRED` | No |
| 403 | `RESOLUTION_CREATE_DENIED` | No |
| 409 | `IDEMPOTENCY_KEY_REUSED` | No |
| 429 | `RESOLUTION_CREATE_BUSY` | Yes, with backoff and the same key/body |
| 500 | `RESOLUTION_CREATE_FAILED` | Yes, with the same key/body |

Authentication and scope checks happen before the body is read. Internal
repository errors are logged but never returned to the caller.

## Operational qualification

At most 32 creations run concurrently per process. This bound does not replace
per-actor/per-tenant rate limiting or deployment admission control. Production
acceptance must also verify real mTLS ingress, PostgreSQL transaction loss,
outbox delivery/replay, timing non-interference and planner consumption of the
versioned request event.
