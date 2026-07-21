# Resolution watch API

The control plane exposes a bounded Server-Sent Events stream for durable
resolution state changes:

```text
GET /v1/resolutions/{resolution_id}/events
Accept: text/event-stream
```

The stream reports workflow progress only. It cannot trigger collection or
release evidence.

## Authentication and authority

The route is available only with the complete mTLS configuration. The verified
SPIFFE identity must use the `agent` role; the route-specific binding grants
only `resolutions:watch`. Tenant authority comes from that identity and is used
in both the resolution-existence check and every durable event query.

Missing and cross-tenant resolutions return the same
`404 RESOLUTION_NOT_FOUND` response before SSE headers are committed.

## Safe event projection

The source of truth is the transactional resolution outbox history. The API
does not proxy raw outbox payloads. It allowlists resolution lifecycle event
types and emits only:

```json
{
  "cursor": 2,
  "type": "resolution.state_changed",
  "state": "resolving_targets",
  "occurred_at": "2026-07-21T09:00:00Z"
}
```

Canonical requests, request digests, tenant and actor identifiers, task counts,
event IDs, delivery attempts, dead-letter state and global outbox sequences are
not disclosed.

The SSE `id` and JSON `cursor` are the resolution version. They are not the
global outbox sequence, so gaps cannot be used to infer activity in other
tenants or resolutions. A resolution transaction produces at most one exposed
lifecycle event for a version.

Example stream:

```text
retry: 1000

id: 1
event: resolution.received
data: {"cursor":1,"type":"resolution.received","state":"received","occurred_at":"2026-07-21T09:00:00Z"}

id: 2
event: resolution.state_changed
data: {"cursor":2,"type":"resolution.state_changed","state":"resolving_targets","occurred_at":"2026-07-21T09:00:01Z"}

```

Streams are marked `Cache-Control: no-store` and
`X-Accel-Buffering: no`. Terminal states close the stream after their event.

## Reconnection and bounded waiting

Clients reconnect using either:

```text
Last-Event-ID: 2
```

or:

```text
GET /v1/resolutions/{resolution_id}/events?after=2
```

Supplying both is invalid. Cursors are non-negative decimal resolution
versions. Events with a version less than or equal to the cursor are not sent.

`wait_seconds` controls the bounded connection lifetime from 1 to 30 seconds;
the default is 15 seconds. A stream with no terminal event ends with an SSE
timeout comment. The client reconnects with its last successfully processed
event ID. Durable history makes reconnect independent of JetStream's duplicate
window and consumer state.

The process polls PostgreSQL every 250 ms and returns at most 100 events per
read. At most 32 watch streams run concurrently per process. These controls do
not replace deployment connection limits or per-actor/per-tenant admission.

## Errors

Before streaming begins, errors use the same simple JSON code shape as the
status API:

| HTTP status | Code |
|---|---|
| 400 | `INVALID_RESOLUTION_ID` |
| 400 | `INVALID_WATCH_CURSOR` |
| 401 | `AUTHENTICATION_REQUIRED` |
| 403 | `RESOLUTION_WATCH_DENIED` |
| 404 | `RESOLUTION_NOT_FOUND` |
| 429 | `RESOLUTION_WATCH_BUSY` |
| 500 | `WATCH_STREAM_UNAVAILABLE` or `RESOLUTION_WATCH_FAILED` |

After SSE headers are committed, cancellation, write failure or repository
failure closes the stream without inventing a durable event. Clients reconnect
from the last received version.

## Qualification still required

Repository and handler tests cover tenant binding, safe projection, cursor
resume, terminal closure, malformed cursors and concurrency. Production
acceptance still requires real proxy/load-balancer buffering tests, connection
drain behavior during rollout, per-tenant admission, slow-client testing and
timing side-channel measurement.
