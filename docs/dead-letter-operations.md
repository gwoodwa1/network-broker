# Dead-letter operations

The control plane exposes dead-letter inspection and replay only when its operator mTLS configuration is complete. It never accepts actor, tenant, role, or scope from HTTP headers.

## Identity and transport

Configure all four settings together:

- `SERVER_TLS_CERT_FILE`
- `SERVER_TLS_KEY_FILE`
- `OPERATOR_CLIENT_CA_FILE`
- `OPERATOR_SPIFFE_TRUST_DOMAIN`

The server requires TLS 1.3. Health and metrics requests may omit a client certificate, but every operator endpoint requires a verified certificate issued by `OPERATOR_CLIENT_CA_FILE` with exactly one URI SAN using this convention:

```text
spiffe://<trust-domain>/tenant/<tenant>/role/outbox-operator/workload/<name>
```

The authenticated tenant comes only from that SPIFFE ID. Operator certificates receive the server-defined `outbox:dead-letter:read` and `outbox:dead-letter:replay` scopes. Certificate issuance is therefore a privileged administrative operation.

If the four settings are absent, the control plane continues serving its non-operator endpoints over HTTP and does not register the operator routes. Partial configuration fails startup.

## API

All responses exclude the event payload and raw broker error because either may contain sensitive network data or secrets.

### List

```http
GET /v1/operations/dead-letters?limit=50&cursor=<opaque-cursor>
```

`limit` defaults to 50 and cannot exceed 100. `next_cursor` is returned when another page may exist. Unknown or duplicate query parameters are rejected.

### Get

```http
GET /v1/operations/dead-letters/<event-id>
```

Missing and cross-tenant events both return `404`.

### Replay

```http
POST /v1/operations/dead-letters/<event-id>/replay
Idempotency-Key: incident-2026-001-attempt-1
Content-Type: application/json

{"reason":"NATS stream configuration repaired"}
```

The idempotency key is scoped to the authenticated tenant and actor. The reason is mandatory and limited to 512 bytes. Bodies are limited to 4 KiB, unknown JSON fields and trailing documents are rejected, and accepted requests return `202`.

Replay performs the following in one PostgreSQL transaction:

1. Serializes concurrent uses of the actor's idempotency key.
2. Locks the tenant-scoped dead-letter row.
3. Snapshots its prior failure, attempts, and dead-letter time into `broker_dead_letter_actions`.
4. Clears terminal and lease state, resets attempts to zero, and makes the event available using database transaction time.
5. Commits one append-only audit action.

The audit table rejects `UPDATE` and `DELETE`. Reusing the same key for the same event returns the original action without another replay. Reusing it for another event returns `409`.

## Operational cautions

- Confirm the underlying broker or configuration fault is resolved before replay.
- JetStream publication uses the immutable event ID as `Nats-Msg-Id`. If a previous acknowledgement was lost, JetStream may identify the replay as a duplicate and the dispatcher will reconcile the outbox row as published.
- Consumers must remain idempotent because duplicate detection is bounded by the stream's configured duplicate window.
- Replay reasons, event payloads, and raw broker errors must not be copied into metrics labels or ordinary logs.
- Monitor the replay, idempotent replay, denial, retry, failure, and dead-letter counters exposed by `/metrics`.

## Example

```bash
curl --fail --silent --show-error \
  --cert operator.pem \
  --key operator.key \
  --cacert server-ca.pem \
  https://broker.example/v1/operations/dead-letters
```
