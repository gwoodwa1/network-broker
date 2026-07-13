# Network Broker

Network Broker is a Go prototype for governed, asynchronous collection and disclosure of network evidence. It separates read-only context queries from collection workflows and treats identity, policy, approval, bounded execution, evidence lineage, and retrieval disclosure as distinct security boundaries.

The project currently uses in-memory stores and deterministic local adapters so the core workflow and invariants can be exercised without external infrastructure.

## What it demonstrates

- Authenticated, tenant-scoped request context.
- Deterministic inventory resolution and immutable target snapshots.
- Idempotent asynchronous resolution state.
- Candidate policy decisions and bounded approval grants.
- Fenced collector leases with stale and duplicate commit rejection.
- Execution-time re-authorization.
- Signed, single-use execution grants bound to the collector, task, target, recipe, and fencing token.
- Short-lived target credentials and bounded transport execution.
- Separate captured, sanitised, and normalised evidence objects.
- Schema-validated observations and Ed25519-signed evidence envelopes.
- Actor-, tenant-, evidence-, field-, and representation-specific disclosure decisions.
- Delivery receipts containing a digest of the exact disclosed payload.

## Architecture

The initial implementation is a modular monolith with a separate trusted collector entrypoint:

```text
Agent / client
      |
      v
Query plane ----> existing authorised context
      |
      v
Decision plane -> inventory -> policy -> approval -> target tasks
                                             |
                                             v
Collection plane -> fenced lease -> execution grant -> bounded transport
                                             |
                                             v
Evidence pipeline -> captured -> sanitised -> normalised -> signed envelope
                                             |
                                             v
Retrieval -> current actor-specific disclosure decision -> delivery receipt
```

Collection authorization and evidence disclosure are intentionally separate. Permission to trigger work does not imply permission to retrieve everything that work produces.

## Repository layout

```text
cmd/
  collector/       Local trusted-collector executable and smoke path
  controlplane/    Control-plane entrypoint scaffold
internal/
  approval/        Scoped approval grants
  artefacts/       Immutable captured and sanitised objects
  authctx/         Authenticated tenant and scope context
  collector/       Task leasing, fencing, execution, retries, and commit
  contextstore/    Side-effect-free existing-context queries
  disclosure/      Disclosure decisions and delivery receipts
  evidence/        Signed envelopes and the evidence pipeline
  grants/          Signed execution grants and credential exchange
  inventory/       Tenant-scoped immutable target snapshots
  outbox/          Transactional workflow event contracts
  parsing/         Concrete observation parsing and validation
  policy/          Collection and recipe policy evaluation
  resolution/      Idempotent resolution lifecycle
  retrieval/       Selective normalised evidence retrieval
  sanitise/        Versioned redaction and bounded transformation
  transport/       Narrow bounded transport adapter contract
migrations/        PostgreSQL schema and rollback migrations
```

## Requirements

- Go 1.25 or newer
- PostgreSQL 17 for durable workflow operation
- NATS JetStream 2.14 for durable event publication

## Run the tests

```bash
go test ./...
```

For concurrency checks:

```bash
go test -race ./...
```

## Quality checks and containers

Run the pinned lint, test and security toolchain in Docker:

```bash
docker build --target quality -t network-broker-quality .
docker run --rm network-broker-quality
```

To format the code with the same pinned toolchain:

```bash
docker run --rm -v "$PWD:/src" -w /src network-broker-quality \
  golangci-lint fmt
```

Build minimal, non-root runtime images:

```bash
docker build --target collector -t network-broker-collector .
docker build --target controlplane -t network-broker-controlplane .
```

The quality gate verifies module tidiness and integrity, builds every package, enforces the repository dependency policy, runs strict linting and formatting checks, executes race-enabled tests, and scans with `gosec` and `govulncheck`. The runtime targets contain only a statically linked binary and the system CA bundle. The `quality` target is intentionally separate and contains the pinned analysis tools defined by the repository.

## Run the local collector flow

```bash
go run ./cmd/collector \
  -task-id task-demo \
  -target-id target-demo
```

The command runs a deterministic local workflow that:

1. Acquires a fenced task lease.
2. Re-authorizes the exact execution attempt.
3. Issues and exchanges a signed, identity-bound execution grant.
4. Executes a bounded transport operation.
5. Stores distinct captured and sanitised artefacts.
6. Parses a typed observation and signs its lineage envelope.
7. Commits exactly one accepted evidence result.

It prints the terminal task state and accepted evidence identifier as JSON.

## Resolution persistence

The resolution workflow now has two repository adapters:

- `MemoryRepository` is a concurrency-safe reference implementation for tests and local development.
- `PostgresRepository` uses tenant-scoped compare-and-set updates and commits resolution state, idempotency records, and outbox events in the same database transaction.

PostgreSQL deployments must apply the versioned scripts in `migrations/` before constructing the repository with an application-owned `*sql.DB`. Reusing an idempotency key with the same actor, tenant, and request digest returns the existing workflow; reusing it for different request content fails closed.

The control-plane entrypoint requires `DATABASE_URL`, `NATS_URL`, and a deployment-unique `OUTBOX_WORKER_ID`. It verifies PostgreSQL and NATS connectivity before becoming ready and exposes `GET /livez`, `GET /readyz`, and Prometheus-format `GET /metrics` endpoints. Set `APPLY_MIGRATIONS=true` only for an instance authorised to apply the embedded, checksum-verified migrations; concurrent migration attempts are serialised with a PostgreSQL advisory lock. `LISTEN_ADDRESS` defaults to `:8080`.

The NATS stream is provisioned separately from the application and must cover the configured subject. `NATS_STREAM` defaults to `BROKER_EVENTS` and `NATS_SUBJECT` to `network-broker.events`. Production authentication can use `NATS_CREDENTIALS_FILE`; TLS trust and mutual TLS identity can be configured with `NATS_CA_FILE`, `NATS_CERT_FILE`, and `NATS_KEY_FILE`.

Outbox dispatchers use ordered `FOR UPDATE SKIP LOCKED` claims, expiring worker leases, bounded exponential retry scheduling, and terminal dead-letter state. The JetStream publisher waits for a persistence acknowledgement, asserts the expected stream, and supplies the immutable event ID for server-side deduplication. Consumers must still be idempotent because delivery remains intentionally at least once outside JetStream's configured duplicate window.

Dead-letter inspection and replay are available through a separately authorised operator surface. Configure `SERVER_TLS_CERT_FILE`, `SERVER_TLS_KEY_FILE`, `OPERATOR_CLIENT_CA_FILE`, and `OPERATOR_SPIFFE_TRUST_DOMAIN` together to enable TLS 1.3 and tenant-bound SPIFFE client authentication. When these settings are absent, operator routes are not registered. Replay is concurrency-safe and idempotent, resets the bounded delivery-attempt cycle, and records the previous failure in an append-only PostgreSQL audit row. See the [dead-letter operations contract and runbook](docs/dead-letter-operations.md).

## Durable artefact storage

The evidence pipeline now accepts a tenant-aware artefact storage interface. The reference memory store remains available for deterministic local workflows, while `DurableStore` composes immutable PostgreSQL lineage metadata with an S3-compatible blob adapter. Artefact records have stable idempotent identifiers; object keys are tenant-encoded and content-addressed by SHA-256. Reads enforce the recorded byte count and recompute the digest before returning any bytes. Migration `000004_artefact_metadata` makes metadata append-only and enforces captured-to-sanitised parentage within a tenant. Migration `000005_artefact_lifecycle` adds versioned retention, legal-hold and deletion state with an append-only event ledger. Evidence and execution grants use opaque signing-key references that remain verifiable across rotation, and artefact capture resolves tenant-specific opaque encryption-key references. See the [durable artefact storage contract](docs/artefact-storage.md).

## Current status

This repository is a security-oriented prototype, not a production service. Important production work still includes:

- Production runtime wiring for durable object storage and a lifecycle deletion/reconciliation worker.
- Generated protobuf API contracts and network-facing services.
- Production gNMI, NETCONF, or SSH transport implementations.
- External policy bundles and approval persistence.
- KMS/HSM key-provider adapters, workload identity, and an external credential-broker integration.
- Tracing, audit-ledger export, resilience testing, dashboards, alerts, and rollout controls.

The in-memory implementations are deliberately narrow and map the expected compare-and-set and immutability semantics for later durable adapters.

## Security model

The prototype is built around several explicit constraints:

- Client input cannot supply arbitrary device commands.
- Server-owned policy limits cannot be expanded by execution authorization.
- A collector must hold the current lease and fencing token.
- An execution grant is signed, short-lived, and bound to one collector and operation.
- Captured bytes are never silently overwritten by sanitised data.
- Evidence is signed only for the current fenced attempt with complete lineage.
- Every retrieval is independently authorized for the current actor and produces a receipt.

These controls reduce duplicate contact and unauthorized disclosure, but they do not claim exactly-once device interaction. The authoritative task store accepts only one current fenced result.

## Security

This is an early-stage prototype and is not ready for production network access. Please report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md); do not disclose security issues through a public issue.

## License

This project is available under the [MIT License](LICENSE.md). It is provided without warranty, including without warranties of merchantability, fitness for a particular purpose, or non-infringement.
