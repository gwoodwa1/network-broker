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

The control-plane entrypoint now requires `DATABASE_URL`, verifies connectivity before becoming available, and exposes `GET /livez` and `GET /readyz` for orchestration probes. Set `APPLY_MIGRATIONS=true` only for an instance authorised to apply the embedded, checksum-verified migrations; concurrent migration attempts are serialised with a PostgreSQL advisory lock. `LISTEN_ADDRESS` defaults to `:8080`.

Outbox dispatchers use ordered `FOR UPDATE SKIP LOCKED` claims, expiring worker leases, bounded retry scheduling, and terminal dead-letter state. Publishers must deduplicate on the immutable event ID because delivery is intentionally at least once.

## Current status

This repository is a security-oriented prototype, not a production service. Important production work still includes:

- A production event-broker publisher, dead-letter operations workflow, and durable object storage.
- Generated protobuf API contracts and network-facing services.
- Production gNMI, NETCONF, or SSH transport implementations.
- External policy bundles and approval persistence.
- Key management, workload identity, and credential-broker integration.
- Metrics, tracing, audit-ledger export, resilience testing, and rollout controls.

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
