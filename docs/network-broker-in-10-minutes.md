# Network Broker in 10 Minutes

This guide is the shortest path to understanding the Network Evidence Broker:
what problem it solves, how authority flows through it, what is implemented,
and where to start in the code.

## Minute 1 — The problem

Agents and automation often need facts from network devices, such as whether an
interface is operationally up. Giving an agent device credentials or an
arbitrary SSH/gNMI/NETCONF capability creates a large security boundary:

- the caller may contact the wrong tenant or device;
- a generated command may be unsafe;
- queued work may execute after policy changes;
- retries may race or accept a stale result;
- device output may contain secrets or prompt-injection content; and
- collected evidence may later be disclosed to the wrong actor.

The broker narrows that boundary. A caller requests a fact. Server-owned
inventory, policy and recipe catalogues decide whether and how that fact may be
collected. The caller does not supply a device command and does not receive a
device credential.

## Minute 2 — The security objective

For every accepted observation, preserve a verifiable chain across:

```text
caller identity
  -> tenant and scope
  -> immutable target snapshot
  -> policy and approval
  -> exact recipe version
  -> fenced task attempt
  -> single-use execution grant
  -> captured and sanitised artefacts
  -> typed observation
  -> signed evidence envelope
  -> actor-specific disclosure decision
  -> signed delivery receipt
```

Collection authority and disclosure authority are separate. Permission to
trigger collection does not automatically grant permission to retrieve the
result or its captured source data.

## Minute 3 — The request flow

```text
Authenticated caller
        |
        v
Query existing context or create a durable resolution
        |
        v
Resolve tenant-scoped targets and evaluate policy
        |
        v
Create bounded tasks and transactional outbox event
        |
        v
Collector acquires a lease and monotonic fencing token
        |
        v
Re-authorize, issue a signed grant, exchange for a short-lived credential
        |
        v
Execute one exact-versioned, bounded, read-only transport recipe
        |
        v
Capture -> sanitise/normalise -> strict parse -> sign evidence
        |
        v
Fresh disclosure decision -> selected fields -> signed receipt
```

The system accepts exactly one current fenced result. It does **not** claim
exactly-once device interaction: a failure with an uncertain device outcome may
cause a retry and duplicate contact.

## Minute 4 — The authority model

Four controls do most of the security work.

### Verified identity

Workload identity is derived from a certificate in a verified mTLS chain. The
SPIFFE URI supplies the tenant and role only after trust-domain and path
validation. Request bodies and headers are not identity authority.

### Server-owned recipes

Tasks carry an exact recipe ID and version. The transport looks up its path,
filter or command in a trusted catalogue. A caller cannot place a raw command
or arbitrary RPC body into a task.

### Leases and fencing

A collector must acquire the task before execution. Every authority-bearing
transition checks the current lease owner and monotonic fencing token. If a
lease expires and another worker acquires the task, the old worker's grant,
evidence and commit become stale.

### Fresh disclosure

Evidence access is evaluated separately for the current actor. A delivery
receipt signs the exact payload digest, fields, redactions, taint and policy
lineage delivered for one request.

## Minute 5 — Durable workflow and partial failure

PostgreSQL is the source of truth for resolutions, idempotency records, tasks,
leases, fences, execution authority, evidence envelopes, approval/grant
consumption, disclosure records and outbox delivery state.

Important failure properties include:

- resolution creation is idempotent;
- task fan-out, resolution transition and outbox insertion are transactional;
- grant nonces can be consumed only once across replicas and restarts;
- stale fences cannot commit;
- a task can accept only one attempt/evidence pair;
- immutable evidence must exist before task success can reference it;
- crash reconciliation rechecks tenant, task, grant and fence authority; and
- external event delivery remains intentionally at least once, so consumers
  must be idempotent.

Start with:

- [Durable collector task authority](collector-task-persistence.md)
- [Execution-grant persistence](execution-grant-persistence.md)
- [JetStream delivery operations](jetstream-operations.md)

## Minute 6 — Evidence and hostile device data

Transport authentication proves which configured endpoint replied; it does not
prove the device is truthful. All device output remains hostile.

The evidence pipeline preserves distinct stages:

1. **Captured** — exact bounded transport output, encrypted and immutable.
2. **Sanitised** — a separately digested derivative with a transformation
   manifest.
3. **Normalised** — strict recipe-specific typed data.
4. **Envelope** — signed lineage and attribution referencing the immutable
   artefacts.

The sanitiser bounds structure and strings, removes terminal controls, applies
configured redactions, detects instruction-like or encoded content, and
quarantines unsafe payloads. Tainted device-controlled fields remain typed data
and are denied from disclosure by default.

For the first real gNMI profile, raw protobuf JSON remains the captured object.
A bounded normaliser accepts only one OpenConfig interface `name` and
`oper-status` response before producing the canonical parser schema.

Read:

- [Adversarial network-output sanitisation](adversarial-sanitisation.md)
- [gNMI interface-state normalisation profile](gnmi-interface-state-profile.md)
- [Durable evidence and disclosure](evidence-disclosure-persistence.md)

## Minute 7 — Repository map

```text
cmd/
  collector/          Local deterministic collector demonstration
  controlplane/       Durable control-plane, planning and operator runtime

internal/
  authctx/            Authenticated tenant, role, scope and limits
  workloadidentity/   Verified-chain SPIFFE identity derivation
  inventory/          Immutable tenant-scoped target snapshots
  resolution/         Durable idempotent workflow lifecycle
  planning/           Authenticated bounded task planning
  policy/             Signed bundles and decision provenance
  approval/           Scoped durable approvals
  collector/          Tasks, leases, fencing, execution and reconciliation
  grants/             Signed single-use grants and credential exchange
  transport/          Bounded gNMI, NETCONF and SSH adapters
  normalise/          Protocol-specific canonical normalisation
  sanitise/           Hostile-output transformation and manifests
  parsing/            Strict typed observation parsing
  artefacts/          Immutable captured/sanitised storage and lifecycle
  evidence/           Signed envelopes and evidence pipeline
  disclosure/         Actor-specific decisions and signed receipts
  retrieval/          Selective normalised evidence retrieval
  outbox/             Durable event delivery
  deadletter/         Authenticated inspection and replay
  databaseauth/       Exact PostgreSQL runtime-role and grant checks

migrations/           Embedded checksum-verified PostgreSQL schema
test/integration/     PostgreSQL and JetStream restart/concurrency tests
docs/                 Threat model, contracts, profiles and runbooks
```

## Minute 8 — Run it locally

Requirements:

- Go 1.25 or newer
- Docker for the pinned quality toolchain and integration dependencies

Run all unit tests:

```bash
go test ./...
```

Run concurrency checks:

```bash
go test -race ./...
```

Run the deterministic local collector demonstration:

```bash
go run ./cmd/collector \
  -task-id task-demo \
  -target-id target-demo
```

This local command demonstrates the security sequence, but it deliberately
uses memory stores, local keys, a stub transport and a scaffold policy. It is
not the production collector runtime.

Run the repository's pinned quality and security checks:

```bash
docker build --target quality -t network-broker-quality .
docker run --rm network-broker-quality
```

The quality image runs formatting, module integrity, build, strict lint, race
tests, `gosec` and `govulncheck`.

## Minute 9 — What is implemented versus still open

### Implemented at component or durable repository level

- Verified-chain workload identity derivation.
- Durable resolutions, tasks, fencing and idempotency.
- Transactional task fan-out and outbox creation.
- Durable single-use execution-grant consumption.
- Crash reconciliation for evidence persisted before task commit.
- Signed/versioned policy bundles and durable approvals.
- Read-only bounded gNMI, NETCONF and SSH adapters.
- S3-compatible immutable blob and AWS KMS provider adapters.
- Captured/sanitised lineage and lifecycle metadata.
- Strict interface-state normalisation and parsing.
- Signed evidence envelopes and actor-bound delivery receipts.
- Authenticated internal planning and dead-letter operator surfaces.
- Authenticated, canonical and idempotent resolution creation.
- Authenticated, tenant-scoped resolution status reads.
- Exact control-plane PostgreSQL role and object-grant verification.

### Still open before production use

- A supported collector entrypoint composing PostgreSQL, S3, KMS, verified
  workload identity, production policy, an external credential broker and one
  qualified transport.
- Resolution watch, QueryContext and evidence-retrieval APIs. Versioned,
  authenticated resolution creation and tenant-scoped status reads are
  available at `POST /v1/resolutions` and
  `GET /v1/resolutions/{resolution_id}`.
- Vendor/network-OS release qualification.
- A lifecycle deletion and orphan-reconciliation worker.
- Production policy and approval administration.
- SPIRE deployment, rotation, revocation and recovery exercises.
- Real process-kill tests across security-sensitive collector boundaries.
- Correlated traces, dashboards, alerts and external audit export.
- Deployment manifests, egress policy, canary/rollback and HA/DR evidence.
- SBOM/provenance and independent penetration/cryptographic review.

The repository is a security-oriented prototype, not a production service.
Component tests do not establish that external infrastructure is configured
safely.

## Minute 10 — Where to go next

Choose the path matching your role.

### Product or architecture

1. [README](../README.md)
2. [Threat model](threat-model.md)
3. [Production hardening](production-hardening.md)
4. [Implementation roadmap](../Implementation_Roadmap.md)

### Collector and reliability engineering

1. [`internal/collector`](../internal/collector)
2. [Collector task persistence](collector-task-persistence.md)
3. [Production authority runtime](production-authority-runtime.md)
4. [`test/integration`](../test/integration)

### Evidence and agent safety

1. [Adversarial sanitisation](adversarial-sanitisation.md)
2. [`internal/normalise`](../internal/normalise)
3. [`internal/parsing`](../internal/parsing)
4. [`internal/evidence`](../internal/evidence)
5. [`internal/disclosure`](../internal/disclosure)

### Security review

1. [Threat model](threat-model.md)
2. [External security review package](security-review-package.md)
3. [Transport security](transport-security.md)
4. [Key rotation](key-rotation.md)
5. [PostgreSQL runtime-role enforcement](database-role-enforcement.md)

## Five rules to remember

1. The caller requests a fact, never an arbitrary device operation.
2. A plan is advice; current policy, approval, lease and fence are authority.
3. Credentials are transient and never belong in tasks, evidence or logs.
4. Device output is hostile data, even over an authenticated transport.
5. Signed evidence proves integrity and provenance, not device truthfulness.
