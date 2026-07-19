# Production authority runtime

The production runtime must not silently replace durable authority with process-local stores. This increment provides three explicit runtime boundaries.

## Durable collector construction

`collectorruntime.New` requires:

- a validated collector `AuthContext` carrying a SPIFFE identity revision, the `collector` role and `tasks:execute` scope;
- PostgreSQL for task authority, artefact metadata, signed evidence envelopes and grant-consumption coordination;
- immutable blob storage;
- opaque signing and tenant encryption providers;
- a qualified bounded transport adapter;
- a recipe-specific hostile-output transformer producing the strict parser schema;
- execution-time policy authorization;
- signed execution-grant issuance; and
- credential-broker exchange.

The constructor creates no signing key and has no memory-store fallback. Before acquiring a task, `Runtime.Run` checks that its tenant matches the authenticated workload tenant. The deployment entrypoint remains responsible for deriving `AuthContext` from a verified SVID and constructing qualified S3, KMS, policy, transport and external credential-broker adapters.

For the first gNMI interface-state recipe, `normalise.GNMIInterfaceState`
closes the protocol/schema boundary: captured protobuf JSON remains immutable,
while only one bounded, sanitised and manifest-bound OpenConfig
`name`/`oper-status` response can reach the strict parser. This is a required
composition dependency, not evidence of vendor qualification.

## Transactional task fan-out

`collector.PostgresRepository.CreateFanoutContext` locks a planned resolution and verifies its expected version. Within the same transaction it:

1. inserts the complete validated task set;
2. advances the resolution to `queued`, records the target count and increments its version; and
3. appends the bound `resolution.tasks_queued` outbox event.

Any insertion, version or event conflict rolls back the entire task set. Concurrent planners therefore produce one winner and one `ErrFanoutConflict`, never two independently executable task sets.

## Authenticated planning invocation

The control plane exposes `POST /v1/resolutions/{resolution_id}/tasks:queue` only when its TLS and client trust configuration is enabled. The peer certificate must already be verified by TLS and must carry the configured SPIFFE trust domain with the `planner` role. That role receives only the `resolutions:plan` scope.

The request uses schema version `v1`, is limited to 512 KiB and 1,000 tasks, rejects unknown fields and accepts exactly one JSON document. It contains the expected resolution version and task planning outputs, but no tenant, resolution, task-state, event-id or event-time authority. `planning.Service` derives those values from the authenticated context, URL and server dependencies before invoking the transactional repository. A changed resolution version returns `RESOLUTION_AUTHORITY_CHANGED`; the losing planner cannot partially insert tasks.

The planner is an authority-bearing internal workload. It must submit only catalogue-derived recipes and persisted trigger/planning decision identifiers. Database-role enforcement and direct foreign-key validation of those provenance bindings remain part of the supported deployment hardening gate.

## Authenticated resolution status

The control plane exposes `GET /v1/resolutions/{resolution_id}` when its mTLS
configuration is enabled. A verified SPIFFE identity with the `agent` role
receives the narrow `resolutions:read` scope. The handler derives tenant
authority exclusively from that identity and performs a tenant-and-ID bound
repository lookup.

The v1 response contains only workflow state, target count, completion flag,
version and timestamps. It excludes tenant, originating actor, idempotency key
and request digest, is marked `no-store`, and cannot trigger collection or
release evidence. Missing and cross-tenant identifiers return the same 404
code. Authentication and scope checks precede identifier validation and
repository access. See the [resolution status API contract](resolution-status-api.md).

This is the first external read slice, not completion of the northbound API.
Resolution creation/watch, QueryContext, evidence retrieval, per-tenant rate
limits and deployment-level side-channel qualification remain open.

## Reconciliation scheduling

The control plane always constructs `ReconciliationRunner`. It lists a bounded, deterministic batch of expired tasks whose indexed evidence bindings still match, then invokes the guarded acceptance update. A task can be accepted only if tenant, task, fence and execution-grant authority are unchanged at update time.

Configuration:

- `RECONCILIATION_BATCH_SIZE` — `1..10000`, default `100`;
- `RECONCILIATION_POLL_INTERVAL` — positive Go duration, default `5s`; and
- `RECONCILIATION_FAILURE_DELAY` — positive Go duration, default `5s`.

Prometheus counters report candidates, reconciled envelopes, expected skips and failures. Alerts should distinguish a rising skip rate caused by collector churn from storage/integrity failures.

## Verification

The PostgreSQL integration suite proves:

- two concurrent planners create one complete task set and one outbox event;
- the concurrent planners enter through the authenticated, tenant-binding planning service;
- a collector assembled exclusively from durable repository boundaries completes a task and its result survives reconstruction;
- a persisted envelope is accepted after simulated collector loss; and
- reacquisition increments the fence and prevents stale evidence acceptance.

The remaining deployment acceptance test must repeat these cases by killing actual collector processes while using qualified external S3, KMS, workload identity, credential-broker and device-lab dependencies.

## PostgreSQL identity enforcement

The control-plane process requires `DATABASE_ROLE` and verifies the exact live
`current_user` and `session_user` before constructing authority repositories.
Administrative capabilities and `CREATE` on the `public` schema fail startup.
The same check audits effective privileges on every broker-prefixed table and
sequence against the exact control-plane manifest, rejecting missing grants and
any access obtained beyond that manifest.
Schema migration uses a separately configured `MIGRATION_DATABASE_URL`, which
is opened only for migration and closed before the runtime connection is
created. See [PostgreSQL runtime-role enforcement](database-role-enforcement.md).
