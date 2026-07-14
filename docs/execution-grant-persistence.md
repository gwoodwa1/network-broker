# Durable execution-grant consumption and evidence reconciliation

An execution grant is useful authority even though it contains no device credential. Its single-use state must therefore be shared by every credential-broker replica and survive process loss.

Migration `000010_execution_grant_consumptions` creates an append-only PostgreSQL ledger. Credential exchange verifies the grant signature, issuer, audience, validity, authenticated collector identity and current fence before attempting consumption. The repository then locks the authoritative collector-task row and independently verifies:

- tenant and task identity;
- authenticated collector SPIFFE identity;
- target and exact recipe version;
- the grant identifier recorded for the executing attempt;
- the current fencing token and active lease; and
- expiry using database time.

Only then is the consumption inserted. The grant identifier and SHA-256 digest of the signed grant are retained. The raw nonce and target credential are not persisted; a SHA-256 nonce digest provides the uniqueness key. Unique constraints and the task-row lock ensure concurrent replicas produce one successful exchange and one `ErrAlreadyConsumed` result.

Credential bytes are minted before the durable insert but released only after it commits. A process failure after commitment can therefore burn a grant without exposing its credential. The task must retry through a new attempt, fence and grant; replaying the consumed grant is never an availability recovery mechanism.

The memory consumption repository preserves conflict semantics for deterministic local workflows but is explicitly not production authority. `collectorruntime.New` requires an explicit credential exchange boundary and durable PostgreSQL authority; production credential-broker replicas must share `PostgresConsumptionRepository` or an adapter with equivalent transactional guarantees.

## Evidence acceptance crash window

Evidence persistence and task acceptance are separate durable writes. Migration `000011` adds the execution-grant identifier as an indexed envelope binding. `ReconcileExpiredEvidenceContext` waits until the task lease has expired, then performs one guarded update that accepts an envelope only if its tenant, task, fencing token and execution-grant identifier still match the active task authority.

This creates two safe race outcomes:

- reconciliation wins before reacquisition and the task becomes `succeeded`; or
- reacquisition increments the fencing token and the old envelope is retained for audit but cannot be accepted.

Reconciliation is idempotent for the already accepted envelope. It rejects a live lease, a changed fence or grant, a competing accepted result and an invalid task state. The control-plane runner processes bounded deterministic batches, immediately drains full batches, backs off on failures and treats reacquisition races as expected skips.

## Verification

`TestExecutionGrantConsumptionSurvivesRestartAndIsConcurrentSingleUse` races separate authority and repository instances, recreates them after consumption, verifies the stored non-secret binding and confirms append-only enforcement.

`TestExpiredEvidenceReconciliationAcceptsOnlyUnchangedFence` models process loss after envelope creation. It verifies recovery after lease expiry and proves that reacquisition fences the old envelope.

Run the PostgreSQL integration suite with:

```bash
POSTGRES_TEST_DSN='postgres://...' go test -tags integration ./test/integration
```
