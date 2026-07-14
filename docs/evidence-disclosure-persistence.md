# Durable evidence and disclosure authority

Signed evidence and delivery receipts are authority-bearing records. Losing them on restart would make a successfully committed task unverifiable and could let a retried disclosure produce a second receipt for the same caller request.

Migration `000008_evidence_envelopes` stores the exact signed envelope bytes and their SHA-256 digest. Indexed identity, task, attempt, fence, target, recipe and validity fields are compared with the decoded document on every read. Records are append-only, tenant-scoped and unique per task attempt. A collector task cannot transition to `succeeded` with an evidence identifier that is absent from the envelope table.

Migration `000009_disclosure_records` stores:

- actor-, tenant-, evidence- and policy-bound disclosure decisions with expiry; and
- signed delivery receipts binding the exact delivered-payload digest, fields, taint, redactions and request identity.

The repository retains the exact encoded bytes rather than relying on a database JSON re-encoding. Reads recompute the document digest and compare indexed security fields with the decoded record. Database triggers reject update and deletion of decisions, envelopes and receipts.

## Delivery idempotency

`request_id` is an idempotency key scoped to one tenant and actor. Retrying the same decision and exact delivered representation returns the original signed receipt, including its original receipt ID and delivery time. Reusing the request ID with a different evidence, decision, representation, field set, taint classification, redaction set or payload digest returns `ErrReceiptConflict`.

This contract handles an uncertain acknowledgement without manufacturing two audit facts. Callers must retain a request ID until the delivery outcome is known and must generate a new one for a materially different retrieval.

## Restart verification

`TestEvidenceAndDisclosureAuthoritySurviveRestart` creates and commits a real signed envelope, reconstructs the repositories, evaluates and delivers an actor-specific disclosure, reconstructs the disclosure service, and verifies that:

- tenant-scoped envelope lookup survives restart;
- the stored decision remains usable until expiry;
- the original signed receipt is returned for an identical retry;
- conflicting request reuse fails closed;
- the receipt remains cryptographically verifiable; and
- append-only triggers reject mutation.

Run the PostgreSQL integration suite with:

```bash
POSTGRES_TEST_DSN='postgres://...' go test -tags integration ./test/integration
```

## Remaining work

The production control plane and collector must construct these repositories from deployment configuration. Evidence creation, task commit and event publication also need an explicit reconciliation contract for process loss between their separate durable writes. Single-use execution-grant consumption remains process-local and is the remaining authority-persistence item in the first production gate.
