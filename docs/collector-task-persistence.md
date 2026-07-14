# Durable collector task authority

Collector task state is security authority, not a delivery hint. A database record is the source of truth for the current lease owner, lease deadline, monotonic fencing token, execution decision and grant, and the single accepted attempt and evidence result.

Migration `000007_collector_tasks` creates this authority record. The PostgreSQL repository uses guarded updates for every transition:

- acquisition accepts only queued/retry work or an expired active lease and increments the fencing token;
- execution, authority recording, retry and commit require the current owner, token, unexpired lease and expected state;
- a new fencing epoch clears execution authority from the previous attempt;
- retry releases ownership without decrementing or reusing a token; and
- commit writes the accepted attempt and evidence identifiers together and can succeed only once.

The database constrains active lease completeness, execution decision/grant pairing, accepted attempt/evidence pairing and the relationship between a successful task and its accepted result. Partial unique indexes prevent one accepted attempt or evidence identifier from being attached to multiple tasks.

## Restart contract

Creating another repository instance does not create another authority domain. Before lease expiry, reacquisition fails even when the collector presents the same SPIFFE identity. After expiry, reacquisition increments the token; grants, evidence assembly and commits using the previous token fail closed. A completed result remains readable and a second commit remains rejected after another process restart.

The integration test `TestPostgresCollectorTaskSurvivesRestartAndRejectsStaleFence` exercises this sequence against PostgreSQL. Run it with:

```bash
POSTGRES_TEST_DSN='postgres://...' go test -tags integration ./test/integration \
  -run TestPostgresCollectorTaskSurvivesRestartAndRejectsStaleFence
```

## Remaining runtime work

`CreateFanoutContext` now creates the complete task set, advances a planned resolution to queued and appends its outbox event in one transaction. A concurrent planner loses the locked resolution-version comparison and cannot leave partial or duplicate work. `collectorruntime.New` constructs workers with this PostgreSQL task authority and durable artefact/evidence repositories. The control plane schedules bounded expired-evidence reconciliation and exports its counters.

The remaining integration work is for the network-facing planner to invoke this fan-out boundary and for a deployment entrypoint to supply qualified transport, policy, external credential-broker, S3, KMS and verified workload-identity dependencies. Database roles must prevent collectors from inserting tasks or bypassing guarded transitions.
