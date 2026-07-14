# PostgreSQL runtime-role enforcement

Authority-bearing services must connect with a dedicated PostgreSQL login. The
control plane now verifies the live connection before constructing any
repository; the user named in a connection string is not treated as evidence.

Set `DATABASE_ROLE` to the exact runtime login. Startup fails when `current_user`
or `session_user` differs, including after `SET ROLE`, and when the role is a
superuser, can bypass row security, create roles or databases, replicate, cannot
log in directly, or can create objects in the `public` schema.

## Separate migration authority

The runtime role must not own or mutate the schema. When
`APPLY_MIGRATIONS=true`, `MIGRATION_DATABASE_URL` is required and must differ
from `DATABASE_URL`. The control plane opens that identity only for the
checksum-verified migration transaction, closes it, then opens and verifies the
runtime identity. Prefer running the same embedded migrator as a separate
deployment job and leaving `APPLY_MIGRATIONS` disabled in steady state.

## Provisioning contract

Provision roles outside the application. A deployment-specific administrator
should apply the equivalent of:

```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE ROLE broker_controlplane LOGIN
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE broker TO broker_controlplane;
GRANT USAGE ON SCHEMA public TO broker_controlplane;

GRANT SELECT, INSERT, UPDATE ON
    broker_resolutions,
    broker_outbox,
    broker_collector_tasks
TO broker_controlplane;
GRANT SELECT, INSERT ON broker_resolution_idempotency TO broker_controlplane;
GRANT SELECT ON broker_evidence_envelopes TO broker_controlplane;
GRANT SELECT, INSERT ON broker_dead_letter_actions TO broker_controlplane;
GRANT USAGE ON SEQUENCE broker_outbox_sequence_seq TO broker_controlplane;
```

Keep schema ownership and migration-ledger access on the separate migrator
role. Reapply the explicit runtime grants when a migration adds a table or
sequence needed by the process. Do not use `GRANT ... ON ALL TABLES`, default
grants, role inheritance, or ownership as a substitute for this manifest.

Startup also enumerates every `broker_` table, view and sequence in `public`
and evaluates the role's effective privileges. It requires every grant in the
manifest above and rejects any additional table or sequence privilege,
including privileges obtained through ownership, `PUBLIC` or inherited roles.
This makes grant drift and overly broad default grants fail closed.
