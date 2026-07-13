# JetStream delivery operations

The broker publishes immutable outbox events to an administratively provisioned JetStream stream. It supplies
the event ID as `Nats-Msg-Id`, waits for a persistence acknowledgement and asserts the expected stream. The
application does not create or modify the stream, so its duplicate window, retention and consumer behavior are
deployment contracts rather than application defaults.

## Required deployment record

For every environment, record and review:

- stream name, exact subjects, storage type and replica count;
- duplicate window duration;
- retention policy, maximum age, message and byte limits;
- discard policy and behavior when limits are reached;
- durable consumer names, filter subjects and delivery policy;
- acknowledgement policy, acknowledgement wait, maximum deliveries and backoff;
- inactive-consumer and message-retention behavior;
- maximum supported publisher outage and consumer outage; and
- owners, alert thresholds and recovery procedure.

The duplicate window must cover the maximum interval in which the outbox publisher may retry after an uncertain
acknowledgement. Increasing it consumes server resources and does not replace idempotent consumers. Stream
retention must cover the maximum supported consumer outage plus investigation and recovery time.

## Delivery semantics

These mechanisms solve different problems:

- The duplicate window may suppress a repeated publish with the same event ID while that ID remains in the window.
- Stream retention determines whether an acknowledged publication remains available to an offline durable consumer.
- Consumer acknowledgement and redelivery settings determine when an unacknowledged message is delivered again.
- Application-level idempotency determines whether repeated delivery causes repeated business effects.

A consumer being offline longer than the duplicate window does not by itself lose retained messages. If the
stream still retains them and the durable consumer state remains valid, they can be delivered after recovery.
However, a publisher retry after the duplicate window may be stored again, and consumer redelivery may occur at
any time. Consumers must therefore deduplicate by immutable event ID for at least the full event-retention and
business-effect horizon, not merely the JetStream duplicate window.

## Startup and change checks

1. Inspect the provisioned stream and compare its subjects, duplicate window, retention, limits, storage and replicas with the approved deployment record.
2. Confirm the configured `NATS_STREAM` and `NATS_SUBJECT` resolve to that stream.
3. Publish a canary event, verify the persistence acknowledgement and confirm the expected stream and sequence.
4. Republish the canary within the duplicate window and verify the intended duplicate behavior.
5. Exercise consumer redelivery and idempotent processing without using a production business event.
6. Alert when stream or consumer configuration drifts from the approved record.

Re-run these checks after changing stream limits, duplicate windows, retention, subjects, replicas or consumer
policies. Treat a reduction in retention or duplicate coverage as a potentially breaking operational change.

## Outage and incident handling

- If a publisher acknowledgement is uncertain, leave the outbox record retryable; do not mark it published without a valid acknowledgement.
- If the retry occurs outside the duplicate window, assume JetStream may store another copy with the same event ID.
- If a consumer outage exceeds approved retention, stop claiming complete recovery and reconcile authoritative database state against downstream state.
- If a stream reaches a discard or storage limit, stop and repair capacity or policy before replaying dead letters.
- Replay through the tenant-scoped operator API so the action remains idempotent and audited.
- Do not purge or recreate a stream during an incident without preserving the configuration, sequence and reconciliation evidence required for recovery.
