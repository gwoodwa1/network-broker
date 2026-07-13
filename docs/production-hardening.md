# Production hardening

This document defines deployment requirements. Passing unit tests does not make a deployment production-ready.

## Identity and TLS

- Terminate TLS 1.3 with client-certificate verification at the service that constructs `AuthContext`.
- Accept SPIFFE identities only from configured trust domains and exact role bindings. Do not copy tenant or role values from headers, request bodies or unverified certificate fields.
- Automate workload certificate issuance, short expiry, rotation and revocation through SPIRE or an equivalent system.
- Separate gateway, collector, migration, policy-administration and lifecycle-worker identities and database roles.
- Store device TLS roots and SSH known-host data as reviewed, versioned deployment configuration. Never enable `InsecureSkipVerify`, `ssh.InsecureIgnoreHostKey`, trust-on-first-use or plaintext protocol fallback.

## Key custody

- Configure `KMSSigningProvider` by purpose using aliases, but grant signing permission only to the intended workload. The provider records immutable key ARNs in signed objects.
- Retain disabled historical signing keys for verification until every dependent evidence and audit retention period has expired. Test rotation and recovery before deployment.
- Configure signature-set policy independently for creation and verification. During a dual-signing migration, require every mandated algorithm and reject stripped, duplicate, unknown or invalid signature entries.
- Treat post-quantum signatures and long-lived data confidentiality as separate migrations. Qualify standardized providers, message-size limits, latency and failure behaviour before requiring a new algorithm in production.
- Configure `KMSEncryptionProvider` by tenant and purpose. Align the resolved ARN with S3 SSE-KMS configuration or enforce an equivalent bucket policy; recording an ARN in metadata alone does not encrypt an object.
- Deny key deletion, alias changes and policy changes outside a dual-controlled administrative path. Alert on disabled keys, unexpected ARN resolution and verification failures.
- Execute and retain evidence from the [key rotation runbook](key-rotation.md) before production activation or retirement.

## Policy and approvals

- Sign policy bundles outside the runtime workload. Store and activate bundles using separate administrative authority.
- Treat bundle ID and version as immutable. Roll back by activating a previously signed version, never by editing stored JSON.
- Ensure every production execution and disclosure uses `BundleEngine`; the local `Evaluator` is a scaffold only.
- Require approval expiry, bounded uses, tenant, recipe, target-set digest and originating policy decision. Approval consumption must occur in the same authority sequence as execution grant issuance.

## Network transports

- Populate endpoints only from immutable target snapshots. Reject endpoints received from agent requests.
- Keep recipes read-only and exact-versioned. Review gNMI paths, NETCONF subtree filters and SSH commands for data sensitivity and worst-case response size.
- Use separate collector pools and credential classes for gNMI, NETCONF and SSH where practical.
- gNMI requires TLS 1.3, explicit roots, hostname/IP verification and a bounded gRPC receive size.
- NETCONF advertises only base 1.0 framing and implements `<get>` only. Do not add `<edit-config>`, actions or arbitrary RPC bodies to this read-only adapter.
- SSH requires a verified host-key callback backed by managed known-host records. Recipes cannot contain newlines or control characters.
- Qualify each network OS and release in a lab for authentication, certificate behaviour, response bounds, cancellation and parser compatibility before enabling its recipe.

## Data and runtime

- Apply checksum-verified migrations through a dedicated migration identity before application rollout.
- Restrict direct mutation of governance, evidence and lifecycle tables; retain append-only triggers and audit their presence.
- Use private S3-compatible endpoints, conditional writes, versioning/object lock where required and explicit public-access blocks.
- Run collectors without root privileges, with a read-only filesystem, a minimal network egress allowlist and no access to control-plane signing credentials.
- Set CPU, memory, process, connection and concurrency limits. Alert on repeated bounded-response failures as potential device or denial-of-service events.
- Export secret-safe structured logs and audit events to a separately administered, retention-controlled sink.
- Record and continuously verify the deployment-specific [JetStream delivery contract](jetstream-operations.md), including duplicate window, retention, limits and durable-consumer recovery behavior.

## Adversarial device output

- Treat rule versions as reviewed catalogue configuration. Do not let requests or device output select patterns, limits, free-text fields or quarantine behaviour.
- Alert on quarantine rates by recipe and qualified device release without logging captured values.
- Preserve captured quarantine parents under the appropriate access class and retention policy; expose them only through a separately authorised investigation path.
- Require strict schema parsers to reject unknown fields and caller-supplied taint metadata. Propagate schema-derived taint through evidence and disclosure.
- Render tainted fields as data. Never concatenate device-controlled values into prompts, commands, policy source or tool instructions.
- Keep any probabilistic or LLM classifier advisory and unable to override deterministic bounds, quarantine or schema rejection.

## Release evidence

Before promotion, retain the commit SHA and results for race tests, strict lint, `gosec`, `govulncheck`, migration tests, protocol conformance tests, image builds and the independent security assessment. Record all exceptions with an owner and expiry.
