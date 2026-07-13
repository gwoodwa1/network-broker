# Threat model

## Scope and security objective

The broker lets an authenticated workload obtain narrowly defined network facts without giving the requesting agent device credentials or arbitrary command capability. The primary objective is to preserve the authority, tenant, target, recipe, execution and disclosure chain for every accepted observation.

This model covers the gateway, policy and approval services, resolution state, collector, credential exchange, network transports, artefact stores and evidence retrieval. Model behaviour and prompt safety outside the broker are upstream responsibilities.

## Protected assets

- Device credentials, workload private keys and KMS/HSM key material.
- Captured and sanitised network data.
- Target snapshots, tenant ownership and inventory identifiers.
- Signed policy bundles, decisions, approvals and execution grants.
- Artefact lineage, lifecycle state, evidence envelopes and disclosure receipts.
- Fencing tokens and authoritative task state.

## Trust boundaries

1. An agent crosses the gateway boundary using a verified workload or user identity.
2. The gateway crosses the policy boundary with server-derived tenant, scope and limits.
3. A collector crosses the task boundary only after acquiring a leased fencing token.
4. The collector crosses the credential boundary using a signed, target-bound execution grant.
5. A transport crosses the device boundary with a short-lived credential resolved from an opaque token.
6. Captured bytes cross the parser boundary into an untrusted/sandboxed parsing domain.
7. Evidence crosses the retrieval boundary only after a fresh actor-specific disclosure decision.

## Principal threats and controls

| Threat | Required controls | Residual risk |
|---|---|---|
| Caller forges tenant or role | Derive identity from a certificate in a verified mTLS chain; require one SPIFFE URI SAN under an allowlisted trust domain and role path | CA or workload issuer compromise |
| Agent requests arbitrary device operations | Resolve only exact recipe ID and version from a server-owned catalogue; gNMI paths, NETCONF filters and SSH commands never come from task input | Malicious or incorrectly reviewed catalogue entry |
| Queued work executes after authority changes | Re-evaluate signed active policy immediately after acquiring the fenced lease; bind decision and bundle digests into execution provenance | Incorrect policy or stale inventory classification |
| Approval is replayed or used for another target | Persist tenant, recipe, target-set hash, expiry, maximum uses and policy decision; consume transactionally and idempotently for one task | Compromised approver or overly broad target set |
| Stale collector commits | Compare lease owner and monotonic fencing token at every state transition and accepted-result commit | Database compromise or incorrectly implemented external task repository |
| Credential theft | Keep device secrets behind the credential boundary; tasks and grants contain only opaque, short-lived tokens; never log credential structures | Collector memory compromise during execution |
| Device impersonation | gNMI requires TLS 1.3, explicit roots and hostname verification; SSH and NETCONF require a non-nil verified host-key callback | Compromised trust root, incorrect known-host provisioning or first-use trust outside the broker |
| Oversized or hanging response | Enforce policy and recipe duration/byte limits, gRPC receive limits, bounded NETCONF framing and bounded SSH streams | Protocol-library or decompression amplification below the application boundary |
| Evidence or policy tampering | Content digests, immutable metadata, signed envelopes, immutable signed bundles and append-only decisions/events | Database administrator or KMS administrator collusion; external ledger export remains future work |
| Disclosure receipt tampering or signature stripping | Bind tenant, actor, evidence, policy lineage and delivered-payload digest into a domain-separated signature set; enforce minimum and required-algorithm verification policy | Durable receipt repository and external transparency anchoring remain future work |
| Cross-tenant read | Include tenant in every durable lookup and make cross-tenant absence indistinguishable from missing | Query introduced without tenant predicate |
| Signing alias rotation invalidates history | Resolve aliases to immutable KMS key ARNs before signing and persist that ARN with the signature | Deleting historical KMS keys before evidence retention expires |
| Unsafe deletion | Separate immutable metadata from versioned lifecycle state; block deletion during retention or legal hold; require request and confirmation transitions | External object-deletion worker is not yet implemented |

## Assumptions

- PostgreSQL roles prevent application callers from bypassing service APIs or disabling append-only triggers.
- Object storage denies public access, enforces TLS and uses the configured tenant encryption key or an equally strict bucket policy.
- KMS key policies bind signing and encryption operations to the intended workload, tenant and purpose.
- Inventory snapshots supply canonical endpoints and target classifications.
- Catalogue changes receive security review equivalent to code changes.
- Captured bytes are hostile until sanitisation and parsing complete.

## Out of scope and open review items

- Security of the model provider, agent prompt and upstream orchestration environment.
- Physical device compromise and malicious device firmware.
- Independent penetration testing and cryptographic design review.
- Production SPIRE deployment, CA operations and recovery exercises.
- Vendor lab qualification for every supported gNMI, NETCONF and SSH implementation.
- Tamper-evident external audit-ledger export.
- Standardized post-quantum signing-provider qualification and formal algorithm creation/retirement policy.
- The lifecycle deletion and orphan-reconciliation worker.

Review this model whenever a protocol recipe, identity convention, policy schema, durable store or trust root changes.
