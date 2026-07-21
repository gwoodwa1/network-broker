# External security review package

This package is the entry point for an independent reviewer. Repository maintainers must not mark the independent-review backlog item complete based on self-review.

## Review scope

Prioritise these components:

1. SPIFFE/mTLS derivation in `internal/workloadidentity`, resolution creation
   and status, planning and operator route wiring.
2. KMS alias resolution, signature construction and historical verification in `internal/keyprovider`.
3. Policy bundle signing, activation, decision provenance and approval consumption.
4. Lease/fencing and exactly-one accepted-result state transitions.
5. gNMI, NETCONF and SSH recipe isolation, credential lifetime, trust verification, cancellation and response bounds.
6. Captured/sanitised artefact separation, digest verification, lifecycle transitions and tenant predicates.
7. Evidence signing and retrieval-time disclosure decisions.

## Questions for the reviewer

- Can any unverified string become a tenant, actor, collector or workload identity?
- Can a caller influence a device path, RPC body or command outside a reviewed recipe?
- Can policy activation, approval consumption, grant exchange or evidence acceptance be raced or replayed?
- Can alias rotation, key disablement or deletion make historical evidence unverifiable without detection?
- Can a malicious device bypass response limits, hold resources after cancellation or inject trusted parser output?
- Can one tenant infer another tenant's artefact, approval, policy decision or dead-letter data?
- Does resolution-status authentication, response shaping, error behavior or
  timing expose cross-tenant workflow existence or internal authority fields?
- Can resolution creation be replayed under another actor/tenant, canonicalize
  two distinct meanings to one digest, omit provenance from the transactional
  event or exceed documented claim/target/request bounds?
- Can a database, object-store or queue partial failure produce accepted evidence without complete provenance?
- Are logs, metrics, traces, errors or crash dumps capable of exposing credentials or captured bytes?

## Required evidence

- Architecture and data-flow diagrams with deployed trust boundaries.
- Current threat model and production-hardening configuration.
- Policy bundle and recipe catalogue used during assessment.
- SPIFFE trust bundles, role mappings and certificate lifecycle procedures without private keys.
- KMS key policies, alias/rotation procedure and deletion controls.
- PostgreSQL role grants, migration ledger and trigger inventory.
- Object-store encryption, retention and public-access policies.
- Protocol lab matrix covering supported vendors and releases.
- CI results, SBOM, vulnerability results and container provenance.
- Fault-injection results for interruption, retry, fencing, rotation and store corruption.

## Completion record

An independent assessment should produce a dated report containing reviewer identity, scope, commit SHA, environment, findings, severity, evidence, remediation owner and retest status. Keep this section open until every critical or high finding is fixed or formally risk-accepted by an authorised owner.
