# Key rotation operations

This runbook covers signing-key and captured-artefact encryption-key rotation. They are separate operations:
signing rotation preserves authenticity and historical verification, while encryption rotation preserves
confidentiality and access to retained artefacts. An opaque key reference is provenance, not proof that an
operator has completed either procedure.

## Invariants

- New signatures use the newly activated immutable key reference.
- Records created before rotation continue to verify for their full retention period.
- Verification resolves the exact historical key reference stored in the signed record, never the current alias.
- A signing key is not deleted while any retained evidence, grant, policy bundle or receipt depends on it.
- New captured artefacts use the newly activated tenant-and-purpose encryption reference.
- Old artefacts remain readable under their historical storage encryption until deletion or an audited re-encryption procedure completes.
- Rotation never edits an existing signed envelope, immutable artefact manifest or historical key reference.

## Signing-key rotation

### Prepare

1. Inventory every signing purpose, provider, current alias, resolved immutable reference, algorithm and retention period.
2. Create and policy-bind the replacement key without changing the active alias.
3. Confirm that the signing workload can sign with the replacement and that verifier workloads can resolve both old and new immutable references.
4. Verify representative historical evidence envelopes, execution grants, policy bundles and disclosure receipts using the old reference.
5. For an algorithm migration, configure verification to accept the old and new algorithms before enabling dual signing. Do not weaken the minimum-signature policy during the transition.

### Activate and verify

1. Move the purpose alias or provider configuration to the replacement key through the dual-controlled administrative path.
2. Resolve the alias and record the resulting immutable reference in the change record.
3. Create one canary record for each affected signing purpose.
4. Confirm each canary contains the new immutable reference and verifies under the production verification policy.
5. Re-verify retained records created with the old reference.
6. Monitor signing errors, verification errors, unexpected alias resolution and signature-policy failures before expanding rollout.

### Roll back

If canary creation or verification fails, stop new work for the affected purpose and restore the previous alias or provider configuration. Verify a newly created canary uses the restored immutable reference. Do not delete either key or rewrite records created during the attempted rotation.

### Retire

Disable a historical key for new signatures only after all creators use the replacement. Keep verification capability until the last dependent record has expired and all legal holds have cleared. Deletion requires evidence from the retention inventory, a successful historical-verification sample and dual approval.

## Encryption-key rotation

1. Inventory the tenant, purpose, storage location, current alias and resolved immutable encryption reference.
2. Create the replacement key and apply the required KMS and object-store policies before activation.
3. Write and read a canary object under the new key using the same workload and storage policy as production.
4. Activate the tenant-and-purpose reference for new captures and confirm new artefact metadata records the new reference.
5. Read representative retained artefacts written under every still-supported historical key.
6. Decide explicitly whether old objects remain under historical encryption or require re-encryption. Re-encryption is a separate audited storage operation and must preserve logical bytes, content digests, immutable lineage and legal holds.
7. Do not rewrite the historical `EncryptionKeyRef`; it records the key selected when the artefact was captured. Record later storage re-encryption in a separate operational audit record.
8. Retain or disable old decrypt capability according to artefact retention and legal-hold requirements. Never schedule key deletion ahead of the last dependent object.

## Evidence to retain

- Change identifier, approvers, operator identity and timestamps.
- Alias values and immutable references before and after activation.
- Algorithms and signature-set policy before and after activation.
- Canary record identifiers and verification results.
- Historical verification and artefact read samples.
- Rollback result, if used.
- Earliest safe retirement and deletion dates for replaced keys.

The repository tests exercise immutable-reference resolution, new-key selection and historical verification.
Deployment owners must additionally test their real KMS/HSM policies, outage behavior, throttling and recovery.
