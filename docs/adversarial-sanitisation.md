# Adversarial network-output sanitisation

Network-device output is untrusted even when its transport and evidence envelope are authentic. Device-controlled banners, descriptions, neighbour data and log text can contain terminal controls, encoded payloads or instruction-like content intended to influence an agent.

## Trusted pipeline

The collector preserves captured bytes as an immutable encrypted artefact before sanitisation. The sanitiser then creates a separately digested derivative and a versioned transformation manifest. Only a non-quarantined derivative with the required taint classification may enter the strict typed parser and evidence assembler.

The default rules:

- bound captured bytes, output bytes, JSON nesting, JSON nodes and individual strings;
- normalize text with Unicode NFKC before instruction-pattern comparison;
- remove raw terminal escape sequences and prohibited control characters;
- quarantine invalid, structurally excessive or oversized JSON rather than silently truncating it;
- quarantine instruction-like strings, encoded control sequences, long encoded tokens and abnormal character repetition;
- classify known device-controlled free-text fields as tainted;
- identify configured redactions by opaque rule position rather than recording a secret or a guessable hash of it; and
- emit deterministic retained, redacted, stripped, tainted, rejected, truncated and quarantined reason codes.

The versioned manifest contract is published as
[`schemas/adversarial-sanitisation-manifest-v1.schema.json`](schemas/adversarial-sanitisation-manifest-v1.schema.json).
It binds the captured and derivative SHA-256 digests, records an overall `clean`, `tainted` or `quarantined`
status, and identifies catalogue rules only by their opaque one-based position. The manifest is
content-addressed by the artefact store. Its digest is carried in the sanitised artefact reference and is
therefore covered by the evidence-envelope signature.

A quarantined derivative contains only `{"quarantined":true}`. Its manifest and captured parent remain available for authorised investigation, but it cannot be parsed, promoted to typed evidence or signed as accepted evidence.

Redaction and quarantine are deliberately different. Redaction replaces a configured sensitive value and
may still produce promotable typed evidence. Quarantine rejects the complete observation from typed evidence;
only the captured object, safe marker derivative and transformation manifest remain available.

## Taint propagation

The interface-state parser promotes only its exact schema and rejects unknown fields, including caller-supplied taint metadata. It independently marks `interface_name` as device-controlled and requires the sanitisation manifest to carry the matching path. Taint follows the typed observation into the signed evidence envelope, retrieval result and signed disclosure receipt.

Disclosure policy denies tainted fields by default. An actor-specific decision must explicitly allow them;
when it does, the signed receipt carries both the delivered taint paths and a mandatory consumer warning.

Taint is a warning about data origin, not a substitute for output encoding or agent-side instruction/data separation. Consumers must render tainted values as data and must never concatenate them into system prompts, tool instructions, commands or policy source.

## Rule changes and false positives

Rules are security-sensitive, versioned catalogue configuration. Changes require adversarial tests and review. Detection is deliberately conservative and can quarantine legitimate unusual text; operators should investigate through the captured artefact rather than weakening rules globally. Any future model-based classifier must be optional and advisory and must not be able to override deterministic quarantine or schema enforcement.

The current pipeline intentionally accepts only bounded artefacts. Streaming sanitisation for outputs such as
full technical-support bundles requires per-chunk manifests and a signed roll-up manifest; it is a separate
roadmap stage and must not bypass the whole-artefact size limit in the meantime.
