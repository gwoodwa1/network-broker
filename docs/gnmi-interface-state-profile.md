# gNMI interface-state normalisation profile

The `gnmi_interface_get` v1 evidence path uses a deliberately narrow
normalisation profile. The transport preserves the complete protobuf JSON
`GetResponse` as the captured artefact. `normalise.GNMIInterfaceState` then
combines hostile-output inspection and deterministic schema normalisation into
one transformation whose manifest binds the captured digest directly to the
canonical derivative digest.

## Accepted response shape

The profile accepts:

- exactly one successful gNMI notification;
- a positive nanosecond timestamp representable from 1970 through year 9999;
- between one and the configured bounded maximum of updates, never more than
  256;
- structured `PathElem` paths only;
- an empty or `openconfig` origin and no response-supplied target;
- exactly one `interface[name=...]` key across the response;
- one `oper-status` leaf and an optional matching `name` leaf; and
- scalar string, ASCII, JSON or JSON-IETF string values.

Deletes, legacy string paths, extra path keys, multiple interfaces, duplicate
state, unrecognised leaves, non-string values and unknown operational states
fail closed. The first qualified recipe must request only the exact
OpenConfig `name` and `oper-status` leaves; it must not request the complete
interface state subtree.

OpenConfig state is mapped to the broker v1 enum as follows:

| Input | Normalised value |
|---|---|
| `UP`, `up` | `up` |
| `DOWN`, `down`, `DORMANT`, `NOT_PRESENT`, `LOWER_LAYER_DOWN` | `down` |
| `UNKNOWN`, `unknown`, `TESTING` | `unknown` |

Any other value is rejected pending an explicit versioned profile change.

## Hostile-data boundary

Before protobuf decoding, the complete response passes through the bounded
adversarial JSON sanitiser. The profile requires `name` fields to be classified
as device-controlled free text, so instruction-like, encoded, structurally
hostile or abnormally repetitive interface identifiers are quarantined before
normalisation. A quarantined marker and its manifest may be persisted, but it
cannot enter the parser or evidence assembler.

For an accepted response, the canonical derivative contains exactly:

```json
{
  "schema_version": "v1",
  "interface_name": "Ethernet1",
  "operational_state": "up",
  "observed_at": "2026-07-14T12:00:00Z"
}
```

The combined manifest retains the captured input digest and sanitisation
outcomes, replaces the output digest with the canonical derivative digest and
maps taint to `$/interface_name`. The existing strict interface-state parser
then independently checks the derivative digest, media type, taint, identifier
grammar, timestamp and state enum before evidence signing.

## Qualification limits

This profile closes the code-level mismatch between real gNMI protobuf output
and the broker's typed interface observation. It is not vendor qualification.
Production support still requires named network OS/release fixtures proving the
exact response paths, timestamp behaviour, encoding, cancellation and size
bounds. A vendor response outside this profile must fail closed until reviewed
and added through a new profile version.
