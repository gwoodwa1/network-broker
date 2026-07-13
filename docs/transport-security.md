# Read-only transport security

Production transport adapters implement the same narrow `transport.Adapter` contract. They receive an endpoint from a trusted target snapshot, an opaque short-lived credential token and an exact catalogue recipe version.

## gNMI

`GNMIAdapter` resolves only server-owned protobuf paths. `GRPCGNMIDialer` requires TLS 1.3, explicit trust roots, hostname verification, per-RPC credentials and a maximum gRPC receive size. Responses are encoded deterministically as protobuf JSON and checked again against the policy byte limit.

## NETCONF

`NETCONFAdapter` supports read-only `<get>` with a catalogue-owned, well-formed subtree filter. The concrete dialer uses the SSH `netconf` subsystem, requires verified host keys, advertises NETCONF base 1.0 only, binds replies to generated message IDs and bounds hello and RPC framing. Configuration edits and arbitrary RPC bodies are intentionally absent.

## SSH

`SSHAdapter` runs only a fixed catalogue command beginning with the read-only `show` or `display` verbs. Catalogue validation rejects shell/control metacharacters, empty, oversized, multiline or control-character commands. The concrete dialer requires verified host keys and exactly one broker-supplied authentication method. Standard output and error are drained under a combined bound; only successful standard output becomes captured evidence.

## Qualification status

The repository includes protocol-level gNMI TLS testing and deterministic conformance tests for all three adapters. Real network operating systems vary in protocol and authentication behaviour. A recipe is not production-supported until it has passed the vendor/release lab matrix described in [production hardening](production-hardening.md).
