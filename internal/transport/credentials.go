package transport

import (
	"context"
	"crypto/tls"
)

type Protocol string

const (
	ProtocolGNMI    Protocol = "gnmi"
	ProtocolNETCONF Protocol = "netconf"
	ProtocolSSH     Protocol = "ssh"
)

// DeviceCredential exists only within the collector transport process. A
// resolver exchanges the opaque, grant-bound token for protocol credentials;
// neither task records nor evidence envelopes persist these fields.
type DeviceCredential struct {
	Username          string
	Password          string
	PrivateKeyPEM     []byte
	ClientCertificate *tls.Certificate
}

type CredentialResolver interface {
	Resolve(context.Context, string, string, string, Protocol) (DeviceCredential, error)
}
