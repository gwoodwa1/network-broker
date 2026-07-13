// Package operatorauth derives operator identity only from verified mTLS
// client certificates issued under a configured SPIFFE trust domain.
package operatorauth

import (
	"net/http"
	"time"

	"network_broker/internal/authctx"
	"network_broker/internal/deadletter"
	"network_broker/internal/workloadidentity"
)

var ErrUnauthenticated = workloadidentity.ErrUnauthenticated

// Authenticator accepts the repository's SPIFFE path convention:
// spiffe://<trust-domain>/tenant/<tenant>/role/outbox-operator/workload/<name>.
type Authenticator struct {
	TrustDomain string
	Now         func() time.Time
}

func (a Authenticator) Authenticate(request *http.Request) (authctx.AuthContext, error) {
	if request == nil {
		return authctx.AuthContext{}, ErrUnauthenticated
	}
	// #nosec G101 -- these constants are authorization labels, not credentials.
	verifier := workloadidentity.Authenticator{
		TrustDomain: a.TrustDomain, Now: a.Now,
		Roles: map[string]workloadidentity.RoleBinding{
			deadletter.OperatorRole: {
				Scopes:          []string{deadletter.ReadScope, deadletter.ReplayScope},
				CredentialClass: "mtls-spiffe",
			},
		},
	}

	return verifier.Authenticate(request.TLS)
}
