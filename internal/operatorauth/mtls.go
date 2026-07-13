// Package operatorauth derives operator identity only from verified mTLS
// client certificates issued under a configured SPIFFE trust domain.
package operatorauth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"network_broker/internal/authctx"
	"network_broker/internal/deadletter"
)

var ErrUnauthenticated = errors.New("verified operator client certificate is required")

// Authenticator accepts the repository's SPIFFE path convention:
// spiffe://<trust-domain>/tenant/<tenant>/role/outbox-operator/workload/<name>.
type Authenticator struct {
	TrustDomain string
	Now         func() time.Time
}

func (a Authenticator) Authenticate(request *http.Request) (authctx.AuthContext, error) {
	if request == nil || request.TLS == nil || len(request.TLS.PeerCertificates) == 0 ||
		len(request.TLS.VerifiedChains) == 0 || a.TrustDomain == "" || a.Now == nil {
		return authctx.AuthContext{}, ErrUnauthenticated
	}
	certificate := request.TLS.PeerCertificates[0]
	identity, tenant, err := operatorIdentity(certificate, a.TrustDomain)
	if err != nil {
		return authctx.AuthContext{}, ErrUnauthenticated
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	// #nosec G101 -- these constants are authorization labels, not credentials.
	actor := authctx.AuthContext{
		SubjectID: identity.String(), SPIFFEID: identity.String(), TenantID: tenant,
		Roles:           []string{deadletter.OperatorRole},
		AllowedScopes:   []string{deadletter.ReadScope, deadletter.ReplayScope},
		AuthenticatedAt: a.Now().UTC(), IdentityRevision: hex.EncodeToString(fingerprint[:]),
		CredentialClass: "mtls-spiffe",
	}
	if err := actor.Validate(); err != nil {
		return authctx.AuthContext{}, ErrUnauthenticated
	}

	return actor, nil
}

func operatorIdentity(certificate *x509.Certificate, trustDomain string) (*url.URL, string, error) {
	if certificate == nil || len(certificate.URIs) != 1 {
		return nil, "", fmt.Errorf("exactly one URI SAN is required")
	}
	identity := certificate.URIs[0]
	if identity.Scheme != "spiffe" || identity.Host != trustDomain || identity.RawQuery != "" || identity.Fragment != "" {
		return nil, "", fmt.Errorf("SPIFFE identity is outside the operator trust domain")
	}
	parts := strings.Split(strings.TrimPrefix(identity.EscapedPath(), "/"), "/")
	if len(parts) != 6 || parts[0] != "tenant" || parts[2] != "role" ||
		parts[3] != deadletter.OperatorRole || parts[4] != "workload" {
		return nil, "", fmt.Errorf("SPIFFE identity does not match the operator path convention")
	}
	tenant, err := url.PathUnescape(parts[1])
	if err != nil || invalidIdentitySegment(tenant) {
		return nil, "", fmt.Errorf("SPIFFE tenant segment is invalid")
	}
	workload, err := url.PathUnescape(parts[5])
	if err != nil || invalidIdentitySegment(workload) {
		return nil, "", fmt.Errorf("SPIFFE workload segment is invalid")
	}

	return identity, tenant, nil
}

func invalidIdentitySegment(value string) bool {
	return value == "" || len(value) > 128 || strings.ContainsAny(value, "/\\") ||
		strings.IndexFunc(value, func(char rune) bool { return unicode.IsSpace(char) || unicode.IsControl(char) }) >= 0
}
