// Package workloadidentity derives authorization context exclusively from
// certificate chains already verified by a mutually authenticated TLS server.
package workloadidentity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"network_broker/internal/authctx"
)

var ErrUnauthenticated = errors.New("verified SPIFFE workload certificate is required")

type RoleBinding struct {
	Scopes          []string
	DataClearances  []string
	CredentialClass string
}

type Authenticator struct {
	TrustDomain string
	Roles       map[string]RoleBinding
	Now         func() time.Time
}

// Authenticate accepts only a leaf certificate present in a verified chain.
// The URI convention is spiffe://<domain>/tenant/<tenant>/role/<role>/workload/<name>.
func (a Authenticator) Authenticate(state *tls.ConnectionState) (authctx.AuthContext, error) {
	if state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 ||
		a.TrustDomain == "" || len(a.Roles) == 0 || a.Now == nil {
		return authctx.AuthContext{}, ErrUnauthenticated
	}
	leaf := state.PeerCertificates[0]
	if !leafInVerifiedChain(leaf, state.VerifiedChains) {
		return authctx.AuthContext{}, ErrUnauthenticated
	}
	identity, tenant, role, err := parseIdentity(leaf, a.TrustDomain)
	if err != nil {
		return authctx.AuthContext{}, ErrUnauthenticated
	}
	binding, ok := a.Roles[role]
	if !ok || binding.CredentialClass == "" {
		return authctx.AuthContext{}, ErrUnauthenticated
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	actor := authctx.AuthContext{
		SubjectID: identity.String(), SPIFFEID: identity.String(), TenantID: tenant,
		Roles: []string{role}, AllowedScopes: append([]string(nil), binding.Scopes...),
		DataClearances:  append([]string(nil), binding.DataClearances...),
		CredentialClass: binding.CredentialClass, AuthenticatedAt: a.Now().UTC(),
		IdentityRevision: hex.EncodeToString(fingerprint[:]),
	}
	if err := actor.Validate(); err != nil {
		return authctx.AuthContext{}, ErrUnauthenticated
	}

	return actor, nil
}

func parseIdentity(certificate *x509.Certificate, trustDomain string) (
	identity *url.URL, tenant, role string, err error,
) {
	if certificate == nil || len(certificate.URIs) != 1 {
		return nil, "", "", fmt.Errorf("exactly one URI SAN is required")
	}
	identity = certificate.URIs[0]
	if identity.Scheme != "spiffe" || identity.Host != trustDomain || identity.RawQuery != "" || identity.Fragment != "" {
		return nil, "", "", fmt.Errorf("SPIFFE identity is outside the trust domain")
	}
	parts := strings.Split(strings.TrimPrefix(identity.EscapedPath(), "/"), "/")
	if len(parts) != 6 || parts[0] != "tenant" || parts[2] != "role" || parts[4] != "workload" {
		return nil, "", "", fmt.Errorf("SPIFFE identity does not match the workload path convention")
	}
	tenant, err = url.PathUnescape(parts[1])
	if err != nil || invalidSegment(tenant) {
		return nil, "", "", fmt.Errorf("SPIFFE tenant segment is invalid")
	}
	role, err = url.PathUnescape(parts[3])
	if err != nil || invalidSegment(role) {
		return nil, "", "", fmt.Errorf("SPIFFE role segment is invalid")
	}
	workload, err := url.PathUnescape(parts[5])
	if err != nil || invalidSegment(workload) {
		return nil, "", "", fmt.Errorf("SPIFFE workload segment is invalid")
	}

	return identity, tenant, role, nil
}

func leafInVerifiedChain(leaf *x509.Certificate, chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		if len(chain) > 0 && chain[0].Equal(leaf) {
			return true
		}
	}

	return false
}

func invalidSegment(value string) bool {
	return value == "" || len(value) > 128 || strings.ContainsAny(value, "/\\") ||
		strings.IndexFunc(value, func(char rune) bool { return unicode.IsSpace(char) || unicode.IsControl(char) }) >= 0
}
