package workloadidentity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
	"time"
)

func TestAuthenticatorDerivesIdentityOnlyFromVerifiedSPIFFECertificate(t *testing.T) {
	identity, err := url.Parse("spiffe://broker.example/tenant/tenant-a/role/collector/workload/site-1")
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{Raw: []byte("leaf-a"), URIs: []*url.URL{identity}}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	authenticator := Authenticator{
		TrustDomain: "broker.example", Now: func() time.Time { return now },
		// #nosec G101 -- credential class is an authorization label, not a credential.
		Roles: map[string]RoleBinding{"collector": {
			Scopes: []string{"tasks:execute"}, CredentialClass: "mtls-spiffe",
		}},
	}
	actor, err := authenticator.Authenticate(&tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if actor.TenantID != "tenant-a" || actor.SPIFFEID != identity.String() ||
		len(actor.Roles) != 1 || actor.Roles[0] != "collector" || actor.IdentityRevision == "" {
		t.Fatalf("unexpected authenticated context: %+v", actor)
	}
}

func TestAuthenticatorRejectsUnverifiedUnknownAndAmbiguousIdentities(t *testing.T) {
	valid, err := url.Parse("spiffe://broker.example/tenant/tenant-a/role/collector/workload/site-1")
	if err != nil {
		t.Fatal(err)
	}
	unknownRole, err := url.Parse("spiffe://broker.example/tenant/tenant-a/role/admin/workload/site-1")
	if err != nil {
		t.Fatal(err)
	}
	authenticator := Authenticator{
		TrustDomain: "broker.example", Now: time.Now,
		// #nosec G101 -- credential class is an authorization label, not a credential.
		Roles: map[string]RoleBinding{"collector": {CredentialClass: "mtls-spiffe"}},
	}
	tests := []tls.ConnectionState{
		{PeerCertificates: []*x509.Certificate{{Raw: []byte("a"), URIs: []*url.URL{valid}}}},
		{
			PeerCertificates: []*x509.Certificate{{Raw: []byte("a"), URIs: []*url.URL{unknownRole}}},
			VerifiedChains:   [][]*x509.Certificate{{{Raw: []byte("a"), URIs: []*url.URL{unknownRole}}}},
		},
		{
			PeerCertificates: []*x509.Certificate{{Raw: []byte("a"), URIs: []*url.URL{valid, unknownRole}}},
			VerifiedChains:   [][]*x509.Certificate{{{Raw: []byte("a"), URIs: []*url.URL{valid, unknownRole}}}},
		},
	}
	for index := range tests {
		if _, err := authenticator.Authenticate(&tests[index]); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("case %d: expected unauthenticated, got %v", index, err)
		}
	}
}
