package operatorauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestAuthenticatorDerivesTenantAndOperatorScopesFromVerifiedSPIFFEIdentity(t *testing.T) {
	identity, err := url.Parse("spiffe://broker.example/tenant/tenant-a/role/outbox-operator/workload/operator-a")
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		Raw: []byte("certificate"), SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ignored"},
		URIs: []*url.URL{identity},
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://broker.example/v1/operations/dead-letters", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	authenticator := Authenticator{TrustDomain: "broker.example", Now: func() time.Time {
		return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	}}
	actor, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	if actor.TenantID != "tenant-a" || actor.SubjectID != identity.String() || actor.IdentityRevision == "" ||
		len(actor.AllowedScopes) != 2 {
		t.Fatalf("unexpected operator identity: %+v", actor)
	}
}

func TestAuthenticatorRejectsUnverifiedOrMalformedIdentity(t *testing.T) {
	authenticator := Authenticator{TrustDomain: "broker.example", Now: time.Now}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://broker.example", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(request); err == nil {
		t.Fatal("expected missing TLS identity to fail")
	}
	identity, err := url.Parse("spiffe://other.example/tenant/tenant-a/role/outbox-operator/workload/operator-a")
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{Raw: []byte("certificate"), URIs: []*url.URL{identity}}
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	if _, err := authenticator.Authenticate(request); err == nil {
		t.Fatal("expected foreign trust domain to fail")
	}
}
