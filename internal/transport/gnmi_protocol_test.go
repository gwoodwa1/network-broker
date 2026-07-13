package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type protocolGNMIServer struct {
	gpb.UnimplementedGNMIServer
}

func (protocolGNMIServer) Get(ctx context.Context, _ *gpb.GetRequest) (*gpb.GetResponse, error) {
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok || first(values.Get("username")) != "collector" || first(values.Get("password")) != "secret" {
		return nil, status.Error(codes.Unauthenticated, "missing bounded device credential")
	}

	return &gpb.GetResponse{Notification: []*gpb.Notification{{Timestamp: time.Now().UnixNano()}}}, nil
}

func TestGRPCGNMIDialerPerformsVerifiedTLSProtocolExchange(t *testing.T) {
	serverCertificate, roots := gnmiTestCertificate(t)
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate},
	})))
	gpb.RegisterGNMIServer(server, protocolGNMIServer{})
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil {
			return
		}
	}()
	t.Cleanup(func() {
		server.Stop()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close gNMI test listener: %v", err)
		}
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	resolver := &credentialFixture{credential: DeviceCredential{Username: "collector", Password: "secret"}}
	adapter, err := NewGNMIAdapter([]GNMIRecipe{{
		ID: "system_get", Version: "v1", Paths: []*gpb.Path{{Elem: []*gpb.PathElem{{Name: "system"}}}},
		DataType: gpb.GetRequest_STATE, Encoding: gpb.Encoding_JSON_IETF,
	}}, resolver, GRPCGNMIDialer{}, roots, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	captured, err := adapter.Execute(context.Background(), TargetConnection{
		TargetID: "router-1", Endpoint: net.JoinHostPort("localhost", port), CredentialToken: "opaque",
		CredentialExpiry: now.Add(time.Minute), CredentialClass: "network-read",
	}, BoundedOperation{
		RecipeID: "system_get", RecipeVersion: "v1", MaximumDuration: 5 * time.Second, MaximumBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(captured.Payload) == 0 || captured.MediaType != "application/json" {
		t.Fatal("expected captured gNMI protocol response")
	}
}

func gnmiTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gNMI test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	return certificate, roots
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}

	return values[0]
}
