package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
)

type credentialFixture struct {
	credential DeviceCredential
	protocol   Protocol
}

func (r *credentialFixture) Resolve(_ context.Context, _, _, _ string,
	protocol Protocol,
) (DeviceCredential, error) {
	r.protocol = protocol

	return r.credential, nil
}

type gnmiDialerFixture struct {
	tlsConfiguration *tls.Config
	maximumBytes     int
	request          *gpb.GetRequest
	response         *gpb.GetResponse
	err              error
}

func (d *gnmiDialerFixture) Dial(_ context.Context, _ string, configuration *tls.Config,
	_ DeviceCredential, maximumBytes int,
) (GNMISession, error) {
	d.tlsConfiguration = configuration
	d.maximumBytes = maximumBytes

	return d, nil
}

func (d *gnmiDialerFixture) Get(_ context.Context, request *gpb.GetRequest,
	_ ...grpc.CallOption,
) (*gpb.GetResponse, error) {
	d.request = request

	return d.response, d.err
}

func (*gnmiDialerFixture) Close() error { return nil }

func TestGNMIAdapterExecutesOnlyAllowlistedPathWithStrictTLS(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	resolver := &credentialFixture{credential: DeviceCredential{Username: "collector", Password: "secret"}}
	dialer := &gnmiDialerFixture{response: &gpb.GetResponse{
		Notification: []*gpb.Notification{{
			Timestamp: now.UnixNano(),
			Update: []*gpb.Update{{
				Path: &gpb.Path{Elem: []*gpb.PathElem{{Name: "interface"}}},
				Val:  &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{StringVal: "up"}},
			}},
		}},
	}}
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{RawSubject: []byte("test-root")})
	adapter, err := NewGNMIAdapter([]GNMIRecipe{{
		ID: "gnmi_interface_get", Version: "v1",
		Paths:    []*gpb.Path{{Elem: []*gpb.PathElem{{Name: "interfaces"}, {Name: "interface"}, {Name: "state"}}}},
		DataType: gpb.GetRequest_STATE, Encoding: gpb.Encoding_JSON_IETF,
	}}, resolver, dialer, roots, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G101 -- opaque fixture value is not a credential.
	captured, err := adapter.Execute(context.Background(), TargetConnection{
		TargetID: "router-1", Endpoint: "router-1.example:57400", CredentialToken: "opaque-grant-token",
		CredentialExpiry: now.Add(time.Minute), CredentialClass: "network-read",
	}, BoundedOperation{
		RecipeID: "gnmi_interface_get", RecipeVersion: "v1",
		MaximumDuration: time.Second, MaximumBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(captured.Payload) == 0 || resolver.protocol != ProtocolGNMI || dialer.request == nil ||
		len(dialer.request.Path) != 1 || dialer.request.Path[0].Elem[0].Name != "interfaces" ||
		captured.MediaType != "application/json" {
		t.Fatalf("unexpected bounded gNMI request or response: request=%+v captured=%+v", dialer.request, captured)
	}
	if dialer.tlsConfiguration.MinVersion != tls.VersionTLS13 ||
		dialer.tlsConfiguration.ServerName != "router-1.example" || dialer.tlsConfiguration.RootCAs != roots ||
		dialer.maximumBytes != 4096 {
		t.Fatalf("gNMI transport did not enforce strict TLS and message bounds: %+v", dialer.tlsConfiguration)
	}
}

func TestGNMIAdapterRejectsUnknownRecipeExpiryAndOversizedResponse(t *testing.T) {
	now := time.Now().UTC()
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{RawSubject: []byte("test-root")})
	resolver := &credentialFixture{credential: DeviceCredential{Username: "collector", Password: "secret"}}
	dialer := &gnmiDialerFixture{response: &gpb.GetResponse{}}
	adapter, err := NewGNMIAdapter([]GNMIRecipe{{
		ID: "allowed", Version: "v1", Paths: []*gpb.Path{{Elem: []*gpb.PathElem{{Name: "system"}}}},
	}}, resolver, dialer, roots, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	target := TargetConnection{
		TargetID: "router-1", Endpoint: "router-1.example:57400", CredentialToken: "opaque",
		CredentialExpiry: now.Add(time.Minute), CredentialClass: "network-read",
	}
	operation := BoundedOperation{
		RecipeID: "unknown", RecipeVersion: "v1", MaximumDuration: time.Second, MaximumBytes: 4096,
	}
	if _, err := adapter.Execute(context.Background(), target, operation); err == nil {
		t.Fatal("expected unknown recipe rejection")
	}
	target.CredentialExpiry = now
	operation.RecipeID = "allowed"
	if _, err := adapter.Execute(context.Background(), target, operation); err == nil {
		t.Fatal("expected expired credential rejection")
	}
	target.CredentialExpiry = now.Add(time.Minute)
	dialer.err = errors.New("received message larger than max")
	if _, err := adapter.Execute(context.Background(), target, operation); err == nil {
		t.Fatal("expected bounded receive failure")
	}
}
