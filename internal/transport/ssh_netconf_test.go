package transport

import (
	"bufio"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type sshDialerFixture struct {
	command string
	payload []byte
	err     error
}

func (d *sshDialerFixture) Dial(context.Context, string, DeviceCredential) (SSHSession, error) {
	return d, nil
}

func (d *sshDialerFixture) Run(_ context.Context, command string, _ int64) ([]byte, error) {
	d.command = command

	return d.payload, d.err
}

func (*sshDialerFixture) Close() error { return nil }

type netconfDialerFixture struct {
	filter  string
	payload []byte
	err     error
}

func (d *netconfDialerFixture) Dial(context.Context, string, DeviceCredential) (NETCONFSession, error) {
	return d, nil
}

func (d *netconfDialerFixture) Get(_ context.Context, filter string, _ int64) ([]byte, error) {
	d.filter = filter

	return d.payload, d.err
}

func (*netconfDialerFixture) Close() error { return nil }

func TestSSHAdapterUsesCatalogueCommandAndOpaqueCredentialResolver(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	resolver := &credentialFixture{credential: DeviceCredential{Username: "operator", Password: "secret"}}
	dialer := &sshDialerFixture{payload: []byte("Ethernet1 is up")}
	adapter, err := NewSSHAdapter([]SSHRecipe{{
		ID: "vendor_cli_show_interface", Version: "v1", Command: "show interface Ethernet1",
	}}, resolver, dialer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	captured, err := adapter.Execute(context.Background(), transportTarget(now), BoundedOperation{
		RecipeID: "vendor_cli_show_interface", RecipeVersion: "v1",
		MaximumDuration: time.Second, MaximumBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dialer.command != "show interface Ethernet1" || string(captured.Payload) != "Ethernet1 is up" ||
		resolver.protocol != ProtocolSSH {
		t.Fatalf("SSH execution escaped catalogue boundary: command=%q captured=%q", dialer.command, captured.Payload)
	}
	if _, err := NewSSHAdapter([]SSHRecipe{{ID: "bad", Version: "v1", Command: "show clock\nreload"}},
		resolver, dialer, time.Now); err == nil {
		t.Fatal("expected multiline SSH command rejection")
	}
	if _, err := NewSSHAdapter([]SSHRecipe{{ID: "bad", Version: "v1", Command: "reload"}},
		resolver, dialer, time.Now); err == nil {
		t.Fatal("expected non-read-only SSH command rejection")
	}
}

func TestNETCONFAdapterUsesReadOnlyCatalogueFilter(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	resolver := &credentialFixture{credential: DeviceCredential{Username: "operator", Password: "secret"}}
	dialer := &netconfDialerFixture{payload: []byte(`<rpc-reply message-id="1"><data/></rpc-reply>`)}
	filter := `<interfaces xmlns="http://openconfig.net/yang/interfaces"><interface><state/></interface></interfaces>`
	adapter, err := NewNETCONFAdapter([]NETCONFRecipe{{
		ID: "netconf_interface_get", Version: "v1", Filter: filter,
	}}, resolver, dialer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	captured, err := adapter.Execute(context.Background(), transportTarget(now), BoundedOperation{
		RecipeID: "netconf_interface_get", RecipeVersion: "v1",
		MaximumDuration: time.Second, MaximumBytes: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dialer.filter != filter || len(captured.Payload) == 0 || resolver.protocol != ProtocolNETCONF {
		t.Fatalf("NETCONF execution escaped catalogue boundary: filter=%q", dialer.filter)
	}
	if _, err := NewNETCONFAdapter([]NETCONFRecipe{{
		ID: "bad", Version: "v1", Filter: `<interfaces>]]>]]></interfaces>`,
	}}, resolver, dialer, time.Now); err == nil {
		t.Fatal("expected NETCONF framing injection rejection")
	}
}

func TestConcreteSSHDialersRequireHostKeyVerification(t *testing.T) {
	credential := DeviceCredential{Username: "operator", Password: "secret"}
	if _, err := (SSHNetworkDialer{}).Dial(context.Background(), "127.0.0.1:22", credential); err == nil {
		t.Fatal("expected SSH dialer without host verification to fail")
	}
	if _, err := (SSHNETCONFDialer{}).Dial(context.Background(), "127.0.0.1:830", credential); err == nil {
		t.Fatal("expected NETCONF dialer without host verification to fail")
	}
}

func TestReadNETCONFMessageEnforcesFramingAndBounds(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(`<rpc-reply message-id="1"/>` + netconfDelimiter))
	payload, err := readNETCONFMessage(context.Background(), reader, 64)
	if err != nil || string(payload) != `<rpc-reply message-id="1"/>` {
		t.Fatalf("unexpected NETCONF frame: %q error=%v", payload, err)
	}
	reader = bufio.NewReader(strings.NewReader(strings.Repeat("x", 80) + netconfDelimiter))
	if _, err := readNETCONFMessage(context.Background(), reader, 16); err == nil {
		t.Fatal("expected NETCONF bound rejection")
	}
	reader = bufio.NewReader(strings.NewReader("unterminated"))
	if _, err := readNETCONFMessage(context.Background(), reader, 64); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("expected framing read failure, got %v", err)
	}
}

func transportTarget(now time.Time) TargetConnection {
	// #nosec G101 -- opaque fixture value is not a credential.
	return TargetConnection{
		TargetID: "router-1", Endpoint: "router-1.example:22", CredentialToken: "opaque-token",
		CredentialExpiry: now.Add(time.Minute), CredentialClass: "network-read",
	}
}
