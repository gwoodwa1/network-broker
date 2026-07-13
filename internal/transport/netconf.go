package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	netconfDelimiter        = "]]>]]>"
	maximumNETCONFHelloSize = 64 * 1024
)

type NETCONFRecipe struct {
	ID      string
	Version string
	Filter  string
}

type NETCONFSession interface {
	Get(context.Context, string, int64) ([]byte, error)
	Close() error
}

type NETCONFDialer interface {
	Dial(context.Context, string, DeviceCredential) (NETCONFSession, error)
}

type NETCONFAdapter struct {
	recipes     map[string]NETCONFRecipe
	credentials CredentialResolver
	dialer      NETCONFDialer
	now         func() time.Time
}

func NewNETCONFAdapter(recipes []NETCONFRecipe, resolver CredentialResolver,
	dialer NETCONFDialer, now func() time.Time,
) (*NETCONFAdapter, error) {
	if len(recipes) == 0 || resolver == nil || dialer == nil || now == nil {
		return nil, fmt.Errorf("NETCONF recipes, credential resolver, dialer and clock are required")
	}
	catalogue := make(map[string]NETCONFRecipe, len(recipes))
	for _, recipe := range recipes {
		if recipe.ID == "" || recipe.Version == "" || !validXMLFragment(recipe.Filter) {
			return nil, fmt.Errorf("NETCONF recipe identity, version and well-formed filter are required")
		}
		key := recipe.ID + "\x00" + recipe.Version
		if _, exists := catalogue[key]; exists {
			return nil, fmt.Errorf("duplicate NETCONF recipe version")
		}
		catalogue[key] = recipe
	}

	return &NETCONFAdapter{recipes: catalogue, credentials: resolver, dialer: dialer, now: now}, nil
}

func (a *NETCONFAdapter) Execute(ctx context.Context, target TargetConnection,
	operation BoundedOperation,
) (captured CapturedBytes, err error) {
	if err := validateRealTransportRequest(target, operation, a.now()); err != nil {
		return CapturedBytes{}, err
	}
	recipe, ok := a.recipes[operation.RecipeID+"\x00"+operation.RecipeVersion]
	if !ok {
		return CapturedBytes{}, fmt.Errorf("NETCONF recipe version is not allowlisted")
	}
	if _, _, err := net.SplitHostPort(target.Endpoint); err != nil {
		return CapturedBytes{}, fmt.Errorf("NETCONF endpoint must be a host and port")
	}
	credential, err := a.credentials.Resolve(ctx, target.CredentialToken,
		target.TargetID, target.CredentialClass, ProtocolNETCONF)
	if err != nil {
		return CapturedBytes{}, fmt.Errorf("resolve NETCONF credential: %w", err)
	}
	if err := validateSSHCredential(credential); err != nil {
		return CapturedBytes{}, err
	}
	executionCtx, cancel := context.WithTimeout(ctx, operation.MaximumDuration)
	defer cancel()
	session, err := a.dialer.Dial(executionCtx, target.Endpoint, credential)
	if err != nil {
		return CapturedBytes{}, fmt.Errorf("dial NETCONF target: %w", err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close NETCONF session: %w", closeErr))
		}
	}()
	payload, err := session.Get(executionCtx, recipe.Filter, operation.MaximumBytes)
	if err != nil {
		return CapturedBytes{}, fmt.Errorf("execute NETCONF get: %w", err)
	}
	if int64(len(payload)) > operation.MaximumBytes {
		return CapturedBytes{}, fmt.Errorf("NETCONF response exceeds %d byte limit", operation.MaximumBytes)
	}
	payload = bytes.Clone(payload)

	return CapturedBytes{
		TargetID: target.TargetID, Payload: payload, Digest: sha256.Sum256(payload),
		MediaType: "application/xml", CapturedAt: a.now().UTC(),
	}, nil
}

type SSHNETCONFDialer struct {
	HostKeyCallback ssh.HostKeyCallback
}

func (d SSHNETCONFDialer) Dial(ctx context.Context, endpoint string,
	credential DeviceCredential,
) (NETCONFSession, error) {
	if d.HostKeyCallback == nil {
		return nil, fmt.Errorf("verified NETCONF SSH host-key callback is required")
	}
	client, err := dialSSHClient(ctx, endpoint, credential, d.HostKeyCallback)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create NETCONF SSH session: %w", err), client.Close())
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open NETCONF stdin: %w", err), session.Close(), client.Close())
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open NETCONF stdout: %w", err), session.Close(), client.Close())
	}
	if err := session.RequestSubsystem("netconf"); err != nil {
		return nil, errors.Join(fmt.Errorf("start NETCONF subsystem: %w", err), session.Close(), client.Close())
	}
	netconf := &sshNETCONFSession{
		client: client, session: session, stdin: stdin, stdout: bufio.NewReader(stdout),
	}
	if err := netconf.exchangeHello(ctx); err != nil {
		return nil, errors.Join(err, netconf.Close())
	}

	return netconf, nil
}

type sshNETCONFSession struct {
	client    *ssh.Client
	session   *ssh.Session
	stdin     io.WriteCloser
	stdout    *bufio.Reader
	messageID atomic.Uint64
}

func (s *sshNETCONFSession) exchangeHello(ctx context.Context) error {
	if _, err := readNETCONFMessage(ctx, s.stdout, maximumNETCONFHelloSize); err != nil {
		return fmt.Errorf("read NETCONF server hello: %w", err)
	}
	clientHello := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>` +
		`<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>` + netconfDelimiter
	if _, err := io.WriteString(s.stdin, clientHello); err != nil {
		return fmt.Errorf("write NETCONF client hello: %w", err)
	}

	return nil
}

func (s *sshNETCONFSession) Get(ctx context.Context, filter string, maximumBytes int64) ([]byte, error) {
	messageID := strconv.FormatUint(s.messageID.Add(1), 10)
	rpc := `<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="` + messageID +
		`"><get><filter type="subtree">` + filter + `</filter></get></rpc>` + netconfDelimiter
	if _, err := io.WriteString(s.stdin, rpc); err != nil {
		return nil, fmt.Errorf("write NETCONF RPC: %w", err)
	}
	response, err := readNETCONFMessage(ctx, s.stdout, maximumBytes)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		XMLName   xml.Name
		MessageID string `xml:"message-id,attr"`
	}
	if err := xml.Unmarshal(response, &envelope); err != nil {
		return nil, fmt.Errorf("decode NETCONF RPC reply: %w", err)
	}
	if envelope.XMLName.Local != "rpc-reply" || envelope.MessageID != messageID {
		return nil, fmt.Errorf("NETCONF RPC reply binding does not match request")
	}
	if bytes.Contains(response, []byte("<rpc-error")) || bytes.Contains(response, []byte(":rpc-error")) {
		return nil, fmt.Errorf("NETCONF target returned an RPC error")
	}

	return response, nil
}

func (s *sshNETCONFSession) Close() error {
	return errors.Join(s.session.Close(), s.client.Close())
}

func readNETCONFMessage(ctx context.Context, reader *bufio.Reader, maximumBytes int64) ([]byte, error) {
	if maximumBytes <= 0 {
		return nil, fmt.Errorf("positive NETCONF message limit is required")
	}
	message := make([]byte, 0, min(maximumBytes, 4096))
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		value, err := reader.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read NETCONF message: %w", err)
		}
		message = append(message, value)
		if int64(len(message)) > maximumBytes+int64(len(netconfDelimiter)) {
			return nil, fmt.Errorf("NETCONF response exceeds %d byte limit", maximumBytes)
		}
		if bytes.HasSuffix(message, []byte(netconfDelimiter)) {
			return bytes.Clone(message[:len(message)-len(netconfDelimiter)]), nil
		}
	}
}

func validXMLFragment(fragment string) bool {
	if strings.TrimSpace(fragment) == "" || len(fragment) > 64*1024 || strings.Contains(fragment, netconfDelimiter) {
		return false
	}
	decoder := xml.NewDecoder(strings.NewReader("<filter-root>" + fragment + "</filter-root>"))
	for {
		if _, err := decoder.Token(); errors.Is(err, io.EOF) {
			return true
		} else if err != nil {
			return false
		}
	}
}
