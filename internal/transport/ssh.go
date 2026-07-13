package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

type SSHRecipe struct {
	ID      string
	Version string
	Command string
}

type SSHSession interface {
	Run(context.Context, string, int64) ([]byte, error)
	Close() error
}

type SSHDialer interface {
	Dial(context.Context, string, DeviceCredential) (SSHSession, error)
}

type SSHAdapter struct {
	recipes     map[string]SSHRecipe
	credentials CredentialResolver
	dialer      SSHDialer
	now         func() time.Time
}

func NewSSHAdapter(recipes []SSHRecipe, resolver CredentialResolver, dialer SSHDialer,
	now func() time.Time,
) (*SSHAdapter, error) {
	if len(recipes) == 0 || resolver == nil || dialer == nil || now == nil {
		return nil, fmt.Errorf("SSH recipes, credential resolver, dialer and clock are required")
	}
	catalogue := make(map[string]SSHRecipe, len(recipes))
	for _, recipe := range recipes {
		if recipe.ID == "" || recipe.Version == "" || invalidCatalogueCommand(recipe.Command) {
			return nil, fmt.Errorf("SSH recipe identity, version and safe command are required")
		}
		key := recipe.ID + "\x00" + recipe.Version
		if _, exists := catalogue[key]; exists {
			return nil, fmt.Errorf("duplicate SSH recipe version")
		}
		catalogue[key] = recipe
	}

	return &SSHAdapter{recipes: catalogue, credentials: resolver, dialer: dialer, now: now}, nil
}

func (a *SSHAdapter) Execute(ctx context.Context, target TargetConnection,
	operation BoundedOperation,
) (captured CapturedBytes, err error) {
	if err := validateRealTransportRequest(target, operation, a.now()); err != nil {
		return CapturedBytes{}, err
	}
	recipe, ok := a.recipes[operation.RecipeID+"\x00"+operation.RecipeVersion]
	if !ok {
		return CapturedBytes{}, fmt.Errorf("SSH recipe version is not allowlisted")
	}
	if _, _, err := net.SplitHostPort(target.Endpoint); err != nil {
		return CapturedBytes{}, fmt.Errorf("SSH endpoint must be a host and port")
	}
	credential, err := a.credentials.Resolve(ctx, target.CredentialToken,
		target.TargetID, target.CredentialClass, ProtocolSSH)
	if err != nil {
		return CapturedBytes{}, fmt.Errorf("resolve SSH credential: %w", err)
	}
	if err := validateSSHCredential(credential); err != nil {
		return CapturedBytes{}, err
	}
	executionCtx, cancel := context.WithTimeout(ctx, operation.MaximumDuration)
	defer cancel()
	session, err := a.dialer.Dial(executionCtx, target.Endpoint, credential)
	if err != nil {
		return CapturedBytes{}, fmt.Errorf("dial SSH target: %w", err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close SSH session: %w", closeErr))
		}
	}()
	payload, err := session.Run(executionCtx, recipe.Command, operation.MaximumBytes)
	if err != nil {
		return CapturedBytes{}, fmt.Errorf("execute SSH recipe: %w", err)
	}
	if int64(len(payload)) > operation.MaximumBytes {
		return CapturedBytes{}, fmt.Errorf("SSH response exceeds %d byte limit", operation.MaximumBytes)
	}
	payload = append([]byte(nil), payload...)

	return CapturedBytes{
		TargetID: target.TargetID, Payload: payload, Digest: sha256.Sum256(payload), CapturedAt: a.now().UTC(),
	}, nil
}

type SSHNetworkDialer struct {
	HostKeyCallback ssh.HostKeyCallback
}

func (d SSHNetworkDialer) Dial(ctx context.Context, endpoint string,
	credential DeviceCredential,
) (SSHSession, error) {
	if d.HostKeyCallback == nil {
		return nil, fmt.Errorf("verified SSH host-key callback is required")
	}
	client, err := dialSSHClient(ctx, endpoint, credential, d.HostKeyCallback)
	if err != nil {
		return nil, err
	}

	return &sshNetworkSession{client: client}, nil
}

func dialSSHClient(ctx context.Context, endpoint string, credential DeviceCredential,
	hostKeyCallback ssh.HostKeyCallback,
) (*ssh.Client, error) {
	if hostKeyCallback == nil {
		return nil, fmt.Errorf("verified SSH host-key callback is required")
	}
	authentication, err := sshAuthentication(credential)
	if err != nil {
		return nil, err
	}
	networkConnection, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("connect SSH socket: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := networkConnection.SetDeadline(deadline); err != nil {
			return nil, errors.Join(fmt.Errorf("bound SSH socket deadline: %w", err), networkConnection.Close())
		}
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(networkConnection, endpoint, &ssh.ClientConfig{
		User: credential.Username, Auth: authentication, HostKeyCallback: hostKeyCallback,
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("authenticate and verify SSH target: %w", err), networkConnection.Close())
	}

	return ssh.NewClient(clientConnection, channels, requests), nil
}

type sshNetworkSession struct {
	client *ssh.Client
}

func (s *sshNetworkSession) Run(ctx context.Context, command string, maximumBytes int64) (payload []byte, err error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("create SSH command session: %w", err)
	}
	defer func() {
		closeErr := session.Close()
		if closeErr != nil && !errors.Is(closeErr, io.EOF) {
			err = errors.Join(err, fmt.Errorf("close SSH command session: %w", closeErr))
		}
	}()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open SSH stdout: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("open SSH stderr: %w", err)
	}
	if err := session.Start(command); err != nil {
		return nil, fmt.Errorf("start SSH command: %w", err)
	}
	return readSSHCommand(ctx, session, stdout, stderr, maximumBytes)
}

type sshReadResult struct {
	payload []byte
	err     error
	stdout  bool
}

func readSSHCommand(ctx context.Context, session *ssh.Session, stdout, stderr io.Reader,
	maximumBytes int64,
) ([]byte, error) {
	results := make(chan sshReadResult, 2)
	readBounded := func(reader io.Reader, isStdout bool) {
		payload, readErr := io.ReadAll(io.LimitReader(reader, maximumBytes+1))
		results <- sshReadResult{payload: payload, err: readErr, stdout: isStdout}
	}
	go readBounded(stdout, true)
	go readBounded(stderr, false)
	wait := make(chan error, 1)
	go func() { wait <- session.Wait() }()
	var stdoutPayload, stderrPayload []byte
	for range 2 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if result.err != nil {
				return nil, fmt.Errorf("read SSH response: %w", result.err)
			}
			if int64(len(result.payload)) > maximumBytes {
				return nil, fmt.Errorf("SSH response exceeds %d byte limit", maximumBytes)
			}
			if result.stdout {
				stdoutPayload = result.payload
			} else {
				stderrPayload = result.payload
			}
		}
	}
	if int64(len(stdoutPayload)+len(stderrPayload)) > maximumBytes {
		return nil, fmt.Errorf("SSH combined response exceeds %d byte limit", maximumBytes)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-wait:
		if err != nil {
			return nil, fmt.Errorf("SSH command failed: %w", err)
		}
	}

	return bytes.Clone(stdoutPayload), nil
}

func (s *sshNetworkSession) Close() error { return s.client.Close() }

func sshAuthentication(credential DeviceCredential) ([]ssh.AuthMethod, error) {
	if credential.Password != "" && len(credential.PrivateKeyPEM) != 0 {
		return nil, fmt.Errorf("SSH credential must use exactly one authentication method")
	}
	if credential.Password != "" {
		return []ssh.AuthMethod{ssh.Password(credential.Password)}, nil
	}
	if len(credential.PrivateKeyPEM) != 0 {
		signer, err := ssh.ParsePrivateKey(credential.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse SSH private key: %w", err)
		}

		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}

	return nil, fmt.Errorf("SSH password or private key is required")
}

func validateSSHCredential(credential DeviceCredential) error {
	if credential.Username == "" {
		return fmt.Errorf("SSH username is required")
	}
	_, err := sshAuthentication(credential)

	return err
}

func invalidCatalogueCommand(command string) bool {
	trimmed := strings.TrimSpace(command)
	fields := strings.Fields(trimmed)
	if len(fields) == 0 || (fields[0] != "show" && fields[0] != "display") ||
		strings.ContainsAny(trimmed, ";|><&`$\\") {
		return true
	}

	return len(command) > 4096 ||
		strings.IndexFunc(command, func(character rune) bool {
			return character == '\r' || character == '\n' || unicode.IsControl(character)
		}) >= 0
}
