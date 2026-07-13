package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
)

const maximumGRPCMessageBytes int64 = 16 * 1024 * 1024

type GNMIRecipe struct {
	ID       string
	Version  string
	Paths    []*gpb.Path
	DataType gpb.GetRequest_DataType
	Encoding gpb.Encoding
}

type GNMIClient interface {
	Get(context.Context, *gpb.GetRequest, ...grpc.CallOption) (*gpb.GetResponse, error)
}

type GNMISession interface {
	GNMIClient
	io.Closer
}

type GNMIDialer interface {
	Dial(context.Context, string, *tls.Config, DeviceCredential, int) (GNMISession, error)
}

type GNMIAdapter struct {
	recipes     map[string]GNMIRecipe
	credentials CredentialResolver
	dialer      GNMIDialer
	rootCAs     *x509.CertPool
	now         func() time.Time
}

func NewGNMIAdapter(recipes []GNMIRecipe, credentialResolver CredentialResolver,
	dialer GNMIDialer, rootCAs *x509.CertPool, now func() time.Time,
) (*GNMIAdapter, error) {
	if len(recipes) == 0 || credentialResolver == nil || dialer == nil || rootCAs == nil || now == nil {
		return nil, fmt.Errorf("gNMI recipes, credential resolver, dialer, trust roots and clock are required")
	}
	catalogue := make(map[string]GNMIRecipe, len(recipes))
	for _, recipe := range recipes {
		if recipe.ID == "" || recipe.Version == "" || len(recipe.Paths) == 0 {
			return nil, fmt.Errorf("gNMI recipe identity, version and paths are required")
		}
		key := recipe.ID + "\x00" + recipe.Version
		if _, exists := catalogue[key]; exists {
			return nil, fmt.Errorf("duplicate gNMI recipe version")
		}
		catalogue[key] = cloneGNMIRecipe(recipe)
	}

	return &GNMIAdapter{
		recipes: catalogue, credentials: credentialResolver, dialer: dialer,
		rootCAs: rootCAs, now: now,
	}, nil
}

func (a *GNMIAdapter) Execute(ctx context.Context, target TargetConnection,
	operation BoundedOperation,
) (captured CapturedBytes, err error) {
	if err := validateRealTransportRequest(target, operation, a.now()); err != nil {
		return CapturedBytes{}, err
	}
	if operation.MaximumBytes > maximumGRPCMessageBytes {
		return CapturedBytes{}, fmt.Errorf("gNMI response limit exceeds transport maximum")
	}
	recipe, ok := a.recipes[operation.RecipeID+"\x00"+operation.RecipeVersion]
	if !ok {
		return CapturedBytes{}, fmt.Errorf("gNMI recipe version is not allowlisted")
	}
	host, _, err := net.SplitHostPort(target.Endpoint)
	if err != nil || host == "" {
		return CapturedBytes{}, fmt.Errorf("gNMI endpoint must be a host and port")
	}
	deviceCredential, err := a.credentials.Resolve(ctx, target.CredentialToken,
		target.TargetID, target.CredentialClass, ProtocolGNMI)
	if err != nil {
		return CapturedBytes{}, fmt.Errorf("resolve gNMI credential: %w", err)
	}
	if deviceCredential.Username == "" || deviceCredential.Password == "" {
		return CapturedBytes{}, fmt.Errorf("gNMI username and password are required")
	}
	tlsConfiguration := &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: a.rootCAs, ServerName: host,
	}
	if deviceCredential.ClientCertificate != nil {
		tlsConfiguration.Certificates = []tls.Certificate{*deviceCredential.ClientCertificate}
	}
	executionCtx, cancel := context.WithTimeout(ctx, operation.MaximumDuration)
	defer cancel()
	session, err := a.dialer.Dial(executionCtx, target.Endpoint, tlsConfiguration,
		deviceCredential, int(operation.MaximumBytes))
	if err != nil {
		return CapturedBytes{}, fmt.Errorf("dial gNMI target: %w", err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close gNMI session: %w", closeErr))
		}
	}()
	response, err := session.Get(executionCtx, &gpb.GetRequest{
		Path: recipe.Paths, Type: recipe.DataType, Encoding: recipe.Encoding,
	})
	if err != nil {
		return CapturedBytes{}, fmt.Errorf("execute gNMI get: %w", err)
	}
	payload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(response)
	if err != nil {
		return CapturedBytes{}, fmt.Errorf("encode gNMI response: %w", err)
	}
	if int64(len(payload)) > operation.MaximumBytes {
		return CapturedBytes{}, fmt.Errorf("gNMI response exceeds %d byte limit", operation.MaximumBytes)
	}
	capturedAt := a.now().UTC()

	return CapturedBytes{
		TargetID: target.TargetID, Payload: payload, Digest: sha256.Sum256(payload), CapturedAt: capturedAt,
	}, nil
}

type GRPCGNMIDialer struct{}

func (GRPCGNMIDialer) Dial(_ context.Context, endpoint string, tlsConfiguration *tls.Config,
	deviceCredential DeviceCredential, maximumBytes int,
) (GNMISession, error) {
	if tlsConfiguration == nil || tlsConfiguration.RootCAs == nil || tlsConfiguration.ServerName == "" ||
		tlsConfiguration.MinVersion < tls.VersionTLS13 || maximumBytes <= 0 {
		return nil, fmt.Errorf("strict gNMI TLS and positive response limit are required")
	}
	connection, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfiguration.Clone())),
		grpc.WithPerRPCCredentials(basicRPCCredentials{
			username: deviceCredential.Username, password: deviceCredential.Password,
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maximumBytes)),
	)
	if err != nil {
		return nil, fmt.Errorf("create gNMI client: %w", err)
	}

	return &grpcGNMISession{GNMIClient: gpb.NewGNMIClient(connection), connection: connection}, nil
}

type grpcGNMISession struct {
	GNMIClient
	connection *grpc.ClientConn
}

func (s *grpcGNMISession) Close() error {
	return s.connection.Close()
}

type basicRPCCredentials struct {
	username string
	password string
}

func (c basicRPCCredentials) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return map[string]string{"username": c.username, "password": c.password}, nil
}

func (basicRPCCredentials) RequireTransportSecurity() bool { return true }

func cloneGNMIRecipe(recipe GNMIRecipe) GNMIRecipe {
	cloned := recipe
	cloned.Paths = make([]*gpb.Path, len(recipe.Paths))
	for index, path := range recipe.Paths {
		cloned.Paths[index] = &gpb.Path{Target: path.GetTarget(), Origin: path.GetOrigin()}
		for _, element := range path.GetElem() {
			keys := make(map[string]string, len(element.GetKey()))
			for key, value := range element.GetKey() {
				keys[key] = value
			}
			cloned.Paths[index].Elem = append(cloned.Paths[index].Elem,
				&gpb.PathElem{Name: element.GetName(), Key: keys})
		}
	}

	return cloned
}

func validateRealTransportRequest(target TargetConnection, operation BoundedOperation, now time.Time) error {
	if target.TargetID == "" || target.Endpoint == "" || target.CredentialToken == "" ||
		target.CredentialClass == "" || target.CredentialExpiry.IsZero() {
		return fmt.Errorf("complete target identity, endpoint and bounded credential are required")
	}
	if !now.Before(target.CredentialExpiry) {
		return fmt.Errorf("bounded target credential has expired")
	}
	if operation.RecipeID == "" || operation.RecipeVersion == "" ||
		operation.MaximumDuration <= 0 || operation.MaximumBytes <= 0 {
		return fmt.Errorf("complete recipe version and positive transport limits are required")
	}

	return nil
}
