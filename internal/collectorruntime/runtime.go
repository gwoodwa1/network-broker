// Package collectorruntime constructs the collector exclusively from durable
// authority and storage adapters. Protocol, policy and credential boundaries
// remain explicit dependencies so deployment code cannot silently substitute
// local scaffolds.
package collectorruntime

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"time"

	"network_broker/internal/artefacts"
	"network_broker/internal/authctx"
	"network_broker/internal/collector"
	"network_broker/internal/evidence"
	"network_broker/internal/keyprovider"
	"network_broker/internal/parsing"
	"network_broker/internal/sanitise"
	"network_broker/internal/transport"
)

type Config struct {
	Identity          authctx.AuthContext
	TransportName     string
	CollectorVersion  string
	AssemblerVersion  string
	NormaliserVersion string
	LeaseDuration     time.Duration
	GrantTTL          time.Duration
	MaximumDuration   time.Duration
	MaximumBytes      int64
	EvidenceValidity  time.Duration
	Sanitiser         sanitise.Transformer
	Parser            parsing.InterfaceStateParser
}

type Dependencies struct {
	Database    *sql.DB
	Blobs       artefacts.BlobStore
	Signing     keyprovider.SigningProvider
	Encryption  keyprovider.EncryptionProvider
	Transport   transport.Adapter
	Authorizer  collector.ExecutionAuthorizer
	GrantIssuer collector.GrantIssuer
	Credentials collector.CredentialExchanger
}

type Runtime struct {
	identity  authctx.AuthContext
	tasks     *collector.PostgresRepository
	envelopes *evidence.PostgresRepository
	worker    collector.Worker
}

// New constructs a collector with PostgreSQL task/evidence/artefact metadata
// and caller-supplied production boundaries. There is no memory-store fallback.
func New(configuration Config, dependencies Dependencies) (*Runtime, error) {
	if err := validateConfiguration(configuration, dependencies); err != nil {
		return nil, err
	}
	tasks, err := collector.NewPostgresRepository(dependencies.Database)
	if err != nil {
		return nil, err
	}
	metadata, err := artefacts.NewPostgresRepository(dependencies.Database)
	if err != nil {
		return nil, err
	}
	artefactStore, err := artefacts.NewDurableStore(metadata, dependencies.Blobs)
	if err != nil {
		return nil, err
	}
	envelopes, err := evidence.NewPostgresRepository(dependencies.Database)
	if err != nil {
		return nil, err
	}
	assembler, err := evidence.NewAssemblerWithProvider(configuration.AssemblerVersion,
		dependencies.Signing, tasks)
	if err != nil {
		return nil, err
	}
	sink, err := evidence.NewPipelineSinkWithRepositories(
		artefactStore, configuration.Sanitiser, configuration.Parser, assembler,
		configuration.TransportName, dependencies.Encryption, envelopes,
		configuration.CollectorVersion, configuration.NormaliserVersion,
		configuration.EvidenceValidity, time.Now)
	if err != nil {
		return nil, err
	}
	worker := collector.Worker{
		ID: configuration.Identity.SPIFFEID, Tasks: tasks, Transport: dependencies.Transport,
		Sink: sink, Authorizer: dependencies.Authorizer, GrantIssuer: dependencies.GrantIssuer,
		Credentials: dependencies.Credentials, LeaseDuration: configuration.LeaseDuration,
		GrantTTL: configuration.GrantTTL, MaximumDuration: configuration.MaximumDuration,
		MaximumBytes: configuration.MaximumBytes, Now: time.Now,
	}

	return &Runtime{
		identity: configuration.Identity, tasks: tasks, envelopes: envelopes, worker: worker,
	}, nil
}

// Run executes one durable task only when its tenant matches the verified
// workload identity used to construct the runtime.
func (r *Runtime) Run(ctx context.Context, taskID string) error {
	if r == nil || r.tasks == nil || taskID == "" {
		return fmt.Errorf("production collector runtime and task id are required")
	}
	task, err := r.tasks.GetContext(ctx, taskID)
	if err != nil {
		return err
	}
	if task.TenantID != r.identity.TenantID {
		return fmt.Errorf("collector workload tenant does not match task tenant")
	}

	return r.worker.Run(ctx, taskID)
}

func (r *Runtime) Task(ctx context.Context, taskID string) (collector.Task, error) {
	if r == nil || r.tasks == nil {
		return collector.Task{}, fmt.Errorf("production collector runtime is required")
	}

	return r.tasks.GetContext(ctx, taskID)
}

func (r *Runtime) Evidence(ctx context.Context, evidenceID string) (evidence.EvidenceEnvelope, error) {
	if r == nil || r.envelopes == nil {
		return evidence.EvidenceEnvelope{}, fmt.Errorf("production collector runtime is required")
	}

	return r.envelopes.GetForTenant(ctx, r.identity.TenantID, evidenceID)
}

func validateConfiguration(configuration Config, dependencies Dependencies) error {
	if err := validateIdentity(configuration.Identity); err != nil {
		return err
	}
	if err := validateRuntimeBounds(configuration); err != nil {
		return err
	}

	return validateDependencies(dependencies)
}

func validateIdentity(identity authctx.AuthContext) error {
	if err := identity.Validate(); err != nil {
		return fmt.Errorf("validate collector workload identity: %w", err)
	}
	if identity.SPIFFEID == "" || identity.IdentityRevision == "" ||
		!slices.Contains(identity.Roles, "collector") ||
		!slices.Contains(identity.AllowedScopes, "tasks:execute") {
		return fmt.Errorf("verified collector SPIFFE identity and execution scope are required")
	}

	return nil
}

func validateRuntimeBounds(configuration Config) error {
	if configuration.TransportName == "" || configuration.CollectorVersion == "" ||
		configuration.AssemblerVersion == "" || configuration.NormaliserVersion == "" ||
		configuration.Sanitiser == nil || configuration.Parser.ID == "" || configuration.Parser.Version == "" ||
		configuration.LeaseDuration <= 0 || configuration.GrantTTL <= 0 ||
		configuration.MaximumDuration <= 0 || configuration.MaximumBytes <= 0 ||
		configuration.EvidenceValidity <= 0 {
		return fmt.Errorf("collector identities, versions and positive bounds are required")
	}

	return nil
}

func validateDependencies(dependencies Dependencies) error {
	if dependencies.Database == nil || dependencies.Blobs == nil || dependencies.Signing == nil ||
		dependencies.Encryption == nil || dependencies.Transport == nil || dependencies.Authorizer == nil ||
		dependencies.GrantIssuer == nil || dependencies.Credentials == nil {
		return fmt.Errorf("durable storage, cryptographic, transport, policy and credential dependencies are required")
	}

	return nil
}
