package collector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"network_broker/internal/grants"
	"network_broker/internal/transport"
)

// CapturedSink persists an attempt's captured object before the fenced task
// commit. A rejected commit may therefore leave an orphan for later cleanup.
type CapturedSink interface {
	WriteCaptured(context.Context, Task, Lease, transport.CapturedBytes) (attemptID, evidenceID string, err error)
}

// ExecutionRequest is evaluated after the collector owns a fenced lease.
type ExecutionRequest struct {
	CollectorID     string
	Task            Task
	FencingToken    int64
	MaximumDuration time.Duration
	MaximumBytes    int64
	EvaluatedAt     time.Time
}

// ExecutionAuthorization is a fresh policy decision with server-owned limits.
type ExecutionAuthorization struct {
	DecisionID      string
	MaximumDuration time.Duration
	MaximumBytes    int64
}

type ExecutionAuthorizer interface {
	AuthorizeExecution(context.Context, ExecutionRequest) (ExecutionAuthorization, error)
}

type GrantIssuer interface {
	Issue(grants.ExecutionGrant) (grants.ExecutionGrant, error)
}

type CredentialExchanger interface {
	Exchange(grants.ExecutionGrant, grants.ExchangeRequest) (grants.SessionCredential, error)
}

// Worker executes one bounded task attempt.
type Worker struct {
	ID              string
	Tasks           *Store
	Transport       transport.Adapter
	Sink            CapturedSink
	Authorizer      ExecutionAuthorizer
	GrantIssuer     GrantIssuer
	Credentials     CredentialExchanger
	LeaseDuration   time.Duration
	GrantTTL        time.Duration
	MaximumDuration time.Duration
	MaximumBytes    int64
	Now             func() time.Time
}

//nolint:cyclop,funlen,gocognit // Run deliberately keeps the security-sensitive attempt sequence linear and auditable.
func (w Worker) Run(ctx context.Context, taskID string) error {
	if w.ID == "" || w.Tasks == nil || w.Transport == nil || w.Sink == nil {
		return fmt.Errorf("collector id, task store, transport and captured sink are required")
	}
	if w.LeaseDuration <= 0 || w.MaximumDuration <= 0 || w.MaximumBytes <= 0 {
		return fmt.Errorf("positive lease, duration and response byte limits are required")
	}
	if w.Authorizer == nil || w.GrantIssuer == nil || w.Credentials == nil || w.GrantTTL <= 0 {
		return fmt.Errorf("execution authorizer, grant issuer, credential broker and positive grant ttl are required")
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}

	lease, err := w.Tasks.Acquire(taskID, w.ID, now(), w.LeaseDuration)
	if err != nil {
		return err
	}
	if err := w.Tasks.StartExecution(taskID, w.ID, lease.FencingToken, now()); err != nil {
		return err
	}
	task, err := w.Tasks.Get(taskID)
	if err != nil {
		return err
	}

	authorization, err := w.Authorizer.AuthorizeExecution(ctx, ExecutionRequest{
		CollectorID: w.ID, Task: task, FencingToken: lease.FencingToken,
		MaximumDuration: w.MaximumDuration, MaximumBytes: w.MaximumBytes, EvaluatedAt: now(),
	})
	if err != nil {
		return w.failAttempt(taskID, lease, now(), fmt.Errorf("re-authorize task %q: %w", taskID, err))
	}
	if authorization.DecisionID == "" || authorization.MaximumDuration <= 0 || authorization.MaximumBytes <= 0 ||
		authorization.MaximumDuration > w.MaximumDuration || authorization.MaximumBytes > w.MaximumBytes {
		err := fmt.Errorf("execution authorization returned invalid or expanded limits")
		return w.failAttempt(taskID, lease, now(), err)
	}
	issuedAt := now()
	expiresAt := issuedAt.Add(w.GrantTTL)
	if lease.ExpiresAt.Before(expiresAt) {
		expiresAt = lease.ExpiresAt
	}
	if expiresAt.Before(issuedAt.Add(authorization.MaximumDuration)) {
		err := fmt.Errorf("lease and grant validity do not cover authorised execution duration")
		return w.failAttempt(taskID, lease, now(), err)
	}
	grantID, err := randomID("grant")
	if err != nil {
		return err
	}
	nonce, err := randomID("nonce")
	if err != nil {
		return err
	}
	grant, err := w.GrantIssuer.Issue(grants.ExecutionGrant{
		GrantID: grantID, Nonce: nonce, TenantID: task.TenantID, CollectorSPIFFEID: w.ID,
		ResolutionID: task.ResolutionID, TaskID: task.ID, TargetSnapshotID: task.TargetSnapshotID,
		TargetSnapshotDigest: task.TargetSnapshotHash, TargetID: task.TargetID,
		RecipeID: task.RecipeID, RecipeVersion: task.RecipeVersion, FencingToken: lease.FencingToken,
		TriggerDecisionID: task.TriggerDecisionID, PlanningDecisionID: task.PlanningDecisionID,
		ExecutionDecisionID: authorization.DecisionID, ApprovalGrantID: task.ApprovalGrantID,
		NotBefore: issuedAt, ExpiresAt: expiresAt, MaximumDuration: authorization.MaximumDuration,
		MaximumResponseBytes: authorization.MaximumBytes, CredentialClass: "network-read", SingleUse: true,
	})
	if err != nil {
		return w.failAttempt(taskID, lease, now(), fmt.Errorf("issue execution grant for task %q: %w", taskID, err))
	}
	if err := w.Tasks.RecordExecutionAuthority(taskID, w.ID, lease.FencingToken, authorization.DecisionID, grant.GrantID, now()); err != nil {
		return err
	}
	task, err = w.Tasks.Get(taskID)
	if err != nil {
		return err
	}
	credential, err := w.Credentials.Exchange(grant, grants.ExchangeRequest{
		PresentingSPIFFEID: w.ID, TaskID: task.ID, TargetID: task.TargetID,
		RecipeID: task.RecipeID, RecipeVersion: task.RecipeVersion,
		FencingToken: lease.FencingToken, Now: now(),
	})
	if err != nil {
		return w.failAttempt(taskID, lease, now(), fmt.Errorf("exchange execution grant for task %q: %w", taskID, err))
	}
	if credential.Token == "" || credential.GrantID != grant.GrantID || credential.TargetID != task.TargetID ||
		credential.RecipeID != task.RecipeID || credential.FencingToken != lease.FencingToken {
		err := fmt.Errorf("credential broker returned mismatched credential")
		return w.failAttempt(taskID, lease, now(), err)
	}

	executionCtx, cancel := context.WithTimeout(ctx, authorization.MaximumDuration)
	defer cancel()
	captured, err := w.Transport.Execute(executionCtx, transport.TargetConnection{
		TargetID: task.TargetID, CredentialToken: credential.Token,
		CredentialExpiry: credential.ExpiresAt, CredentialClass: credential.CredentialClass,
	}, transport.BoundedOperation{
		RecipeID:        task.RecipeID,
		RecipeVersion:   task.RecipeVersion,
		MaximumDuration: authorization.MaximumDuration,
		MaximumBytes:    authorization.MaximumBytes,
	})
	if err != nil {
		return w.failAttempt(taskID, lease, now(), fmt.Errorf("execute task %q: %w", taskID, err))
	}
	if int64(len(captured.Payload)) > w.MaximumBytes {
		err = fmt.Errorf("transport returned %d bytes above the %d byte limit", len(captured.Payload), w.MaximumBytes)
		return w.failAttempt(taskID, lease, now(), err)
	}

	attemptID, evidenceID, err := w.Sink.WriteCaptured(ctx, task, lease, captured)
	if err != nil {
		return w.failAttempt(taskID, lease, now(), fmt.Errorf("persist captured evidence for task %q: %w", taskID, err))
	}
	if err := w.Tasks.BeginCommit(taskID, w.ID, lease.FencingToken, now()); err != nil {
		return err
	}
	if err := w.Tasks.Commit(taskID, w.ID, lease.FencingToken, attemptID, evidenceID, now()); err != nil {
		return fmt.Errorf("commit task %q: %w", taskID, err)
	}
	return nil
}

func (w Worker) failAttempt(taskID string, lease Lease, failedAt time.Time, cause error) error {
	if retryErr := w.Tasks.Retry(taskID, w.ID, lease.FencingToken, failedAt, cause); retryErr != nil {
		return errors.Join(cause, fmt.Errorf("return task %q to retry wait: %w", taskID, retryErr))
	}

	return cause
}

func randomID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate %s id: %w", prefix, err)
	}
	return prefix + "-" + hex.EncodeToString(b), nil
}

// MemorySink provides a deterministic local sink. A durable implementation
// will replace it when artefact storage is introduced.
type MemorySink struct{}

func (MemorySink) WriteCaptured(_ context.Context, task Task, lease Lease, captured transport.CapturedBytes) (attemptID, evidenceID string, err error) {
	if len(captured.Payload) == 0 {
		return "", "", fmt.Errorf("captured payload is empty")
	}
	attemptID = fmt.Sprintf("attempt-%s-%d", task.ID, lease.FencingToken)
	evidenceID = fmt.Sprintf("evidence-%s-%x", task.ID, captured.Digest[:8])
	return attemptID, evidenceID, nil
}
