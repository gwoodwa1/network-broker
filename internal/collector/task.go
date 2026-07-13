package collector

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// TaskState is the durable lifecycle state of one target task.
type TaskState string

const (
	TaskQueued     TaskState = "queued"
	TaskLeased     TaskState = "leased"
	TaskExecuting  TaskState = "executing"
	TaskCommitting TaskState = "committing"
	TaskSucceeded  TaskState = "succeeded"
	TaskRetryWait  TaskState = "retry_wait"
	TaskFailed     TaskState = "failed"
	TaskDenied     TaskState = "denied"
	TaskCancelled  TaskState = "cancelled"
	TaskExpired    TaskState = "expired"
	TaskDeadLetter TaskState = "dead_letter"
)

var (
	ErrTaskNotFound    = errors.New("collector task not found")
	ErrLeaseHeld       = errors.New("collector task lease is held")
	ErrStaleFence      = errors.New("collector task fencing token is stale")
	ErrLeaseExpired    = errors.New("collector task lease has expired")
	ErrInvalidState    = errors.New("collector task state transition is invalid")
	ErrDuplicateCommit = errors.New("collector task already has an accepted result")
)

// Task models the authoritative state for collecting evidence from one target.
type Task struct {
	ID                  string
	TenantID            string
	ResolutionID        string
	ClaimFingerprint    string
	TargetSnapshotID    string
	TargetSnapshotHash  string
	TargetID            string
	TargetEndpoint      string
	RecipeID            string
	RecipeVersion       string
	TriggerDecisionID   string
	PlanningDecisionID  string
	ExecutionDecisionID string
	ExecutionGrantID    string
	ApprovalGrantID     string
	CompatibilityHash   string
	State               TaskState
	AttemptCount        int
	LeaseOwner          string
	LeaseExpiry         time.Time
	FencingToken        int64
	AcceptedAttemptID   string
	AcceptedEvidenceID  string
	LastError           string
}

// Lease identifies one ownership epoch. The fencing token changes every time
// an expired or available task is acquired.
type Lease struct {
	TaskID       string
	Owner        string
	FencingToken int64
	ExpiresAt    time.Time
}

// Store provides the atomic task operations that a durable job-state adapter
// must preserve. The in-memory implementation is intended for local builds and
// tests; its compare-and-set semantics map directly to a database transaction.
type Store struct {
	mu    sync.Mutex
	tasks map[string]*Task
}

func NewStore() *Store {
	return &Store{tasks: make(map[string]*Task)}
}

// Add queues a task. Existing IDs are rejected so task creation is explicit.
func (s *Store) Add(task Task) error {
	if s == nil {
		return fmt.Errorf("collector task store is nil")
	}
	if task.ID == "" || task.TargetID == "" || task.RecipeID == "" {
		return fmt.Errorf("task id, target id and recipe id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tasks[task.ID]; exists {
		return fmt.Errorf("task %q already exists", task.ID)
	}
	if task.State == "" {
		task.State = TaskQueued
	}
	if task.State != TaskQueued {
		return fmt.Errorf("%w: new task must be queued", ErrInvalidState)
	}
	taskCopy := task
	s.tasks[task.ID] = &taskCopy
	return nil
}

// Acquire atomically claims an available task and increments its fencing token.
func (s *Store) Acquire(taskID, owner string, now time.Time, duration time.Duration) (Lease, error) {
	if owner == "" {
		return Lease{}, fmt.Errorf("lease owner is required")
	}
	if now.IsZero() || duration <= 0 {
		return Lease{}, fmt.Errorf("lease time and positive duration are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	task, err := s.taskLocked(taskID)
	if err != nil {
		return Lease{}, err
	}

	switch task.State {
	case TaskQueued, TaskRetryWait:
		// Available immediately.
	case TaskLeased, TaskExecuting, TaskCommitting:
		if now.Before(task.LeaseExpiry) {
			return Lease{}, ErrLeaseHeld
		}
	default:
		return Lease{}, fmt.Errorf("%w: cannot lease task in state %q", ErrInvalidState, task.State)
	}

	task.State = TaskLeased
	task.LeaseOwner = owner
	task.LeaseExpiry = now.Add(duration)
	task.FencingToken++
	task.AttemptCount++
	task.LastError = ""
	return leaseFor(task), nil
}

// Renew extends a lease only for its current owner and fencing token.
func (s *Store) Renew(taskID, owner string, token int64, now time.Time, duration time.Duration) (Lease, error) {
	if now.IsZero() || duration <= 0 {
		return Lease{}, fmt.Errorf("lease time and positive duration are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	task, err := s.taskLocked(taskID)
	if err != nil {
		return Lease{}, err
	}
	if err := requireLease(task, owner, token, now); err != nil {
		return Lease{}, err
	}
	if task.State != TaskLeased && task.State != TaskExecuting {
		return Lease{}, fmt.Errorf("%w: cannot renew task in state %q", ErrInvalidState, task.State)
	}
	task.LeaseExpiry = now.Add(duration)
	return leaseFor(task), nil
}

func (s *Store) StartExecution(taskID, owner string, token int64, now time.Time) error {
	return s.transitionOwned(taskID, owner, token, now, TaskLeased, TaskExecuting)
}

// RecordExecutionAuthority binds the current attempt to the fresh policy
// decision and signed grant used for credential exchange.
func (s *Store) RecordExecutionAuthority(taskID, owner string, token int64, decisionID, grantID string, now time.Time) error {
	if decisionID == "" || grantID == "" {
		return fmt.Errorf("execution decision id and grant id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	task, err := s.taskLocked(taskID)
	if err != nil {
		return err
	}
	if err := requireLease(task, owner, token, now); err != nil {
		return err
	}
	if task.State != TaskExecuting {
		return fmt.Errorf("%w: cannot record execution authority in state %q", ErrInvalidState, task.State)
	}
	task.ExecutionDecisionID = decisionID
	task.ExecutionGrantID = grantID
	return nil
}

func (s *Store) BeginCommit(taskID, owner string, token int64, now time.Time) error {
	return s.transitionOwned(taskID, owner, token, now, TaskExecuting, TaskCommitting)
}

// Commit performs the authoritative exactly-one accepted-result update.
func (s *Store) Commit(taskID, owner string, token int64, attemptID, evidenceID string, now time.Time) error {
	if attemptID == "" || evidenceID == "" {
		return fmt.Errorf("attempt id and evidence id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	task, err := s.taskLocked(taskID)
	if err != nil {
		return err
	}
	if task.AcceptedAttemptID != "" {
		return ErrDuplicateCommit
	}
	if err := requireLease(task, owner, token, now); err != nil {
		return err
	}
	if task.State != TaskCommitting {
		return fmt.Errorf("%w: cannot commit task in state %q", ErrInvalidState, task.State)
	}
	task.AcceptedAttemptID = attemptID
	task.AcceptedEvidenceID = evidenceID
	task.State = TaskSucceeded
	return nil
}

// Retry releases the current attempt so it can be delivered again.
func (s *Store) Retry(taskID, owner string, token int64, now time.Time, cause error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, err := s.taskLocked(taskID)
	if err != nil {
		return err
	}
	if err := requireLease(task, owner, token, now); err != nil {
		return err
	}
	if task.State != TaskLeased && task.State != TaskExecuting && task.State != TaskCommitting {
		return fmt.Errorf("%w: cannot retry task in state %q", ErrInvalidState, task.State)
	}
	task.State = TaskRetryWait
	task.LeaseOwner = ""
	task.LeaseExpiry = time.Time{}
	if cause != nil {
		task.LastError = cause.Error()
	}
	return nil
}

// Get returns a detached snapshot so callers cannot mutate authoritative state.
func (s *Store) Get(taskID string) (Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, err := s.taskLocked(taskID)
	if err != nil {
		return Task{}, err
	}
	return *task, nil
}

// CurrentFence exposes only the authoritative ownership epoch needed by an
// execution-grant broker. It does not disclose lease ownership or task data.
func (s *Store) CurrentFence(taskID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, err := s.taskLocked(taskID)
	if err != nil {
		return 0, err
	}
	return task.FencingToken, nil
}

// VerifyCurrentAttempt is the narrow trust check used by the evidence
// assembler before it signs an envelope for the active attempt.
func (s *Store) VerifyCurrentAttempt(taskID, collectorID string, fencingToken int64, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, err := s.taskLocked(taskID)
	if err != nil {
		return err
	}
	if err := requireLease(task, collectorID, fencingToken, at); err != nil {
		return err
	}
	if task.State != TaskExecuting && task.State != TaskCommitting {
		return fmt.Errorf("%w: cannot assemble evidence in state %q", ErrInvalidState, task.State)
	}
	return nil
}

func (s *Store) transitionOwned(taskID, owner string, token int64, now time.Time, from, to TaskState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, err := s.taskLocked(taskID)
	if err != nil {
		return err
	}
	if err := requireLease(task, owner, token, now); err != nil {
		return err
	}
	if task.State != from {
		return fmt.Errorf("%w: expected state %q, got %q", ErrInvalidState, from, task.State)
	}
	task.State = to
	return nil
}

func (s *Store) taskLocked(taskID string) (*Task, error) {
	task, ok := s.tasks[taskID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrTaskNotFound, taskID)
	}
	return task, nil
}

func requireLease(task *Task, owner string, token int64, now time.Time) error {
	if task.LeaseOwner != owner || task.FencingToken != token {
		return ErrStaleFence
	}
	if now.IsZero() || !now.Before(task.LeaseExpiry) {
		return ErrLeaseExpired
	}
	return nil
}

func leaseFor(task *Task) Lease {
	return Lease{TaskID: task.ID, Owner: task.LeaseOwner, FencingToken: task.FencingToken, ExpiresAt: task.LeaseExpiry}
}
