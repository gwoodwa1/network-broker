package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"network_broker/internal/artefacts"
	"network_broker/internal/collector"
	"network_broker/internal/evidence"
	"network_broker/internal/grants"
	"network_broker/internal/parsing"
	"network_broker/internal/policy"
	"network_broker/internal/sanitise"
	"network_broker/internal/transport"
)

type result struct {
	TaskID             string              `json:"task_id"`
	State              collector.TaskState `json:"state"`
	FencingToken       int64               `json:"fencing_token"`
	AcceptedAttemptID  string              `json:"accepted_attempt_id"`
	AcceptedEvidenceID string              `json:"accepted_evidence_id"`
}

type catalogueAuthorizer struct{}

func (catalogueAuthorizer) AuthorizeExecution(_ context.Context, request collector.ExecutionRequest) (collector.ExecutionAuthorization, error) {
	decision, err := (policy.Evaluator{}).Evaluate(request.Task.RecipeID, "lab")
	if err != nil {
		return collector.ExecutionAuthorization{}, err
	}
	if !decision.Allow || decision.RequiresApproval {
		return collector.ExecutionAuthorization{}, fmt.Errorf("execution policy denied recipe %q", request.Task.RecipeID)
	}
	durationMS, err := strconv.ParseInt(decision.Obligations["max_duration_ms"], 10, 64)
	if err != nil {
		return collector.ExecutionAuthorization{}, fmt.Errorf("invalid policy duration obligation: %w", err)
	}
	maximumBytes, err := strconv.ParseInt(decision.Obligations["max_response_bytes"], 10, 64)
	if err != nil {
		return collector.ExecutionAuthorization{}, fmt.Errorf("invalid policy byte obligation: %w", err)
	}
	maximumDuration := time.Duration(durationMS) * time.Millisecond
	if request.MaximumDuration < maximumDuration {
		maximumDuration = request.MaximumDuration
	}
	if request.MaximumBytes < maximumBytes {
		maximumBytes = request.MaximumBytes
	}
	return collector.ExecutionAuthorization{DecisionID: decision.DecisionID, MaximumDuration: maximumDuration, MaximumBytes: maximumBytes}, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is a local collector-process scaffold. Durable queue and artefact-store
// adapters can replace the in-memory implementations without changing Worker.
//
//nolint:funlen // Keeping the demo wiring together makes its end-to-end security flow directly inspectable.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("collector", flag.ContinueOnError)
	flags.SetOutput(stderr)
	collectorID := flags.String("collector-id", "collector-local", "authenticated collector identity")
	taskID := flags.String("task-id", "task-local", "target task identifier")
	targetID := flags.String("target-id", "target-local", "resolved target identifier")
	recipeID := flags.String("recipe-id", "gnmi_interface_get", "trusted catalogue recipe identifier")
	recipeVersion := flags.String("recipe-version", "v1", "trusted catalogue recipe version")
	leaseDuration := flags.Duration("lease-duration", 30*time.Second, "task lease duration")
	maximumDuration := flags.Duration("max-duration", 10*time.Second, "maximum transport duration")
	maximumBytes := flags.Int64("max-response-bytes", 1024*1024, "maximum captured response size")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *leaseDuration <= 0 || *maximumDuration <= 0 || *maximumBytes <= 0 {
		fmt.Fprintln(stderr, "collect task: positive lease, duration and response byte limits are required")
		return 1
	}

	store := collector.NewStore()
	if err := store.Add(collector.Task{
		ID: *taskID, TenantID: "tenant-local", ResolutionID: "resolution-local", ClaimFingerprint: "claim-local",
		TargetSnapshotID: "snapshot-local", TargetSnapshotHash: "sha256:local",
		TargetID: *targetID, RecipeID: *recipeID, RecipeVersion: *recipeVersion,
		TriggerDecisionID: "trigger-local", PlanningDecisionID: "planning-local",
		CompatibilityHash: "compatibility-local",
	}); err != nil {
		fmt.Fprintf(stderr, "queue task: %v\n", err)
		return 1
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintf(stderr, "create local signing key: %v\n", err)
		return 1
	}
	authority, err := grants.NewAuthority("collector-local", "credential-local", private, store)
	if err != nil {
		fmt.Fprintf(stderr, "create local credential authority: %v\n", err)
		return 1
	}
	_, evidencePrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintf(stderr, "create evidence signing key: %v\n", err)
		return 1
	}
	assembler, err := evidence.NewAssembler("v1", evidencePrivate, store)
	if err != nil {
		fmt.Fprintf(stderr, "create evidence assembler: %v\n", err)
		return 1
	}
	pipelineSink, err := evidence.NewPipelineSink(artefacts.NewStore(),
		sanitise.Pipeline{ID: "safe-json", Version: "v1", MaximumBytes: int(*maximumBytes)},
		parsing.InterfaceStateParser{ID: "interface-state", Version: "v1"}, assembler,
		"gnmi", "local-encryption-key", "collector-v1", "normaliser-v1", 5*time.Minute, time.Now)
	if err != nil {
		fmt.Fprintf(stderr, "create evidence pipeline: %v\n", err)
		return 1
	}
	observedAt := time.Now().UTC().Format(time.RFC3339Nano)
	stubPayload := []byte(fmt.Sprintf(`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":%q}`, observedAt))
	worker := collector.Worker{
		ID:              *collectorID,
		Tasks:           store,
		Transport:       transport.StubAdapter{Payload: stubPayload},
		Sink:            pipelineSink,
		Authorizer:      catalogueAuthorizer{},
		GrantIssuer:     authority,
		Credentials:     authority,
		LeaseDuration:   *leaseDuration,
		GrantTTL:        *leaseDuration,
		MaximumDuration: *maximumDuration,
		MaximumBytes:    *maximumBytes,
	}
	if err := worker.Run(context.Background(), *taskID); err != nil {
		fmt.Fprintf(stderr, "collect task: %v\n", err)
		return 1
	}
	task, err := store.Get(*taskID)
	if err != nil {
		fmt.Fprintf(stderr, "read task result: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result{
		TaskID: task.ID, State: task.State, FencingToken: task.FencingToken,
		AcceptedAttemptID: task.AcceptedAttemptID, AcceptedEvidenceID: task.AcceptedEvidenceID,
	}); err != nil {
		fmt.Fprintf(stderr, "write task result: %v\n", err)
		return 1
	}
	return 0
}
