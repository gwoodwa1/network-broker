package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"network_broker/internal/artefacts"
	"network_broker/internal/collector"
	"network_broker/internal/parsing"
	"network_broker/internal/sanitise"
	"network_broker/internal/transport"
)

func TestPipelineSinkBuildsSignedEnvelopeFromCurrentAttempt(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	tasks := collector.NewStore()
	task := collector.Task{ID: "task-1", TenantID: "tenant-1", ClaimFingerprint: "claim-1", ResolutionID: "resolution-1",
		TargetSnapshotID: "snapshot-1", TargetSnapshotHash: "snapshot-hash", TargetID: "target-1",
		RecipeID: "gnmi_interface_get", RecipeVersion: "v1", TriggerDecisionID: "trigger-1",
		PlanningDecisionID: "planning-1", CompatibilityHash: "compat-1"}
	if err := tasks.Add(task); err != nil {
		t.Fatal(err)
	}
	lease, err := tasks.Acquire(task.ID, "collector-a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := tasks.StartExecution(task.ID, lease.Owner, lease.FencingToken, now); err != nil {
		t.Fatal(err)
	}
	if err := tasks.RecordExecutionAuthority(task.ID, lease.Owner, lease.FencingToken, "execution-1", "grant-1", now); err != nil {
		t.Fatal(err)
	}
	task, _ = tasks.Get(task.ID)
	_, private, _ := ed25519.GenerateKey(nil)
	assembler, err := NewAssembler("v1", private, tasks)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewPipelineSink(artefacts.NewStore(), sanitise.Pipeline{ID: "safe-json", Version: "v1", MaximumBytes: 4096},
		parsing.InterfaceStateParser{ID: "interface-state", Version: "v1"}, assembler, "gnmi", "key-1", "v1", "v1", 5*time.Minute,
		func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":"2026-07-13T10:00:00Z"}`)
	attemptID, evidenceID, err := sink.WriteCaptured(context.Background(), task, lease, transport.CapturedBytes{
		TargetID: task.TargetID, Payload: payload, Digest: sha256.Sum256(payload), CapturedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sink.Get(evidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.AcceptedAttemptID != attemptID || envelope.InterfaceState.OperationalState != "up" {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
	if err := assembler.Verify(envelope); err != nil {
		t.Fatal(err)
	}
}
