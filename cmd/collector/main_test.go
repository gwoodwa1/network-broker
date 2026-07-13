package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"network_broker/internal/collector"
)

func TestRunExecutesLocalCollectorAttempt(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-task-id", "task-1", "-target-id", "target-1"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected success, got exit %d: %s", code, stderr.String())
	}
	var got result
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if got.TaskID != "task-1" || got.State != collector.TaskSucceeded || got.FencingToken != 1 {
		t.Fatalf("unexpected collector result: %+v", got)
	}
	if got.AcceptedAttemptID == "" || got.AcceptedEvidenceID == "" {
		t.Fatalf("expected accepted attempt and evidence ids: %+v", got)
	}
}

func TestRunRejectsInvalidBounds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-max-response-bytes", "0"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "positive lease, duration and response byte limits") {
		t.Fatalf("expected invalid bounds failure, got exit %d: %s", code, stderr.String())
	}
}
