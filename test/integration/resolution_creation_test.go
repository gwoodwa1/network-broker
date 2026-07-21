//go:build integration

package integration_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"network_broker/internal/resolution"
)

func TestResolutionRequestProvenanceSurvivesRepositoryReconstruction(t *testing.T) {
	database, ctx := openGrantIntegrationDatabase(t)
	now := postgresClock(t, ctx, database)
	suffix := fmt.Sprintf("%d", now.UnixNano())
	document := []byte(`{"schema_version":"v1","claims":["interface.operational_state"],` +
		`"target_ids":["router-1"],"maximum_age_seconds":300}`)
	digest := sha256.Sum256(document)
	repository, err := resolution.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	service := resolution.NewServiceWithRepository(repository, func() time.Time { return now },
		func(prefix string) (string, error) { return prefix + "-" + suffix, nil })
	created, err := service.Create(ctx, resolution.CreateRequest{
		ActorID: "actor-" + suffix, TenantID: "tenant-integration",
		IdempotencyKey: "request-" + suffix,
		RequestDigest:  "sha256:" + hex.EncodeToString(digest[:]), RequestDocument: document,
	})
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := resolution.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := restarted.Get(ctx, "tenant-integration", created.Resolution.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored.RequestDocument) != string(document) || stored.RequestDigest != created.Resolution.RequestDigest {
		t.Fatalf("request provenance changed after reconstruction: %+v", stored)
	}
	var payload []byte
	if err := database.QueryRowContext(ctx, `
		SELECT payload::text
		FROM broker_outbox
		WHERE aggregate_id = $1 AND event_type = 'resolution.received'`, created.Resolution.ID,
	).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"request_document"`) ||
		!strings.Contains(string(payload), created.Resolution.RequestDigest) {
		t.Fatalf("creation event omitted request provenance: %s", payload)
	}
}
