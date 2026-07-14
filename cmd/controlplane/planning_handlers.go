package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"network_broker/internal/authctx"
	"network_broker/internal/collector"
	"network_broker/internal/planning"
)

const (
	planningAPISchemaVersion = "v1"
	maximumPlanningBodySize  = 512 * 1024
	maximumPlanningRequests  = 16
)

type planningAuthenticator interface {
	Authenticate(*tls.ConnectionState) (authctx.AuthContext, error)
}

type planningAPI struct {
	service       *planning.Service
	authenticator planningAuthenticator
	logger        *slog.Logger
	concurrency   chan struct{}
}

type queuePlanBody struct {
	SchemaVersion             string            `json:"schema_version"`
	ExpectedResolutionVersion int64             `json:"expected_resolution_version"`
	Tasks                     []plannedTaskBody `json:"tasks"`
}

type plannedTaskBody struct {
	TaskID             string `json:"task_id"`
	ClaimFingerprint   string `json:"claim_fingerprint"`
	TargetSnapshotID   string `json:"target_snapshot_id"`
	TargetSnapshotHash string `json:"target_snapshot_hash"`
	TargetID           string `json:"target_id"`
	TargetEndpoint     string `json:"target_endpoint,omitempty"`
	RecipeID           string `json:"recipe_id"`
	RecipeVersion      string `json:"recipe_version"`
	TriggerDecisionID  string `json:"trigger_decision_id"`
	PlanningDecisionID string `json:"planning_decision_id"`
	ApprovalGrantID    string `json:"approval_grant_id,omitempty"`
	CompatibilityHash  string `json:"compatibility_hash"`
}

func newPlanningAPI(service *planning.Service, authenticator planningAuthenticator,
	logger *slog.Logger,
) (*planningAPI, error) {
	if service == nil || authenticator == nil || logger == nil {
		return nil, fmt.Errorf("planning service, authenticator and logger are required")
	}

	return &planningAPI{
		service: service, authenticator: authenticator, logger: logger,
		concurrency: make(chan struct{}, maximumPlanningRequests),
	}, nil
}

func (a *planningAPI) register(mux *http.ServeMux) {
	mux.Handle("POST /v1/resolutions/{resolution_id}/tasks:queue",
		a.limit(http.HandlerFunc(a.queue)))
}

func (a *planningAPI) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case a.concurrency <- struct{}{}:
			defer func() { <-a.concurrency }()
			next.ServeHTTP(response, request)
		default:
			writePlanningError(response, http.StatusTooManyRequests, "PLANNING_BUSY")
		}
	})
}

func (a *planningAPI) queue(response http.ResponseWriter, request *http.Request) {
	actor, err := a.authenticator.Authenticate(request.TLS)
	if err != nil {
		response.Header().Set("WWW-Authenticate", "Mutual")
		writePlanningError(response, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		return
	}
	body, err := decodeQueuePlanBody(response, request)
	if err != nil {
		writePlanningError(response, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	tasks := make([]collector.Task, len(body.Tasks))
	for index := range body.Tasks {
		tasks[index] = body.Tasks[index].task()
	}
	result, err := a.service.Queue(request.Context(), actor, planning.QueueRequest{
		ResolutionID:              request.PathValue("resolution_id"),
		ExpectedResolutionVersion: body.ExpectedResolutionVersion, Tasks: tasks,
	})
	if err != nil {
		switch {
		case errors.Is(err, planning.ErrDenied):
			writePlanningError(response, http.StatusForbidden, "PLANNING_DENIED")
		case errors.Is(err, planning.ErrInvalidRequest):
			writePlanningError(response, http.StatusBadRequest, "INVALID_REQUEST")
		case errors.Is(err, collector.ErrFanoutConflict):
			writePlanningError(response, http.StatusConflict, "RESOLUTION_AUTHORITY_CHANGED")
		default:
			a.logger.ErrorContext(request.Context(), "queue planned tasks failed", "error", err)
			writePlanningError(response, http.StatusInternalServerError, "PLANNING_FAILED")
		}
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(response).Encode(result); err != nil {
		a.logger.ErrorContext(request.Context(), "encode planning response failed", "error", err)
	}
}

func decodeQueuePlanBody(response http.ResponseWriter, request *http.Request) (queuePlanBody, error) {
	request.Body = http.MaxBytesReader(response, request.Body, maximumPlanningBodySize)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body queuePlanBody
	if err := decoder.Decode(&body); err != nil {
		return queuePlanBody{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return queuePlanBody{}, fmt.Errorf("planning body must contain one JSON document")
	}
	if body.SchemaVersion != planningAPISchemaVersion {
		return queuePlanBody{}, fmt.Errorf("unsupported planning schema version")
	}

	return body, nil
}

func (body plannedTaskBody) task() collector.Task {
	return collector.Task{
		ID: body.TaskID, ClaimFingerprint: body.ClaimFingerprint,
		TargetSnapshotID: body.TargetSnapshotID, TargetSnapshotHash: body.TargetSnapshotHash,
		TargetID: body.TargetID, TargetEndpoint: body.TargetEndpoint,
		RecipeID: body.RecipeID, RecipeVersion: body.RecipeVersion,
		TriggerDecisionID: body.TriggerDecisionID, PlanningDecisionID: body.PlanningDecisionID,
		ApprovalGrantID: body.ApprovalGrantID, CompatibilityHash: body.CompatibilityHash,
	}
}

func writePlanningError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(struct {
		Code string `json:"code"`
	}{Code: code}); err != nil {
		return
	}
}
