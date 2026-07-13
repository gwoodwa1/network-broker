package contextstore

import (
	"fmt"
	"sort"

	"network_broker/internal/authctx"
	"network_broker/internal/inventory"
)

// Observation represents a normalised observation already available to the service.
type Observation struct {
	ClaimType string
	Value     string
}

// QueryResult is the response shape used by the read-only query plane.
type QueryResult struct {
	Complete       bool
	Observations   []Observation
	GapDescription string
}

// Store holds already-available observations for the current tenant.
type Store struct {
	Observations map[string][]Observation
}

// Query returns authorised observations for the authenticated actor.
func (s Store) Query(auth authctx.AuthContext, claimType string, targets inventory.ResolvedTargetSnapshot) (QueryResult, error) {
	if err := auth.Validate(); err != nil {
		return QueryResult{}, err
	}
	if claimType == "" {
		return QueryResult{}, fmt.Errorf("claim type is required")
	}
	if targets.TenantID != auth.TenantID {
		return QueryResult{}, fmt.Errorf("snapshot tenant does not match caller scope")
	}

	items := s.Observations[claimType]
	if len(items) == 0 {
		return QueryResult{Complete: false, GapDescription: "no observations available"}, nil
	}

	sort.Slice(items, func(i, j int) bool { return items[i].Value < items[j].Value })
	return QueryResult{Complete: true, Observations: items}, nil
}
