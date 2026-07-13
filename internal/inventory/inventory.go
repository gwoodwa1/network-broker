package inventory

import (
	"fmt"
	"sort"
	"strings"

	"network_broker/internal/authctx"
)

// ResolvedTarget represents a target resolved from a selector.
type ResolvedTarget struct {
	TargetID       string
	TenantID       string
	SiteID         string
	Platform       string
	SoftwareFamily string
	DeviceClass    string
	MetadataDigest string
}

// ResolvedTargetSnapshot is an immutable snapshot used for planning and policy.
type ResolvedTargetSnapshot struct {
	SnapshotID        string
	TenantID          string
	SelectorDigest    string
	InventoryRevision string
	Targets           []ResolvedTarget
}

// Selector describes the target set requested by a caller.
type Selector struct {
	TargetIDs []string
}

// Resolver resolves selectors into tenant-scoped snapshots.
type Resolver struct {
	Catalog map[string]ResolvedTarget
}

// Resolve turns a selector into an immutable target snapshot.
func (r Resolver) Resolve(auth authctx.AuthContext, selector Selector) (ResolvedTargetSnapshot, error) {
	if err := auth.Validate(); err != nil {
		return ResolvedTargetSnapshot{}, err
	}
	if len(selector.TargetIDs) == 0 {
		return ResolvedTargetSnapshot{}, fmt.Errorf("selector must include at least one target id")
	}
	if len(r.Catalog) == 0 {
		return ResolvedTargetSnapshot{}, fmt.Errorf("inventory catalog is empty")
	}

	targets := make([]ResolvedTarget, 0, len(selector.TargetIDs))
	for _, id := range selector.TargetIDs {
		target, ok := r.Catalog[id]
		if !ok {
			return ResolvedTargetSnapshot{}, fmt.Errorf("target %q not found", id)
		}
		if target.TenantID != auth.TenantID {
			return ResolvedTargetSnapshot{}, fmt.Errorf("target %q is outside tenant scope", id)
		}
		targets = append(targets, target)
	}

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].TargetID < targets[j].TargetID
	})

	selectorDigest := fmt.Sprintf("targets:%s", strings.Join(selector.TargetIDs, ","))
	return ResolvedTargetSnapshot{
		SnapshotID:        fmt.Sprintf("snapshot-%s", auth.TenantID),
		TenantID:          auth.TenantID,
		SelectorDigest:    selectorDigest,
		InventoryRevision: "rev-1",
		Targets:           targets,
	}, nil
}
