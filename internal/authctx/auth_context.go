package authctx

import (
	"fmt"
	"time"
)

// AuthContext captures the server-derived authenticated identity and scope.
type AuthContext struct {
	SubjectID        string
	SPIFFEID         string
	TenantID         string
	Roles            []string
	AllowedScopes    []string
	DataClearances   []string
	CredentialClass  string
	AuthenticatedAt  time.Time
	IdentityRevision string
}

// Validate ensures the context carries the minimum data required for downstream use.
func (a AuthContext) Validate() error {
	if a.SubjectID == "" {
		return fmt.Errorf("subject id is required")
	}
	if a.TenantID == "" {
		return fmt.Errorf("tenant id is required")
	}
	if a.AuthenticatedAt.IsZero() {
		return fmt.Errorf("authenticated at timestamp is required")
	}
	return nil
}
