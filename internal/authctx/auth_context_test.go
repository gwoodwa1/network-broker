package authctx

import (
	"testing"
	"time"
)

func TestAuthContextValidate(t *testing.T) {
	ctx := AuthContext{
		SubjectID:        "spiffe://example/ns/default/sa/app",
		TenantID:         "tenant-a",
		Roles:            []string{"reader"},
		AllowedScopes:    []string{"inventory:read"},
		AuthenticatedAt:  time.Now(),
		IdentityRevision: "rev-1",
	}

	if err := ctx.Validate(); err != nil {
		t.Fatalf("expected valid auth context, got error: %v", err)
	}
}

func TestAuthContextValidateRejectsMissingTenant(t *testing.T) {
	ctx := AuthContext{
		SubjectID:       "spiffe://example/ns/default/sa/app",
		AuthenticatedAt: time.Now(),
	}

	if err := ctx.Validate(); err == nil {
		t.Fatal("expected missing tenant to be rejected")
	}
}
