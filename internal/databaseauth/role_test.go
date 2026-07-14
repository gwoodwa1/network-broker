package databaseauth

import (
	"strings"
	"testing"
)

func TestValidateAcceptsLeastPrivilegeDirectRole(t *testing.T) {
	role := Role{
		CurrentUser: "broker_controlplane", SessionUser: "broker_controlplane",
		CanLogin: true, CanUsePublic: true,
	}
	if err := validate(role, "broker_controlplane"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsIdentitySwitchAndAdministrativePrivileges(t *testing.T) {
	tests := []struct {
		name string
		role Role
	}{
		{name: "unexpected role", role: validRole("postgres")},
		{name: "set role", role: Role{CurrentUser: "broker_controlplane", SessionUser: "bootstrap", CanLogin: true, CanUsePublic: true}},
		{name: "superuser", role: withRoleFlag(func(role *Role) { role.Superuser = true })},
		{name: "row security bypass", role: withRoleFlag(func(role *Role) { role.BypassRowSecurity = true })},
		{name: "role creation", role: withRoleFlag(func(role *Role) { role.CreateRole = true })},
		{name: "database creation", role: withRoleFlag(func(role *Role) { role.CreateDatabase = true })},
		{name: "replication", role: withRoleFlag(func(role *Role) { role.Replication = true })},
		{name: "indirect role", role: Role{CurrentUser: "broker_controlplane", SessionUser: "broker_controlplane"}},
		{name: "public schema create", role: withRoleFlag(func(role *Role) { role.CanCreatePublic = true })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validate(test.role, "broker_controlplane"); err == nil {
				t.Fatal("expected prohibited database role to fail")
			}
		})
	}
}

func TestValidateObjectGrantsAcceptsExactProfile(t *testing.T) {
	actual := grantsFromProfile(controlPlaneTablePrivileges)
	actual = append(actual, objectGrant{Name: "broker_schema_migrations", Privileges: map[string]bool{"SELECT": false}})
	if err := validateObjectGrants("table", actual, controlPlaneTablePrivileges); err != nil {
		t.Fatal(err)
	}
}

func TestValidateObjectGrantsRejectsMissingAndExtraPrivileges(t *testing.T) {
	missing := grantsFromProfile(controlPlaneTablePrivileges)
	missing[0].Privileges["SELECT"] = false
	if err := validateObjectGrants("table", missing, controlPlaneTablePrivileges); err == nil {
		t.Fatal("expected a missing required privilege to fail")
	}
	extra := grantsFromProfile(controlPlaneTablePrivileges)
	extra = append(extra, objectGrant{Name: "broker_policy_bundles", Privileges: map[string]bool{"SELECT": true}})
	if err := validateObjectGrants("table", extra, controlPlaneTablePrivileges); err == nil {
		t.Fatal("expected an unexpected effective privilege to fail")
	}
	missingObject := grantsFromProfile(controlPlaneTablePrivileges)[1:]
	if err := validateObjectGrants("table", missingObject, controlPlaneTablePrivileges); err == nil {
		t.Fatal("expected a missing required object to fail")
	}
}

func validRole(name string) Role {
	return Role{CurrentUser: name, SessionUser: name, CanLogin: true, CanUsePublic: true}
}

func withRoleFlag(update func(*Role)) Role {
	role := validRole("broker_controlplane")
	update(&role)

	return role
}

func grantsFromProfile(profile map[string]map[string]bool) []objectGrant {
	grants := make([]objectGrant, 0, len(profile))
	for name, expected := range profile {
		privileges := make(map[string]bool, len(expected))
		for privilege, value := range expected {
			privileges[privilege] = value
		}
		grants = append(grants, objectGrant{Name: name, Privileges: privileges})
	}

	return grants
}

func TestValidateNameRejectsNonCanonicalRoleNames(t *testing.T) {
	for _, name := range []string{"", " broker", "broker role", "broker;admin", strings.Repeat("a", 64)} {
		if err := ValidateName(name); err == nil {
			t.Fatalf("expected role name %q to fail", name)
		}
	}
	if err := ValidateName("broker-controlplane_1"); err != nil {
		t.Fatal(err)
	}
}
