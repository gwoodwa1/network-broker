// Package databaseauth verifies that authority-bearing services are connected
// with the exact non-administrative PostgreSQL role assigned by deployment.
package databaseauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const maximumRoleNameBytes = 63

// Role is the security-relevant PostgreSQL identity observed on a live
// connection. Runtime services reject role switching and administrative
// capabilities before constructing repositories.
type Role struct {
	CurrentUser       string
	SessionUser       string
	Superuser         bool
	BypassRowSecurity bool
	CreateRole        bool
	CreateDatabase    bool
	Replication       bool
	CanLogin          bool
	CanUsePublic      bool
	CanCreatePublic   bool
}

type objectGrant struct {
	Name       string
	Privileges map[string]bool
}

var controlPlaneTablePrivileges = map[string]map[string]bool{
	"broker_resolutions":            {"SELECT": true, "INSERT": true, "UPDATE": true},
	"broker_resolution_idempotency": {"SELECT": true, "INSERT": true},
	"broker_outbox":                 {"SELECT": true, "INSERT": true, "UPDATE": true},
	"broker_collector_tasks":        {"SELECT": true, "INSERT": true, "UPDATE": true},
	"broker_evidence_envelopes":     {"SELECT": true},
	"broker_dead_letter_actions":    {"SELECT": true, "INSERT": true},
}

var controlPlaneSequencePrivileges = map[string]map[string]bool{
	"broker_outbox_sequence_seq": {"USAGE": true},
}

// Verify checks the connected identity rather than trusting the role named in
// the connection string. The role must be a direct login with no PostgreSQL
// administrative capabilities and no CREATE privilege on the public schema.
func Verify(ctx context.Context, database *sql.DB, expected string) (Role, error) {
	if database == nil {
		return Role{}, fmt.Errorf("database is required for role verification")
	}
	if err := ValidateName(expected); err != nil {
		return Role{}, err
	}

	var role Role
	err := database.QueryRowContext(ctx, `
		SELECT current_user, session_user, role.rolsuper, role.rolbypassrls,
			role.rolcreaterole, role.rolcreatedb, role.rolreplication,
			role.rolcanlogin, has_schema_privilege(current_user, 'public', 'USAGE'),
			has_schema_privilege(current_user, 'public', 'CREATE')
		FROM pg_catalog.pg_roles AS role
		WHERE role.rolname = current_user`).Scan(
		&role.CurrentUser, &role.SessionUser, &role.Superuser, &role.BypassRowSecurity,
		&role.CreateRole, &role.CreateDatabase, &role.Replication, &role.CanLogin,
		&role.CanUsePublic, &role.CanCreatePublic)
	if errors.Is(err, sql.ErrNoRows) {
		return Role{}, fmt.Errorf("connected PostgreSQL role was not found")
	}
	if err != nil {
		return Role{}, fmt.Errorf("inspect connected PostgreSQL role: %w", err)
	}
	if err := validate(role, expected); err != nil {
		return Role{}, err
	}

	return role, nil
}

// VerifyControlPlane extends identity verification with an exact effective
// privilege audit over every broker-prefixed table and sequence in public.
// Inherited grants and ownership are included because PostgreSQL's
// has_*_privilege functions evaluate the connected role's effective access.
func VerifyControlPlane(ctx context.Context, database *sql.DB, expected string) (Role, error) {
	role, err := Verify(ctx, database, expected)
	if err != nil {
		return Role{}, err
	}
	tables, err := inspectTableGrants(ctx, database)
	if err != nil {
		return Role{}, err
	}
	sequences, err := inspectSequenceGrants(ctx, database)
	if err != nil {
		return Role{}, err
	}
	if err := validateObjectGrants("table", tables, controlPlaneTablePrivileges); err != nil {
		return Role{}, err
	}
	if err := validateObjectGrants("sequence", sequences, controlPlaneSequencePrivileges); err != nil {
		return Role{}, err
	}

	return role, nil
}

func inspectTableGrants(ctx context.Context, database *sql.DB) ([]objectGrant, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT relation.relname,
			has_table_privilege(current_user, relation.oid, 'SELECT'),
			has_table_privilege(current_user, relation.oid, 'INSERT'),
			has_table_privilege(current_user, relation.oid, 'UPDATE'),
			has_table_privilege(current_user, relation.oid, 'DELETE'),
			has_table_privilege(current_user, relation.oid, 'TRUNCATE'),
			has_table_privilege(current_user, relation.oid, 'REFERENCES'),
			has_table_privilege(current_user, relation.oid, 'TRIGGER')
		FROM pg_catalog.pg_class AS relation
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
		WHERE namespace.nspname = 'public'
			AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
			AND left(relation.relname, 7) = 'broker_'
		ORDER BY relation.relname`)
	if err != nil {
		return nil, fmt.Errorf("inspect PostgreSQL table privileges: %w", err)
	}
	defer rows.Close()

	var grants []objectGrant
	for rows.Next() {
		grant := objectGrant{Privileges: make(map[string]bool, 7)}
		var selectPrivilege, insertPrivilege, updatePrivilege, deletePrivilege bool
		var truncatePrivilege, referencesPrivilege, triggerPrivilege bool
		if err := rows.Scan(&grant.Name, &selectPrivilege, &insertPrivilege, &updatePrivilege,
			&deletePrivilege, &truncatePrivilege, &referencesPrivilege, &triggerPrivilege); err != nil {
			return nil, fmt.Errorf("read PostgreSQL table privileges: %w", err)
		}
		grant.Privileges["SELECT"] = selectPrivilege
		grant.Privileges["INSERT"] = insertPrivilege
		grant.Privileges["UPDATE"] = updatePrivilege
		grant.Privileges["DELETE"] = deletePrivilege
		grant.Privileges["TRUNCATE"] = truncatePrivilege
		grant.Privileges["REFERENCES"] = referencesPrivilege
		grant.Privileges["TRIGGER"] = triggerPrivilege
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate PostgreSQL table privileges: %w", err)
	}

	return grants, nil
}

func inspectSequenceGrants(ctx context.Context, database *sql.DB) ([]objectGrant, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT relation.relname,
			has_sequence_privilege(current_user, relation.oid, 'USAGE'),
			has_sequence_privilege(current_user, relation.oid, 'SELECT'),
			has_sequence_privilege(current_user, relation.oid, 'UPDATE')
		FROM pg_catalog.pg_class AS relation
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
		WHERE namespace.nspname = 'public' AND relation.relkind = 'S'
			AND left(relation.relname, 7) = 'broker_'
		ORDER BY relation.relname`)
	if err != nil {
		return nil, fmt.Errorf("inspect PostgreSQL sequence privileges: %w", err)
	}
	defer rows.Close()

	var grants []objectGrant
	for rows.Next() {
		grant := objectGrant{Privileges: make(map[string]bool, 3)}
		var usagePrivilege, selectPrivilege, updatePrivilege bool
		if err := rows.Scan(&grant.Name, &usagePrivilege, &selectPrivilege, &updatePrivilege); err != nil {
			return nil, fmt.Errorf("read PostgreSQL sequence privileges: %w", err)
		}
		grant.Privileges["USAGE"] = usagePrivilege
		grant.Privileges["SELECT"] = selectPrivilege
		grant.Privileges["UPDATE"] = updatePrivilege
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate PostgreSQL sequence privileges: %w", err)
	}

	return grants, nil
}

func validateObjectGrants(kind string, actual []objectGrant, expected map[string]map[string]bool) error {
	seen := make(map[string]bool, len(actual))
	for _, grant := range actual {
		seen[grant.Name] = true
		allowed := expected[grant.Name]
		for privilege, present := range grant.Privileges {
			if present && !allowed[privilege] {
				return fmt.Errorf("PostgreSQL %s %q has prohibited %s privilege", kind, grant.Name, privilege)
			}
		}
	}
	for name, privileges := range expected {
		if !seen[name] {
			return fmt.Errorf("required PostgreSQL %s %q was not found", kind, name)
		}
		for privilege := range privileges {
			found := false
			for _, grant := range actual {
				if grant.Name == name {
					found = grant.Privileges[privilege]
					break
				}
			}
			if !found {
				return fmt.Errorf("PostgreSQL %s %q lacks required %s privilege", kind, name, privilege)
			}
		}
	}

	return nil
}

// ValidateName keeps deployment role configuration canonical and safe to use
// in logs and operational policy. It is never interpolated into SQL.
func ValidateName(name string) error {
	if name == "" || len(name) > maximumRoleNameBytes || strings.TrimSpace(name) != name ||
		strings.IndexFunc(name, func(character rune) bool {
			return !(unicode.IsLetter(character) || unicode.IsDigit(character) ||
				character == '_' || character == '-')
		}) >= 0 {
		return fmt.Errorf("expected PostgreSQL role must be a canonical deployment identifier")
	}

	return nil
}

func validate(role Role, expected string) error {
	if role.CurrentUser != expected || role.SessionUser != expected {
		return fmt.Errorf("connected PostgreSQL identity does not match expected deployment role")
	}
	if !role.CanLogin || !role.CanUsePublic {
		return fmt.Errorf("connected PostgreSQL role must be a direct login role")
	}
	if role.Superuser || role.BypassRowSecurity || role.CreateRole || role.CreateDatabase ||
		role.Replication || role.CanCreatePublic {
		return fmt.Errorf("connected PostgreSQL role has prohibited administrative privileges")
	}

	return nil
}
