package parsing

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"network_broker/internal/artefacts"
)

func TestInterfaceStateParserValidatesConcreteSchema(t *testing.T) {
	parser := InterfaceStateParser{ID: "openconfig-interface-state", Version: "v1"}
	payload := []byte(`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":"2026-07-13T10:00:00Z"}`)
	observation, err := parser.ParseWithManifest(payload, "application/json", validManifest(payload))
	if err != nil {
		t.Fatal(err)
	}
	if observation.InterfaceName != "Ethernet1" || observation.OperationalState != "up" {
		t.Fatalf("unexpected observation: %+v", observation)
	}
	if len(observation.TaintedFields) != 1 || observation.TaintedFields[0] != "interface_name" {
		t.Fatalf("device-controlled field was not tainted: %+v", observation)
	}
}

func TestInterfaceStateParserRequiresSanitisationTaintManifest(t *testing.T) {
	parser := InterfaceStateParser{ID: "openconfig-interface-state", Version: "v1"}
	payload := []byte(`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":"2026-07-13T10:00:00Z"}`)
	manifest := validManifest(payload)
	if _, err := parser.ParseWithManifest(payload, "application/json", manifest); err != nil {
		t.Fatal(err)
	}
	manifest.TaintedFields = nil
	if _, err := parser.ParseWithManifest(payload, "application/json", manifest); err == nil {
		t.Fatal("expected missing taint classification to fail closed")
	}
	manifest = validManifest(payload)
	manifest.OutputDigest = "different"
	if _, err := parser.ParseWithManifest(payload, "application/json", manifest); err == nil {
		t.Fatal("expected an unbound manifest digest to fail closed")
	}
	manifest = validManifest(payload)
	manifest.Quarantined = true
	if _, err := parser.ParseWithManifest(payload, "application/json", manifest); err == nil {
		t.Fatal("expected quarantined payload to be rejected")
	}
	manifest = validManifest(payload)
	if _, err := parser.ParseWithManifest(payload, "application/xml", manifest); err == nil {
		t.Fatal("expected an unsupported media type to be rejected")
	}
}

func TestInterfaceStateParserRejectsUnknownFieldsAndEnumValues(t *testing.T) {
	parser := InterfaceStateParser{ID: "openconfig-interface-state", Version: "v1"}
	for _, payload := range []string{
		`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"flapping","observed_at":"2026-07-13T10:00:00Z"}`,
		`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":"2026-07-13T10:00:00Z","extra":true}`,
		`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":"2026-07-13T10:00:00Z","tainted_fields":[]}`,
		`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":"2026-07-13T10:00:00Z"} {}`,
	} {
		encoded := []byte(payload)
		if _, err := parser.ParseWithManifest(encoded, "application/json", validManifest(encoded)); err == nil {
			t.Fatalf("expected invalid payload to be rejected: %s", payload)
		}
	}
}

func TestInterfaceStateParserRejectsStructuralContentInIdentifier(t *testing.T) {
	parser := InterfaceStateParser{ID: "openconfig-interface-state", Version: "v1"}
	for _, name := range []string{
		"| interface | state |",
		"```tool\ncall```",
		"{\"role\":\"system\"}",
	} {
		payload := []byte(`{"schema_version":"v1","interface_name":` + strconv.Quote(name) +
			`,"operational_state":"up","observed_at":"2026-07-13T10:00:00Z"}`)
		if _, err := parser.ParseWithManifest(payload, "application/json", validManifest(payload)); err == nil {
			t.Fatalf("expected structural interface name to be rejected: %q", name)
		}
	}
}

func validManifest(payload []byte) artefacts.TransformationManifest {
	digest := sha256.Sum256(payload)
	return artefacts.TransformationManifest{
		ManifestVersion: artefacts.TransformationManifestVersionV1, RulesVersion: "rules-v1",
		InputDigest: strings.Repeat("a", sha256.Size*2), OutputDigest: hex.EncodeToString(digest[:]),
		OverallStatus: "tainted", TaintedFields: []string{"$/interface_name"},
	}
}
