package parsing

import (
	"testing"

	"network_broker/internal/artefacts"
)

func TestInterfaceStateParserValidatesConcreteSchema(t *testing.T) {
	parser := InterfaceStateParser{ID: "openconfig-interface-state", Version: "v1"}
	observation, err := parser.Parse([]byte(`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":"2026-07-13T10:00:00Z"}`))
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
	manifest := artefacts.TransformationManifest{RulesVersion: "rules-v1", TaintedFields: []string{"$/interface_name"}}
	if _, err := parser.ParseWithManifest(payload, manifest); err != nil {
		t.Fatal(err)
	}
	manifest.TaintedFields = nil
	if _, err := parser.ParseWithManifest(payload, manifest); err == nil {
		t.Fatal("expected missing taint classification to fail closed")
	}
	manifest.Quarantined = true
	if _, err := parser.ParseWithManifest(payload, manifest); err == nil {
		t.Fatal("expected quarantined payload to be rejected")
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
		if _, err := parser.Parse([]byte(payload)); err == nil {
			t.Fatalf("expected invalid payload to be rejected: %s", payload)
		}
	}
}
