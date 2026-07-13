package parsing

import "testing"

func TestInterfaceStateParserValidatesConcreteSchema(t *testing.T) {
	parser := InterfaceStateParser{ID: "openconfig-interface-state", Version: "v1"}
	observation, err := parser.Parse([]byte(`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":"2026-07-13T10:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if observation.InterfaceName != "Ethernet1" || observation.OperationalState != "up" {
		t.Fatalf("unexpected observation: %+v", observation)
	}
}

func TestInterfaceStateParserRejectsUnknownFieldsAndEnumValues(t *testing.T) {
	parser := InterfaceStateParser{ID: "openconfig-interface-state", Version: "v1"}
	for _, payload := range []string{
		`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"flapping","observed_at":"2026-07-13T10:00:00Z"}`,
		`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":"2026-07-13T10:00:00Z","extra":true}`,
		`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":"2026-07-13T10:00:00Z"} {}`,
	} {
		if _, err := parser.Parse([]byte(payload)); err == nil {
			t.Fatalf("expected invalid payload to be rejected: %s", payload)
		}
	}
}
