// Package parsing converts sanitised artefacts into concrete typed observations.
package parsing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type InterfaceOperationalState struct {
	SchemaVersion    string    `json:"schema_version"`
	InterfaceName    string    `json:"interface_name"`
	OperationalState string    `json:"operational_state"`
	ObservedAt       time.Time `json:"observed_at"`
}

type InterfaceStateParser struct {
	ID      string
	Version string
}

func (p InterfaceStateParser) Parse(payload []byte) (InterfaceOperationalState, error) {
	if p.ID == "" || p.Version == "" || len(payload) == 0 {
		return InterfaceOperationalState{}, fmt.Errorf("parser identity and payload are required")
	}
	var observation InterfaceOperationalState
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&observation); err != nil {
		return InterfaceOperationalState{}, fmt.Errorf("parse interface operational state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return InterfaceOperationalState{}, fmt.Errorf("observation must contain exactly one JSON value")
	}
	if observation.SchemaVersion != "v1" || observation.InterfaceName == "" || observation.ObservedAt.IsZero() {
		return InterfaceOperationalState{}, fmt.Errorf("observation does not satisfy interface operational state v1 schema")
	}
	switch observation.OperationalState {
	case "up", "down", "unknown":
	default:
		return InterfaceOperationalState{}, fmt.Errorf("unsupported operational state %q", observation.OperationalState)
	}
	observation.ObservedAt = observation.ObservedAt.UTC()
	return observation, nil
}
