// Package parsing converts sanitised artefacts into concrete typed observations.
package parsing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"
	"unicode"

	"network_broker/internal/artefacts"
)

type InterfaceOperationalState struct {
	SchemaVersion    string    `json:"schema_version"`
	InterfaceName    string    `json:"interface_name"`
	OperationalState string    `json:"operational_state"`
	ObservedAt       time.Time `json:"observed_at"`
	TaintedFields    []string  `json:"tainted_fields,omitempty"`
}

type InterfaceStateParser struct {
	ID      string
	Version string
}

func (p InterfaceStateParser) parse(payload []byte) (InterfaceOperationalState, error) {
	if p.ID == "" || p.Version == "" || len(payload) == 0 {
		return InterfaceOperationalState{}, fmt.Errorf("parser identity and payload are required")
	}
	var wire struct {
		SchemaVersion    string    `json:"schema_version"`
		InterfaceName    string    `json:"interface_name"`
		OperationalState string    `json:"operational_state"`
		ObservedAt       time.Time `json:"observed_at"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return InterfaceOperationalState{}, fmt.Errorf("parse interface operational state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return InterfaceOperationalState{}, fmt.Errorf("observation must contain exactly one JSON value")
	}
	if wire.SchemaVersion != "v1" || !validInterfaceName(wire.InterfaceName) || wire.ObservedAt.IsZero() {
		return InterfaceOperationalState{}, fmt.Errorf("observation does not satisfy interface operational state v1 schema")
	}
	switch wire.OperationalState {
	case "up", "down", "unknown":
	default:
		return InterfaceOperationalState{}, fmt.Errorf("unsupported operational state %q", wire.OperationalState)
	}
	return InterfaceOperationalState{
		SchemaVersion: wire.SchemaVersion, InterfaceName: wire.InterfaceName,
		OperationalState: wire.OperationalState, ObservedAt: wire.ObservedAt.UTC(),
		TaintedFields: []string{"interface_name"},
	}, nil
}

func (p InterfaceStateParser) ParseWithManifest(payload []byte,
	mediaType string,
	manifest artefacts.TransformationManifest,
) (InterfaceOperationalState, error) {
	if mediaType != "application/json" {
		return InterfaceOperationalState{}, fmt.Errorf("interface state requires application/json, got %q", mediaType)
	}
	if manifest.Quarantined {
		return InterfaceOperationalState{}, fmt.Errorf("quarantined payload cannot be promoted to typed evidence")
	}
	outputDigest := sha256.Sum256(payload)
	if manifest.ManifestVersion != artefacts.TransformationManifestVersionV1 || manifest.RulesVersion == "" ||
		!validSHA256Digest(manifest.InputDigest) ||
		manifest.OutputDigest != hex.EncodeToString(outputDigest[:]) || manifest.OverallStatus != "tainted" ||
		!slices.Contains(manifest.TaintedFields, "$/interface_name") {
		return InterfaceOperationalState{}, fmt.Errorf("sanitisation manifest does not classify interface_name as tainted")
	}
	return p.parse(payload)
}

func validSHA256Digest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if unicode.IsLetter(char) || unicode.IsDigit(char) ||
			char == '-' || char == '_' || char == '.' || char == ':' || char == '/' || char == '[' || char == ']' {
			continue
		}
		return false
	}
	return true
}
