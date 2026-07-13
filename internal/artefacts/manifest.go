package artefacts

import (
	"encoding/json"
	"fmt"
)

type legacyTransformationManifest TransformationManifest

type transformationManifestV1 struct {
	ManifestVersion   string                    `json:"manifest_version"`
	PipelineID        string                    `json:"pipeline_id"`
	PipelineVersion   string                    `json:"sanitiser_version"`
	RulesVersion      string                    `json:"rule_set_version"`
	InputDigest       string                    `json:"input_digest"`
	OutputDigest      string                    `json:"output_digest"`
	OverallStatus     string                    `json:"overall_status"`
	RedactionsApplied []string                  `json:"redactions_applied"`
	TaintedFields     []string                  `json:"tainted_fields,omitempty"`
	Outcomes          []transformationOutcomeV1 `json:"transformations,omitempty"`
	Quarantined       bool                      `json:"quarantined,omitempty"`
	Truncated         bool                      `json:"truncated"`
	OriginalByteCount uint64                    `json:"original_byte_count"`
	OutputByteCount   uint64                    `json:"output_byte_count"`
}

type transformationOutcomeV1 struct {
	Action       string `json:"action"`
	ReasonCode   string `json:"reason_code"`
	JSONPath     string `json:"path"`
	RulePosition uint64 `json:"rule_position,omitempty"`
	Count        uint64 `json:"count"`
}

func (manifest TransformationManifest) MarshalJSON() ([]byte, error) {
	if manifest.ManifestVersion == "" {
		return json.Marshal(legacyTransformationManifest(manifest))
	}
	outcomes := make([]transformationOutcomeV1, len(manifest.Outcomes))
	for index, item := range manifest.Outcomes {
		outcomes[index] = transformationOutcomeV1(item)
	}
	return json.Marshal(transformationManifestV1{
		ManifestVersion: manifest.ManifestVersion, PipelineID: manifest.PipelineID,
		PipelineVersion: manifest.PipelineVersion, RulesVersion: manifest.RulesVersion,
		InputDigest: manifest.InputDigest, OutputDigest: manifest.OutputDigest, OverallStatus: manifest.OverallStatus,
		RedactionsApplied: manifest.RedactionsApplied, TaintedFields: manifest.TaintedFields, Outcomes: outcomes,
		Quarantined: manifest.Quarantined, Truncated: manifest.Truncated,
		OriginalByteCount: manifest.OriginalByteCount, OutputByteCount: manifest.OutputByteCount,
	})
}

func (manifest *TransformationManifest) UnmarshalJSON(payload []byte) error {
	if manifest == nil {
		return fmt.Errorf("transformation manifest destination is required")
	}
	var version struct {
		ManifestVersion string `json:"manifest_version"`
	}
	if err := json.Unmarshal(payload, &version); err != nil {
		return err
	}
	if version.ManifestVersion == "" {
		var legacy legacyTransformationManifest
		if err := json.Unmarshal(payload, &legacy); err != nil {
			return err
		}
		*manifest = TransformationManifest(legacy)
		return nil
	}
	var decoded transformationManifestV1
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return err
	}
	outcomes := make([]TransformationOutcome, len(decoded.Outcomes))
	for index, item := range decoded.Outcomes {
		outcomes[index] = TransformationOutcome(item)
	}
	*manifest = TransformationManifest{
		ManifestVersion: decoded.ManifestVersion, PipelineID: decoded.PipelineID,
		PipelineVersion: decoded.PipelineVersion, RulesVersion: decoded.RulesVersion,
		InputDigest: decoded.InputDigest, OutputDigest: decoded.OutputDigest, OverallStatus: decoded.OverallStatus,
		RedactionsApplied: decoded.RedactionsApplied, TaintedFields: decoded.TaintedFields, Outcomes: outcomes,
		Quarantined: decoded.Quarantined, Truncated: decoded.Truncated,
		OriginalByteCount: decoded.OriginalByteCount, OutputByteCount: decoded.OutputByteCount,
	}
	return nil
}
