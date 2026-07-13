// Package sanitise creates a separately digested safe derivative of captured bytes.
package sanitise

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"network_broker/internal/artefacts"
)

const (
	ActionRetained    = "retained"
	ActionRedacted    = "redacted"
	ActionStripped    = "stripped"
	ActionTainted     = "tainted"
	ActionRejected    = "rejected"
	ActionTruncated   = "truncated"
	ActionQuarantined = "quarantined"

	defaultRulesVersion   = "network-hostile-output/v1"
	maximumCapturedBytes  = artefacts.MaximumArtefactBytes
	quarantinedOutputJSON = `{"quarantined":true}`
)

var ErrQuarantined = errors.New("captured payload was quarantined by sanitisation policy")

type Rules struct {
	Version                string
	FreeTextJSONFields     []string
	InstructionPatterns    []string
	MaximumStringBytes     int
	MaximumNestingDepth    int
	MaximumJSONNodes       int
	EncodedTokenMinimum    int
	RepeatedCharacterLimit int
}

type Pipeline struct {
	ID           string
	Version      string
	Redactions   map[string]string
	MaximumBytes int
	Rules        Rules
}

func DefaultRules() Rules {
	return Rules{
		Version: defaultRulesVersion,
		FreeTextJSONFields: []string{
			"banner", "description", "interface_name", "message", "neighbor_description",
			"port_description", "sys_descr", "system_description",
		},
		InstructionPatterns: []string{
			"###", "```", "assistant:", "execute the following", "ignore all previous", "ignore previous",
			"instruction:", "reveal the system prompt", "system prompt", "system:", "you are chatgpt",
		},
		MaximumStringBytes: 4096, MaximumNestingDepth: 64, MaximumJSONNodes: 10000,
		EncodedTokenMinimum: 128, RepeatedCharacterLimit: 64,
	}
}

func (p Pipeline) Transform(captured []byte) ([]byte, artefacts.TransformationManifest, error) {
	if p.ID == "" || p.Version == "" || p.MaximumBytes < len(quarantinedOutputJSON) ||
		p.MaximumBytes > maximumCapturedBytes ||
		len(captured) == 0 || len(captured) > maximumCapturedBytes {
		return nil, artefacts.TransformationManifest{}, fmt.Errorf("pipeline identity and bounded captured bytes are required")
	}
	rules, err := resolveRules(p.Rules)
	if err != nil {
		return nil, artefacts.TransformationManifest{}, err
	}
	output, outcomes, redactions, err := transformBytes(captured, p.Redactions)
	if err != nil {
		return nil, artefacts.TransformationManifest{}, err
	}
	var tainted []string
	quarantine := len(output) == 0
	if quarantine {
		outcomes = append(outcomes, outcome(ActionRejected, "all_content_removed", "$", 1))
	} else {
		var inspectionOutcomes []artefacts.TransformationOutcome
		tainted, inspectionOutcomes, quarantine = inspectPayload(output, rules)
		outcomes = append(outcomes, inspectionOutcomes...)
	}
	jsonPayload := looksLikeJSON(output)
	truncated := len(output) > p.MaximumBytes
	if truncated && jsonPayload {
		outcomes = append(outcomes, outcome(ActionRejected, "bounded_json_exceeded", "$", 1))
		quarantine = true
	} else if truncated {
		output = truncateUTF8(output, p.MaximumBytes)
		outcomes = append(outcomes, outcome(ActionTruncated, "maximum_output_bytes", "$", 1))
	}
	if quarantine {
		output = []byte(quarantinedOutputJSON)
		outcomes = append(outcomes, outcome(ActionQuarantined, "hostile_or_invalid_content", "$", 1))
	}
	if !quarantine {
		outcomes = append(outcomes, outcome(ActionRetained, "policy_checks_passed", "$", 1))
	}
	sortOutcomes(outcomes)
	sort.Strings(redactions)
	sort.Strings(tainted)
	status := "clean"
	if quarantine {
		status = "quarantined"
	} else if len(tainted) > 0 {
		status = "tainted"
	}
	manifest := artefacts.TransformationManifest{
		ManifestVersion: artefacts.TransformationManifestVersionV1,
		PipelineID:      p.ID, PipelineVersion: p.Version, RulesVersion: rules.Version,
		InputDigest: digest(captured), OutputDigest: digest(output), OverallStatus: status,
		RedactionsApplied: redactions, TaintedFields: slices.Compact(tainted), Outcomes: outcomes,
		Quarantined: quarantine, Truncated: truncated && !quarantine,
		OriginalByteCount: boundedByteCount(len(captured)), OutputByteCount: boundedByteCount(len(output)),
	}
	return output, manifest, nil
}

func resolveRules(configured Rules) (Rules, error) {
	rules := configured
	if rules.Version == "" {
		rules = DefaultRules()
	}
	if rules.Version == "" || rules.MaximumStringBytes <= 0 || rules.MaximumNestingDepth <= 0 ||
		rules.MaximumJSONNodes <= 0 || rules.EncodedTokenMinimum < 32 || rules.RepeatedCharacterLimit < 8 ||
		len(rules.InstructionPatterns) == 0 {
		return Rules{}, fmt.Errorf("complete bounded adversarial sanitisation rules are required")
	}
	for _, field := range rules.FreeTextJSONFields {
		if !safeRuleToken(field) {
			return Rules{}, fmt.Errorf("free-text field rule %q is invalid", field)
		}
	}
	for _, pattern := range rules.InstructionPatterns {
		if pattern == "" || len(pattern) > 256 || strings.IndexFunc(pattern, unicode.IsControl) >= 0 {
			return Rules{}, fmt.Errorf("instruction pattern is invalid")
		}
	}
	return rules, nil
}

func transformBytes(captured []byte, configured map[string]string) (
	output []byte, outcomes []artefacts.TransformationOutcome, redactions []string, err error,
) {
	outcomes = make([]artefacts.TransformationOutcome, 0)
	if !utf8.Valid(captured) {
		output = bytes.ToValidUTF8(captured, []byte("�"))
		outcomes = append(outcomes, outcome(ActionStripped, "invalid_utf8_replaced", "$", 1))
	} else {
		output = append([]byte(nil), captured...)
	}
	redactionKeys := make([]string, 0, len(configured))
	for sensitive := range configured {
		redactionKeys = append(redactionKeys, sensitive)
	}
	sort.Strings(redactionKeys)
	redactions = make([]string, 0, len(redactionKeys))
	for index, sensitive := range redactionKeys {
		replacement := configured[sensitive]
		if sensitive == "" || replacement == "" {
			return nil, nil, nil, fmt.Errorf("redaction values must be non-empty")
		}
		count := bytes.Count(output, []byte(sensitive))
		if count == 0 {
			continue
		}
		output = bytes.ReplaceAll(output, []byte(sensitive), []byte(replacement))
		identifier := redactionIdentifier(index)
		redactions = append(redactions, identifier)
		item := outcome(ActionRedacted, "configured_redaction", "$", boundedByteCount(count))
		item.RulePosition = boundedByteCount(index + 1)
		outcomes = append(outcomes, item)
	}
	output, terminalCount := stripTerminalSequences(output)
	if terminalCount > 0 {
		outcomes = append(outcomes, outcome(ActionStripped, "terminal_escape_sequence", "$", terminalCount))
	}
	output, controlCount := stripRawControls(output)
	if controlCount > 0 {
		outcomes = append(outcomes, outcome(ActionStripped, "raw_control_character", "$", controlCount))
	}
	return output, outcomes, redactions, nil
}

func inspectPayload(payload []byte, rules Rules) ([]string, []artefacts.TransformationOutcome, bool) {
	if !looksLikeJSON(payload) {
		outcomes, quarantine := inspectString(string(payload), "$", rules)
		if !quarantine {
			var taintedOutcomes []artefacts.TransformationOutcome
			taintedOutcomes, quarantine = inspectTaintedString(string(payload), "$", rules)
			outcomes = append(outcomes, taintedOutcomes...)
		}
		return []string{"$"}, append([]artefacts.TransformationOutcome{outcome(ActionTainted, "device_controlled_free_text", "$", 1)}, outcomes...), quarantine
	}
	if !boundedJSONStructure(payload, rules.MaximumNestingDepth, rules.MaximumJSONNodes) {
		return nil, []artefacts.TransformationOutcome{outcome(ActionRejected, "json_structure_limit", "$", 1)}, true
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, []artefacts.TransformationOutcome{outcome(ActionRejected, "invalid_json", "$", 1)}, true
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, []artefacts.TransformationOutcome{outcome(ActionRejected, "multiple_json_values", "$", 1)}, true
	}
	report := inspectionReport{}
	inspectJSONValue(value, "$", "", rules, &report)
	return report.tainted, report.outcomes, report.quarantine
}

type inspectionReport struct {
	tainted    []string
	outcomes   []artefacts.TransformationOutcome
	quarantine bool
}

func inspectJSONValue(value any, path, field string, rules Rules, report *inspectionReport) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			inspectJSONValue(typed[key], path+"/"+escapeJSONPointer(key), key, rules, report)
		}
	case []any:
		for index, item := range typed {
			inspectJSONValue(item, fmt.Sprintf("%s/%d", path, index), field, rules, report)
		}
	case string:
		isTainted := slices.Contains(rules.FreeTextJSONFields, field)
		if isTainted {
			report.tainted = append(report.tainted, path)
			report.outcomes = append(report.outcomes, outcome(ActionTainted, "device_controlled_free_text", path, 1))
		}
		outcomes, quarantine := inspectString(typed, path, rules)
		if isTainted && !quarantine {
			var taintedOutcomes []artefacts.TransformationOutcome
			taintedOutcomes, quarantine = inspectTaintedString(typed, path, rules)
			outcomes = append(outcomes, taintedOutcomes...)
		}
		report.outcomes = append(report.outcomes, outcomes...)
		report.quarantine = report.quarantine || quarantine
	default:
		return
	}
}

func inspectString(value, path string, rules Rules) ([]artefacts.TransformationOutcome, bool) {
	outcomes := make([]artefacts.TransformationOutcome, 0)
	if len(value) > rules.MaximumStringBytes {
		outcomes = append(outcomes, outcome(ActionRejected, "maximum_string_bytes", path, 1))
		return outcomes, true
	}
	normalized := normalizedText(value)
	for index, pattern := range rules.InstructionPatterns {
		if strings.Contains(normalized, normalizedText(pattern)) {
			item := outcome(ActionRejected, "instruction_like_text", path, 1)
			item.RulePosition = boundedByteCount(index + 1)
			outcomes = append(outcomes, item)
			return outcomes, true
		}
	}
	if containsTerminalOrControl(value) {
		outcomes = append(outcomes, outcome(ActionRejected, "encoded_control_or_terminal", path, 1))
		return outcomes, true
	}
	return outcomes, false
}

func inspectTaintedString(value, path string, rules Rules) ([]artefacts.TransformationOutcome, bool) {
	if containsEncodedToken(value, rules.EncodedTokenMinimum) {
		return []artefacts.TransformationOutcome{outcome(ActionRejected, "encoded_payload", path, 1)}, true
	}
	if hasAbnormalRepetition(value, rules.RepeatedCharacterLimit) {
		return []artefacts.TransformationOutcome{outcome(ActionRejected, "abnormal_repetition", path, 1)}, true
	}
	return nil, false
}

func boundedJSONStructure(payload []byte, maximumDepth, maximumNodes int) bool {
	scanner := jsonBoundScanner{maximumDepth: maximumDepth, maximumNodes: maximumNodes}
	for _, char := range payload {
		if !scanner.consume(char) {
			return false
		}
	}
	return scanner.depth == 0 && !scanner.inString && !scanner.escaped
}

type jsonBoundScanner struct {
	depth, nodes               int
	maximumDepth, maximumNodes int
	inString, escaped          bool
}

func (s *jsonBoundScanner) consume(char byte) bool {
	if s.inString {
		return s.consumeString(char)
	}
	switch char {
	case '"':
		s.inString = true
	case '{', '[':
		s.depth++
		s.nodes++
	case '}', ']':
		s.depth--
	case ',':
		s.nodes++
	default:
		return s.withinLimits()
	}
	return s.withinLimits()
}

func (s *jsonBoundScanner) consumeString(char byte) bool {
	switch {
	case s.escaped:
		s.escaped = false
	case char == '\\':
		s.escaped = true
	case char == '"':
		s.inString = false
	default:
		return true
	}
	return true
}

func (s *jsonBoundScanner) withinLimits() bool {
	return s.depth >= 0 && s.depth <= s.maximumDepth && s.nodes <= s.maximumNodes
}

func stripTerminalSequences(input []byte) (output []byte, stripped uint64) {
	output = make([]byte, 0, len(input))
	for index := 0; index < len(input); {
		if input[index] != 0x1b {
			output = append(output, input[index])
			index++
			continue
		}
		stripped++
		index = consumeTerminalSequence(input, index+1)
	}
	return output, stripped
}

func consumeTerminalSequence(input []byte, index int) int {
	if index >= len(input) {
		return index
	}
	switch input[index] {
	case '[':
		return consumeCSI(input, index+1)
	case ']':
		return consumeOSC(input, index+1)
	default:
		return index + 1
	}
}

func consumeCSI(input []byte, index int) int {
	for index < len(input) {
		char := input[index]
		index++
		if char >= 0x40 && char <= 0x7e {
			return index
		}
	}
	return index
}

func consumeOSC(input []byte, index int) int {
	for index < len(input) {
		if input[index] == 0x07 {
			return index + 1
		}
		if input[index] == 0x1b && index+1 < len(input) && input[index+1] == '\\' {
			return index + 2
		}
		index++
	}
	return index
}

func stripRawControls(input []byte) (clean []byte, stripped uint64) {
	clean = make([]byte, 0, len(input))
	for len(input) > 0 {
		char, size := utf8.DecodeRune(input)
		input = input[size:]
		if char == '\n' || char == '\r' || char == '\t' || char >= 0x20 && char != 0x7f {
			clean = utf8.AppendRune(clean, char)
		} else {
			stripped++
		}
	}
	return clean, stripped
}

func containsTerminalOrControl(value string) bool {
	return strings.ContainsRune(value, '\x1b') || strings.IndexFunc(value, func(char rune) bool {
		return unicode.IsControl(char) && char != '\n' && char != '\r' && char != '\t'
	}) >= 0
}

func containsEncodedToken(value string, minimum int) bool {
	base64Run, hexRun, urlEncodedRun := 0, 0, 0
	for index, char := range value {
		if isBase64Character(char) {
			base64Run++
		} else {
			base64Run = 0
		}
		if isHexCharacter(char) {
			hexRun++
		} else {
			hexRun = 0
		}
		if base64Run >= minimum || hexRun >= minimum {
			return true
		}
		if char == '%' && index+2 < len(value) && isHexCharacter(rune(value[index+1])) &&
			isHexCharacter(rune(value[index+2])) {
			urlEncodedRun += 3
		} else if index == 0 || value[index-1] != '%' && (index < 2 || value[index-2] != '%') {
			urlEncodedRun = 0
		}
		if urlEncodedRun >= minimum {
			return true
		}
	}
	return false
}

func isBase64Character(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' ||
		char == '+' || char == '/' || char == '_' || char == '-' || char == '='
}

func isHexCharacter(char rune) bool {
	return char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F'
}

func hasAbnormalRepetition(value string, limit int) bool {
	var previous rune
	run := 0
	for _, char := range value {
		if char == previous {
			run++
		} else {
			previous = char
			run = 1
		}
		if run > limit {
			return true
		}
	}
	return false
}

func normalizedText(value string) string {
	normalized := strings.ToLower(norm.NFKC.String(value))
	return strings.Join(strings.Fields(normalized), " ")
}

func looksLikeJSON(payload []byte) bool {
	trimmed := bytes.TrimSpace(payload)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func truncateUTF8(payload []byte, limit int) []byte {
	for limit > 0 && !utf8.Valid(payload[:limit]) {
		limit--
	}
	return payload[:limit]
}

func sortOutcomes(outcomes []artefacts.TransformationOutcome) {
	sort.Slice(outcomes, func(left, right int) bool {
		if outcomes[left].JSONPath != outcomes[right].JSONPath {
			return outcomes[left].JSONPath < outcomes[right].JSONPath
		}
		if outcomes[left].Action != outcomes[right].Action {
			return outcomes[left].Action < outcomes[right].Action
		}
		return outcomes[left].ReasonCode < outcomes[right].ReasonCode
	})
}

func outcome(action, reason, path string, count uint64) artefacts.TransformationOutcome {
	return artefacts.TransformationOutcome{Action: action, ReasonCode: reason, JSONPath: path, Count: count}
}

func redactionIdentifier(index int) string {
	return fmt.Sprintf("configured-redaction-%04d", index+1)
}

func escapeJSONPointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func safeRuleToken(value string) bool {
	return value != "" && len(value) <= 128 && strings.IndexFunc(value, func(char rune) bool {
		return unicode.IsSpace(char) || unicode.IsControl(char) || char == '/' || char == '~'
	}) < 0
}

func boundedByteCount(value int) uint64 {
	// #nosec G115 -- all inputs are already bounded to 16 MiB or configured limits below that bound.
	return uint64(value)
}

func digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
