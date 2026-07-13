// Package sanitise creates a separately digested safe derivative of captured bytes.
package sanitise

import (
	"bytes"
	"fmt"
	"sort"
	"unicode/utf8"

	"network_broker/internal/artefacts"
)

type Pipeline struct {
	ID           string
	Version      string
	Redactions   map[string]string
	MaximumBytes int
}

func (p Pipeline) Transform(captured []byte) ([]byte, artefacts.TransformationManifest, error) {
	if p.ID == "" || p.Version == "" || p.MaximumBytes <= 0 || len(captured) == 0 {
		return nil, artefacts.TransformationManifest{}, fmt.Errorf("pipeline identity, limit and captured bytes are required")
	}
	output := bytes.ToValidUTF8(captured, []byte("�"))
	applied := make([]string, 0)
	for sensitive, replacement := range p.Redactions {
		if sensitive == "" || replacement == "" {
			return nil, artefacts.TransformationManifest{}, fmt.Errorf("redaction values must be non-empty")
		}
		if bytes.Contains(output, []byte(sensitive)) {
			output = bytes.ReplaceAll(output, []byte(sensitive), []byte(replacement))
			applied = append(applied, sensitive)
		}
	}
	clean := make([]byte, 0, len(output))
	for len(output) > 0 {
		r, size := utf8.DecodeRune(output)
		output = output[size:]
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 {
			clean = utf8.AppendRune(clean, r)
		}
	}
	truncated := len(clean) > p.MaximumBytes
	if truncated {
		limit := p.MaximumBytes
		for limit > 0 && !utf8.Valid(clean[:limit]) {
			limit--
		}
		clean = clean[:limit]
	}
	sort.Strings(applied)
	manifest := artefacts.TransformationManifest{PipelineID: p.ID, PipelineVersion: p.Version,
		RedactionsApplied: applied, Truncated: truncated, OriginalByteCount: uint64(len(captured)), OutputByteCount: uint64(len(clean))}
	return clean, manifest, nil
}
