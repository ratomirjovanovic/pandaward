package report

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/version"
)

// SARIF renders open findings with a source location as SARIF 2.1.0.
func SARIF(r *Report) ([]byte, error) {
	type msg struct {
		Text string `json:"text"`
	}
	type region struct {
		StartLine int `json:"startLine"`
		EndLine   int `json:"endLine,omitempty"`
	}
	type physical struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *region `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physical `json:"physicalLocation"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []location        `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          map[string]any    `json:"properties"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		Help             msg            `json:"help"`
		Properties       map[string]any `json:"properties"`
	}
	rules := map[string]rule{}
	var results []result
	for _, f := range r.Findings {
		if !f.Status.Active() || f.File == "" || f.File == "(outside-root)" || strings.HasPrefix(f.File, "http://") || strings.HasPrefix(f.File, "https://") {
			continue
		}
		level := "warning"
		switch f.Severity {
		case model.SevCritical, model.SevHigh:
			level = "error"
		case model.SevLow, model.SevInfo:
			level = "note"
		}
		if f.Confidence == model.Hypothesis {
			level = "note"
		}
		if _, ok := rules[f.RuleID]; !ok {
			tags := []string{"security", f.ControlID}
			if f.CWE != "" {
				tags = append(tags, "external/cwe/"+f.CWE)
			}
			rules[f.RuleID] = rule{ID: f.RuleID, Name: f.RuleID, ShortDescription: msg{f.Title}, Help: msg{f.Fix}, Properties: map[string]any{"tags": tags, "precision": precision(f.Confidence)}}
		}
		var loc location
		loc.PhysicalLocation.ArtifactLocation.URI = f.File
		if f.StartLine > 0 {
			loc.PhysicalLocation.Region = &region{StartLine: f.StartLine, EndLine: f.EndLine}
		}
		results = append(results, result{RuleID: f.RuleID, Level: level, Message: msg{f.ID + ": " + f.Message}, Locations: []location{loc},
			PartialFingerprints: map[string]string{"pensecFingerprint/v1": f.Fingerprint},
			Properties:          map[string]any{"pensec_id": f.ID, "severity": f.Severity, "confidence": f.Confidence, "control": f.ControlID, "evidence": f.EvidenceIDs}})
	}
	var rl []rule
	for _, v := range rules {
		rl = append(rl, v)
	}
	sort.Slice(rl, func(i, j int) bool { return rl[i].ID < rl[j].ID })
	if results == nil {
		results = []result{}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":       map[string]any{"driver": map[string]any{"name": "PenSec", "version": version.Version, "rules": rl}},
			"results":    results,
			"properties": map[string]any{"assessment_id": r.Assessment.ID, "attestation": Attestation},
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func precision(c model.Confidence) string {
	switch c {
	case model.Confirmed:
		return "very-high"
	case model.StronglySupported:
		return "high"
	}
	return "low"
}
