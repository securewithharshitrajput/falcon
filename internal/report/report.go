// Package report renders a batch of diff.Finding into the operator-facing
// outputs: a compact terminal summary, a JSON document for CI/pipelines,
// and SARIF 2.1.0 for GitHub code scanning. A finding is kept flat — one
// record per observation — rather than clustered, because falcon's findings
// are already distinct by (operation × pattern) and there's nothing to
// collapse.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/securewithharshitrajput/falcon/internal/diff"
)

// Document is the top-level report. Target is the base URL under test;
// Findings is the full flat list sorted most-severe first.
type Document struct {
	Target   string         `json:"target"`
	Total    int            `json:"total_findings"`
	Findings []diff.Finding `json:"findings"`
}

var severityRank = map[string]int{
	diff.SeverityHigh:   4,
	diff.SeverityMedium: 3,
	diff.SeverityLow:    2,
	diff.SeverityInfo:   1,
}

// Build sorts and returns the final Document.
func Build(target string, findings []diff.Finding) Document {
	sorted := make([]diff.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		if ri, rj := severityRank[sorted[i].Severity], severityRank[sorted[j].Severity]; ri != rj {
			return ri > rj
		}
		if sorted[i].Operation != sorted[j].Operation {
			return sorted[i].Operation < sorted[j].Operation
		}
		return sorted[i].Type < sorted[j].Type
	})
	return Document{Target: target, Total: len(sorted), Findings: sorted}
}

// WriteSummary prints the human-readable one-pane view to w.
func WriteSummary(w io.Writer, d Document) {
	fmt.Fprintf(w, "falcon: %d finding(s) for %s\n\n", d.Total, d.Target)
	for _, f := range d.Findings {
		fmt.Fprintf(w, "  [%s] %-24s %s\n", severityLabel(f.Severity), f.Type, f.Operation)
		fmt.Fprintf(w, "        %s\n", f.Description)
		for _, e := range f.Evidence {
			note := ""
			if e.Note != "" {
				note = "   " + e.Note
			}
			fmt.Fprintf(w, "        - %-16s status=%-3d len=%d%s\n", e.Role, e.Status, e.Length, note)
		}
		fmt.Fprintln(w)
	}
}

// WriteJSON writes d as indented JSON — the format pipelines and other
// tools should consume.
func WriteJSON(w io.Writer, d Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

// --- SARIF 2.1.0 ---

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// WriteSARIF emits SARIF 2.1.0 with one rule per finding type. Maps
// hellhound-compatible severities to SARIF levels (high→error, medium/low→
// warning, info→note).
func WriteSARIF(w io.Writer, d Document) error {
	rules := []sarifRule{
		{ID: "falcon/broken-authentication", Name: "BrokenAuthentication", ShortDescription: sarifText{Text: "Endpoint accepted an unauthenticated request with the same body as an authenticated one"}},
		{ID: "falcon/invalid-token-accepted", Name: "InvalidTokenAccepted", ShortDescription: sarifText{Text: "Endpoint accepted an obviously invalid bearer token"}},
		{ID: "falcon/cross-user-access", Name: "CrossUserAccess", ShortDescription: sarifText{Text: "Distinct user identities returned the same resource body (IDOR)"}},
		{ID: "falcon/role-differential", Name: "RoleDifferential", ShortDescription: sarifText{Text: "Test identities received different authorization outcomes for the same request"}},
		{ID: "falcon/auth-server-error", Name: "AuthServerError", ShortDescription: sarifText{Text: "Server returned 5xx under adversarial authentication input"}},
	}
	doc := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "falcon",
				InformationURI: "https://github.com/securewithharshitrajput/falcon",
				Rules:          rules,
			}},
			Results: []sarifResult{},
		}},
	}
	for _, f := range d.Findings {
		doc.Runs[0].Results = append(doc.Runs[0].Results, sarifResult{
			RuleID:  "falcon/" + f.Type,
			Level:   sarifLevelFor(f.Severity),
			Message: sarifText{Text: "[" + strings.ToUpper(f.Severity) + "] " + f.Operation + " — " + f.Description},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.Operation},
				},
			}},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevelFor(sev string) string {
	switch sev {
	case diff.SeverityHigh:
		return "error"
	case diff.SeverityMedium, diff.SeverityLow:
		return "warning"
	case diff.SeverityInfo:
		return "note"
	}
	return "note"
}

func severityLabel(s string) string {
	switch s {
	case diff.SeverityHigh:
		return "HIGH  "
	case diff.SeverityMedium:
		return "MEDIUM"
	case diff.SeverityLow:
		return "LOW   "
	case diff.SeverityInfo:
		return "INFO  "
	}
	return s
}
