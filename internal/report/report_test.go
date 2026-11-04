package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/securewithharshitrajput/falcon/internal/diff"
)

func TestBuildSortsHighestSeverityFirst(t *testing.T) {
	fs := []diff.Finding{
		{Type: "role-differential", Severity: diff.SeverityInfo, Operation: "GET /x"},
		{Type: "cross-user-access", Severity: diff.SeverityHigh, Operation: "GET /y"},
		{Type: "auth-server-error", Severity: diff.SeverityLow, Operation: "GET /z"},
		{Type: "broken-authentication", Severity: diff.SeverityHigh, Operation: "GET /a"},
	}
	d := Build("http://t", fs)
	if d.Findings[0].Severity != diff.SeverityHigh || d.Findings[1].Severity != diff.SeverityHigh {
		t.Errorf("highs did not sort to the top: %+v", d.Findings)
	}
	if d.Findings[len(d.Findings)-1].Severity != diff.SeverityInfo {
		t.Errorf("info did not sort to the bottom: %+v", d.Findings)
	}
}

func TestWriteSummaryIncludesOperationAndSeverity(t *testing.T) {
	d := Build("http://t", []diff.Finding{
		{Type: "cross-user-access", Severity: diff.SeverityHigh, Operation: "GET /users/{id}", Description: "A saw B's data",
			Evidence: []diff.EvidenceRow{{Role: "user-a", Status: 200, Length: 120}, {Role: "user-b", Status: 200, Length: 120}}},
	})
	var buf bytes.Buffer
	WriteSummary(&buf, d)
	out := buf.String()
	if !strings.Contains(out, "HIGH") || !strings.Contains(out, "GET /users/{id}") {
		t.Errorf("summary missing severity/operation line, got:\n%s", out)
	}
	if !strings.Contains(out, "user-a") || !strings.Contains(out, "user-b") {
		t.Errorf("summary missing evidence rows, got:\n%s", out)
	}
}

func TestWriteJSONIsValidAndIncludesFindings(t *testing.T) {
	d := Build("http://t", []diff.Finding{
		{Type: "broken-authentication", Severity: diff.SeverityHigh, Operation: "GET /x"},
	})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, d); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded["target"] != "http://t" {
		t.Errorf("target lost: %v", decoded["target"])
	}
}

func TestWriteSARIFMapsSeveritiesCorrectly(t *testing.T) {
	d := Build("http://t", []diff.Finding{
		{Type: "broken-authentication", Severity: diff.SeverityHigh, Operation: "GET /a"},
		{Type: "role-differential", Severity: diff.SeverityInfo, Operation: "GET /b"},
	})
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, d); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	s := buf.String()
	if !strings.Contains(s, `"error"`) || !strings.Contains(s, `"note"`) {
		t.Errorf("expected SARIF to contain error and note levels, got:\n%s", s)
	}
	if !strings.Contains(s, "falcon/broken-authentication") {
		t.Errorf("rule id missing: %s", s)
	}
}
