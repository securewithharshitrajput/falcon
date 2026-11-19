package diff

import (
	"testing"

	"github.com/securewithharshitrajput/falcon/internal/engine"
	"github.com/securewithharshitrajput/falcon/internal/identity"
	"github.com/securewithharshitrajput/falcon/internal/spec"
)

// Two users both getting an empty 200 body is NOT evidence of a shared
// resource — it's the most common cross-user false positive. It must not
// produce a cross-user-access finding.
func TestClassifyEmptyBodyIsNotCrossUser(t *testing.T) {
	op := &spec.Operation{
		Method:     "GET",
		Path:       "/users/{id}/avatar",
		Parameters: []spec.Parameter{{Name: "id", In: "path", Required: true, Example: "1"}},
	}
	req := engine.Request{Method: "GET", URL: "http://x/users/1/avatar", Meta: op}
	ids := []identity.Identity{identity.Bearer("user-a", "a"), identity.Bearer("user-b", "b")}
	resps := []engine.Response{
		{Status: 200, Body: []byte(""), Length: 0},
		{Status: 200, Body: []byte("   "), Length: 3},
	}
	for _, f := range Classify(req, ids, resps) {
		if f.Type == "cross-user-access" {
			t.Errorf("empty-body responses must not be flagged cross-user-access: %+v", f)
		}
	}
}

// With a real shared body, the empty-body guard must not suppress a genuine
// IDOR.
func TestClassifyNonEmptySharedBodyStillFiresCrossUser(t *testing.T) {
	leaked := `{"owner":"alice","balance":100000,"card":"****"}`
	op := &spec.Operation{
		Method:     "GET",
		Path:       "/accounts/{id}",
		Parameters: []spec.Parameter{{Name: "id", In: "path", Required: true, Example: "1"}},
	}
	req := engine.Request{Method: "GET", URL: "http://x/accounts/1", Meta: op}
	ids := []identity.Identity{identity.Bearer("user-a", "a"), identity.Bearer("user-b", "b")}
	resps := []engine.Response{
		{Status: 200, Body: []byte(leaked), Length: len(leaked)},
		{Status: 200, Body: []byte(leaked), Length: len(leaked)},
	}
	found := false
	for _, f := range Classify(req, ids, resps) {
		if f.Type == "cross-user-access" && f.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Error("real shared body should still fire cross-user-access HIGH")
	}
}

// Evidence for broken-authentication must name the no-auth response (status
// and length), which regressed silently when indexOf always returned -1.
func TestBrokenAuthEvidenceNamesAnon(t *testing.T) {
	body := `{"stats":"public-ish"}`
	op := &spec.Operation{Method: "GET", Path: "/public/stats"}
	req := engine.Request{Method: "GET", URL: "http://x/public/stats", Meta: op}
	ids := []identity.Identity{identity.Bearer("user-a", "a"), identity.Anonymous(), identity.Invalid()}
	resps := []engine.Response{
		{Status: 200, Body: []byte(body), Length: len(body)},
		{Status: 200, Body: []byte(body), Length: len(body)},
		{Status: 200, Body: []byte(body), Length: len(body)},
	}
	var ba *Finding
	for i := range Classify(req, ids, resps) {
		f := Classify(req, ids, resps)[i]
		if f.Type == "broken-authentication" {
			ba = &f
			break
		}
	}
	if ba == nil {
		t.Fatal("expected a broken-authentication finding")
	}
	sawAnon := false
	for _, e := range ba.Evidence {
		if e.Role == "no-auth" {
			sawAnon = true
			if e.Status != 200 {
				t.Errorf("no-auth evidence status = %d, want 200", e.Status)
			}
		}
	}
	if !sawAnon {
		t.Errorf("broken-auth evidence must include the no-auth row, got %+v", ba.Evidence)
	}
}
