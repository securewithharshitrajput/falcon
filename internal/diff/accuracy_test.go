package diff

import (
	"testing"

	"github.com/securewithharshitrajput/falcon/internal/engine"
	"github.com/securewithharshitrajput/falcon/internal/identity"
	"github.com/securewithharshitrajput/falcon/internal/spec"
)

func classify(path string, public bool, params []spec.Parameter, resps ...engine.Response) []Finding {
	op := &spec.Operation{Method: "GET", Path: path, Parameters: params, Public: public}
	req := engine.Request{Method: "GET", URL: "http://x" + path, Meta: op}
	ids := []identity.Identity{
		identity.Bearer("user-a", "a"),
		identity.Bearer("user-b", "b"),
		identity.Anonymous(),
		identity.InvalidFrom(identity.Bearer("user-a", "a")),
	}
	return Classify(req, ids, resps[:len(ids)])
}

func types(fs []Finding) map[string]string {
	m := map[string]string{}
	for _, f := range fs {
		m[f.Type] = f.Severity
	}
	return m
}

// A "soft deny" — HTTP 200 with an error/denial body — must NOT be treated as
// granted access, so an endpoint that refuses everyone with 200+error produces
// no access-control findings.
func TestSoftDenyIsNotSuccess(t *testing.T) {
	deny := `{"error":"forbidden","code":403}`
	fs := classify("/invoices/{id}", false,
		[]spec.Parameter{{Name: "id", In: "path", Required: true, Example: "9"}},
		engine.Response{Status: 200, Body: []byte(deny)},
		engine.Response{Status: 200, Body: []byte(deny)},
		engine.Response{Status: 200, Body: []byte(deny)},
		engine.Response{Status: 200, Body: []byte(deny)},
	)
	if len(fs) != 0 {
		t.Errorf("soft-deny (200 + error body) must produce no findings, got %v", types(fs))
	}
}

// isSoftDeny must not swallow a large data payload that merely contains a
// denial-ish word.
func TestSoftDenyOnlyShortBodies(t *testing.T) {
	big := make([]byte, 0, 400)
	big = append(big, []byte(`{"note":"access to finance is forbidden for guests","records":[`)...)
	for i := 0; i < 20; i++ {
		big = append(big, []byte(`{"id":1,"amount":100},`)...)
	}
	big = append(big, []byte(`{"id":2,"amount":200}]}`)...)
	if isSoftDeny(big) {
		t.Error("a long data payload must not be mistaken for a soft deny")
	}
}

// A spec-declared public endpoint (security: []) that serves no-auth the same
// content as an authed user is behaving to contract — no broken-auth.
func TestDeclaredPublicSuppressesAccessFindings(t *testing.T) {
	body := `{"status":"ok","build":"1.2.3"}`
	fs := classify("/health", true, nil,
		engine.Response{Status: 200, Body: []byte(body)},
		engine.Response{Status: 200, Body: []byte(body)},
		engine.Response{Status: 200, Body: []byte(body)},
		engine.Response{Status: 200, Body: []byte(body)},
	)
	if _, ok := types(fs)["broken-authentication"]; ok {
		t.Errorf("declared-public endpoint must not be flagged broken-auth, got %v", types(fs))
	}
}

// A fully-open endpoint (everyone served the same content) collapses to ONE
// headline finding — broken-authentication — not three restatements.
func TestOpenEndpointDedupesToBrokenAuth(t *testing.T) {
	body := `{"visitors":1203,"signups":44}`
	fs := classify("/public/stats", false, nil,
		engine.Response{Status: 200, Body: []byte(body)},
		engine.Response{Status: 200, Body: []byte(body)},
		engine.Response{Status: 200, Body: []byte(body)},
		engine.Response{Status: 200, Body: []byte(body)},
	)
	got := types(fs)
	if got["broken-authentication"] != SeverityHigh {
		t.Errorf("want broken-authentication HIGH, got %v", got)
	}
	if _, ok := got["invalid-token-accepted"]; ok {
		t.Errorf("invalid-token-accepted should be de-duped away under broken-auth, got %v", got)
	}
	if _, ok := got["cross-user-access"]; ok {
		t.Errorf("cross-user-access should be de-duped away under broken-auth, got %v", got)
	}
}

// When the endpoint DOES validate credentials but fails to scope data to the
// owner, the IDOR still surfaces as cross-user HIGH.
func TestGenuineIdorStillFires(t *testing.T) {
	leaked := `{"owner":"alice","balance":948210,"iban":"DE00 1234"}`
	fs := classify("/accounts/{id}", false,
		[]spec.Parameter{{Name: "id", In: "path", Required: true, Example: "1"}},
		engine.Response{Status: 200, Body: []byte(leaked)},
		engine.Response{Status: 200, Body: []byte(leaked)},
		engine.Response{Status: 401, Body: []byte(`{"error":"unauthenticated"}`)},
		engine.Response{Status: 401, Body: []byte(`{"error":"unauthenticated"}`)},
	)
	if types(fs)["cross-user-access"] != SeverityHigh {
		t.Errorf("genuine IDOR on {id} path must fire cross-user-access HIGH, got %v", types(fs))
	}
}
