package diff

import (
	"testing"

	"github.com/securewithharshitrajput/falcon/internal/engine"
	"github.com/securewithharshitrajput/falcon/internal/identity"
	"github.com/securewithharshitrajput/falcon/internal/spec"
)

// Helper: build the standard 4-identity matrix (A, B, anon, invalid) and
// run Classify on it.
func classifyMatrix(path string, statusA, statusB, statusAnon, statusInv int, bodyA, bodyB, bodyAnon, bodyInv string) []Finding {
	op := &spec.Operation{
		Method: "GET",
		Path:   path,
		Parameters: []spec.Parameter{
			{Name: "id", In: "path", Required: true, Example: "42"},
		},
	}
	req := engine.Request{Method: "GET", URL: "http://x" + path, Meta: op}
	ids := []identity.Identity{
		identity.Bearer("user-a", "a"),
		identity.Bearer("user-b", "b"),
		identity.Anonymous(),
		identity.Invalid(),
	}
	resps := []engine.Response{
		{Status: statusA, Body: []byte(bodyA), Length: len(bodyA)},
		{Status: statusB, Body: []byte(bodyB), Length: len(bodyB)},
		{Status: statusAnon, Body: []byte(bodyAnon), Length: len(bodyAnon)},
		{Status: statusInv, Body: []byte(bodyInv), Length: len(bodyInv)},
	}
	return Classify(req, ids, resps)
}

// A healthy endpoint: owner gets 200, other user gets 403, anon/invalid 401
// — no findings should fire.
func TestClassifyCleanEndpointProducesNoFindings(t *testing.T) {
	findings := classifyMatrix("/users/{id}",
		200, 403, 401, 401,
		`{"user":"alice","id":42,"profile":"private data for alice only"}`,
		`{"error":"forbidden"}`,
		`{"error":"unauthenticated"}`,
		`{"error":"invalid token"}`,
	)
	if len(findings) != 0 {
		t.Errorf("clean endpoint produced %d findings: %v", len(findings), findings)
	}
}

// Classic broken-auth: no-auth returned the same shape as authenticated.
func TestClassifyBrokenAuthFires(t *testing.T) {
	body := `{"users":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]}`
	findings := classifyMatrix("/users",
		200, 200, 200, 200,
		body, body, body, body,
	)
	found := false
	for _, f := range findings {
		if f.Type == "broken-authentication" && f.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected broken-authentication HIGH, got %v", findings)
	}
}

// Invalid-token-accepted: bogus token gives same success body as real user.
func TestClassifyInvalidTokenAcceptedFires(t *testing.T) {
	body := `{"user":"alice","email":"alice@example.com"}`
	findings := classifyMatrix("/me",
		200, 403, 401, 200,
		body, `{"error":"forbidden"}`, `{"error":"no auth"}`, body,
	)
	found := false
	for _, f := range findings {
		if f.Type == "invalid-token-accepted" && f.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid-token-accepted HIGH, got %v", findings)
	}
}

// Cross-user/IDOR on a path with {id} → severity must be HIGH.
func TestClassifyCrossUserHighOnParameterizedPath(t *testing.T) {
	leaked := `{"owner":"alice","email":"alice@example.com","ssn":"***","notes":"private file"}`
	findings := classifyMatrix("/users/{id}",
		200, 200, 401, 401,
		leaked, leaked, `{"error":"no auth"}`, `{"error":"invalid"}`,
	)
	found := false
	for _, f := range findings {
		if f.Type == "cross-user-access" && f.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cross-user-access HIGH on {id} path, got %v", findings)
	}
}

// Same hits, but path has NO parameter — severity degrades to medium
// because a shared global list is a different scenario than an IDOR'd
// per-user resource.
func TestClassifyCrossUserMediumOnNonParameterizedPath(t *testing.T) {
	op := &spec.Operation{Method: "GET", Path: "/dashboard"}
	req := engine.Request{Method: "GET", URL: "http://x/dashboard", Meta: op}
	ids := []identity.Identity{
		identity.Bearer("user-a", "a"),
		identity.Bearer("user-b", "b"),
	}
	same := `{"items":[1,2,3],"meta":"shared list"}`
	resps := []engine.Response{
		{Status: 200, Body: []byte(same), Length: len(same)},
		{Status: 200, Body: []byte(same), Length: len(same)},
	}
	findings := Classify(req, ids, resps)
	foundMedium := false
	for _, f := range findings {
		if f.Type == "cross-user-access" && f.Severity == SeverityMedium {
			foundMedium = true
		}
		if f.Type == "cross-user-access" && f.Severity == SeverityHigh {
			t.Errorf("shared-list endpoint should NOT be HIGH (that scenario is often intentional): %v", f)
		}
	}
	if !foundMedium {
		t.Errorf("expected cross-user-access MEDIUM on non-parameterized path, got %v", findings)
	}
}

// Role differential (one real user succeeds, another gets 403) is INFO —
// surface it for human review but don't call it a finding. MUST only fire
// on non-parameterized paths so a normal owner-only /users/{id} isn't
// flagged.
func TestClassifyRoleDifferentialIsInfo(t *testing.T) {
	// Non-parameterized path — role differential IS a real anomaly worth
	// surfacing for review.
	op := &spec.Operation{Method: "GET", Path: "/admin/stats"}
	req := engine.Request{Method: "GET", URL: "http://x/admin/stats", Meta: op}
	ids := []identity.Identity{
		identity.Bearer("user-a", "a"),
		identity.Bearer("user-b", "b"),
		identity.Anonymous(),
		identity.Invalid(),
	}
	resps := []engine.Response{
		{Status: 200, Body: []byte(`{"total":42}`)},
		{Status: 403, Body: []byte(`{"error":"admin only"}`)},
		{Status: 401, Body: []byte(`{"error":"no auth"}`)},
		{Status: 401, Body: []byte(`{"error":"invalid"}`)},
	}
	findings := Classify(req, ids, resps)
	found := false
	for _, f := range findings {
		if f.Type == "role-differential" && f.Severity == SeverityInfo {
			found = true
		}
	}
	if !found {
		t.Errorf("expected role-differential INFO on non-parameterized path, got %v", findings)
	}
}

// The critical invariant: an ownership-scoped path where user-a owns the
// resource (200) and user-b doesn't (403) is normal REST behavior and must
// produce ZERO findings.
func TestClassifyOwnerOnlyPathIsClean(t *testing.T) {
	findings := classifyMatrix("/users/{id}",
		200, 403, 401, 401,
		`{"user":"alice","id":42}`, `{"error":"forbidden"}`, `{"error":"no auth"}`, `{"error":"invalid"}`,
	)
	if len(findings) != 0 {
		t.Errorf("owner-only path produced spurious findings: %v", findings)
	}
}

// 500 under adversarial auth is low-signal but noteworthy.
func TestClassify5xxUnderAuthIsLow(t *testing.T) {
	findings := classifyMatrix("/weird",
		200, 500, 401, 401,
		`{"ok":true}`, `{"error":"internal"}`, `{}`, `{}`,
	)
	found := false
	for _, f := range findings {
		if f.Type == "auth-server-error" && f.Severity == SeverityLow {
			found = true
		}
	}
	if !found {
		t.Errorf("expected auth-server-error LOW, got %v", findings)
	}
}
