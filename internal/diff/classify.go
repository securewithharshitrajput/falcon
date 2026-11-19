// Core differential classifier: turn a matrix of responses (one per
// identity, same request) into named findings.
//
// Falcon's premise is that one request fired as several identities produces
// a response matrix whose SHAPE tells you what's wrong. Rather than guess
// per-endpoint ("this looks weird"), we enumerate a small set of
// well-defined patterns and name each one. An operator can reason about
// "broken-authentication" (no-auth and real-user returned the same thing)
// in a way they cannot reason about "the scanner flagged this."
package diff

import (
	"github.com/securewithharshitrajput/falcon/internal/engine"
	"github.com/securewithharshitrajput/falcon/internal/identity"
	"github.com/securewithharshitrajput/falcon/internal/spec"
)

// similarityThreshold is the Hamming distance under which two SimHashes
// count as "same content shape." Empirically ~8 covers typical
// per-request cosmetic variance (timestamp, request-id, nonce) without
// collapsing genuinely different pages together.
const similarityThreshold = 8

// Severity constants mirror hellhound's scale so a combined reporting
// surface can use one vocabulary.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
	SeverityInfo   = "info"
)

// Finding is one named security observation produced by comparing the
// response matrix for a single operation.
type Finding struct {
	Type        string        `json:"type"`
	Severity    string        `json:"severity"`
	Operation   string        `json:"operation"` // "GET /users/{id}"
	Description string        `json:"description"`
	Evidence    []EvidenceRow `json:"evidence"`
}

// EvidenceRow is the per-identity line falcon shows so the operator can
// audit the classification without re-firing the requests themselves.
type EvidenceRow struct {
	Role   string `json:"role"`
	Status int    `json:"status"`
	Length int    `json:"length"`
	Note   string `json:"note,omitempty"`
}

// Classify analyzes the response matrix for one operation and returns the
// findings it produced. identities and responses must be aligned 1:1 by
// index — responses[i] is what identities[i] got when firing req.
//
// The pair-and-match patterns below are deliberately conservative: each
// one has a distinct response-matrix signature, and a matrix that fits
// several patterns produces several findings (an endpoint that both
// accepts no-auth AND exposes the same body across users is both broken-
// auth and IDOR — the operator wants to see both).
func Classify(req engine.Request, identities []identity.Identity, responses []engine.Response) []Finding {
	if len(identities) != len(responses) {
		return nil
	}
	op := operationLabel(req)

	// Index identities by convenient role tags. anonIdx/invalidIdx keep the
	// actual slice positions so evidence rows can name the exact responses
	// that drove a finding (not just "some anon response somewhere").
	var anonResp, invalidResp *engine.Response
	anonIdx, invalidIdx := -1, -1
	var authed []int // indices of real (non-anon, non-invalid) identities
	for i, id := range identities {
		r := &responses[i]
		switch {
		case id.IsAnon:
			anonResp = r
			anonIdx = i
		case id.IsInvalid:
			invalidResp = r
			invalidIdx = i
		default:
			authed = append(authed, i)
		}
	}

	var findings []Finding

	// Pattern 1: broken authentication.
	// If an authenticated identity returned success AND no-auth returned
	// success with a similar-shape body, the auth check isn't actually
	// gating this endpoint.
	if anonResp != nil && isSuccess(*anonResp) {
		for _, i := range authed {
			a := responses[i]
			if !isSuccess(a) {
				continue
			}
			if !similarShape(a, *anonResp) {
				continue
			}
			findings = append(findings, Finding{
				Type:        "broken-authentication",
				Severity:    SeverityHigh,
				Operation:   op,
				Description: "no-auth request returned success with the same body shape as an authenticated request — the endpoint does not enforce authentication",
				Evidence:    evidenceRows(identities, responses, i, anonIdx),
			})
			break // one finding per endpoint is enough — the point is made
		}
	}

	// Pattern 2: invalid-token accepted.
	// An auth header that is OBVIOUSLY garbage returned success → the
	// middleware isn't actually validating the token, just checking the
	// header is present.
	if invalidResp != nil && isSuccess(*invalidResp) {
		for _, i := range authed {
			if isSuccess(responses[i]) && similarShape(responses[i], *invalidResp) {
				findings = append(findings, Finding{
					Type:        "invalid-token-accepted",
					Severity:    SeverityHigh,
					Operation:   op,
					Description: "a request with an obviously invalid bearer token returned the same success body as a real-user request — token validation is not actually performed",
					Evidence:    evidenceRows(identities, responses, i, invalidIdx),
				})
				break
			}
		}
	}

	// Pattern 3: cross-user access (IDOR).
	// Two real users both got success AND the same body shape → user B
	// sees user A's resource.
	for ai := 0; ai < len(authed); ai++ {
		for bi := ai + 1; bi < len(authed); bi++ {
			a, b := responses[authed[ai]], responses[authed[bi]]
			if !isSuccess(a) || !isSuccess(b) {
				continue
			}
			// An empty (or whitespace-only) body is no evidence of a shared
			// *resource*: two users both hitting an endpoint that returns an
			// empty 200/204 is the single most common cross-user false
			// positive. Require a substantive body on both sides before
			// calling it IDOR.
			if !substantive(a) || !substantive(b) {
				continue
			}
			if !similarShape(a, b) {
				continue
			}
			// If the path contains {id}/{uid}/{slug} etc., the test is more
			// damning — the point is that one user accessed the other's
			// identified resource. If the path has no parameter, the
			// endpoint might legitimately return the same global list to
			// everyone (lower severity).
			sev := SeverityMedium
			if pathHasID(req.URL, req) {
				sev = SeverityHigh
			}
			findings = append(findings, Finding{
				Type:        "cross-user-access",
				Severity:    sev,
				Operation:   op,
				Description: "two distinct user identities received success responses with the same body shape — same resource visible to both (IDOR if the path addresses a specific resource)",
				Evidence:    evidenceRows(identities, responses, authed[ai], authed[bi]),
			})
		}
	}

	// Pattern 4: inconsistent auth across identities (anomaly).
	// Some real users got 200, others got 403/401 for the SAME request
	// where the path is NOT ownership-scoped → the authorization policy
	// varies by user in an un-obvious way. On a parameterized path like
	// /users/{id} this is just normal owner-only semantics and must NOT
	// fire, or every well-designed REST API would be flagged on every
	// resource endpoint.
	if len(authed) >= 2 && !pathHasID(req.URL, req) {
		success, denied := 0, 0
		for _, i := range authed {
			if isSuccess(responses[i]) {
				success++
			} else if isAuthDenied(responses[i]) {
				denied++
			}
		}
		if success > 0 && denied > 0 && !findingExists(findings, "cross-user-access") {
			findings = append(findings, Finding{
				Type:        "role-differential",
				Severity:    SeverityInfo,
				Operation:   op,
				Description: "test identities received materially different authorization outcomes for the same non-ownership-scoped request — review whether this reflects intended RBAC or a vertical-privilege leak",
				Evidence:    evidenceRowsAll(identities, responses),
			})
		}
	}

	// Pattern 5: server error under adversarial auth (low-signal but worth
	// flagging — 500s under test are often auth-middleware bugs).
	for i, id := range identities {
		if isServerError(responses[i]) {
			findings = append(findings, Finding{
				Type:        "auth-server-error",
				Severity:    SeverityLow,
				Operation:   op,
				Description: "identity \"" + id.Role + "\" triggered a 5xx response — a server error under adversarial auth input often indicates an exception path in middleware worth inspecting",
				Evidence:    evidenceRowsAll(identities, responses),
			})
			break // one 5xx finding per endpoint
		}
	}

	return findings
}

func isSuccess(r engine.Response) bool {
	return r.Err == nil && r.Status >= 200 && r.Status < 300
}

func isAuthDenied(r engine.Response) bool {
	return r.Err == nil && (r.Status == 401 || r.Status == 403)
}

func isServerError(r engine.Response) bool {
	return r.Err == nil && r.Status >= 500 && r.Status < 600
}

func similarShape(a, b engine.Response) bool {
	ha := Hash(a.Body)
	hb := Hash(b.Body)
	return Hamming(ha, hb) <= similarityThreshold
}

// substantive reports whether a response carries a non-trivial body after
// volatile-token normalization — i.e. there is actual content whose shared
// presence across identities is meaningful evidence.
func substantive(r engine.Response) bool {
	return len(Normalize(r.Body)) > 0
}

func pathHasID(fullURL string, req engine.Request) bool {
	op, ok := req.Meta.(*spec.Operation)
	if !ok {
		return false
	}
	for _, p := range op.Parameters {
		if p.In == "path" {
			return true
		}
	}
	return false
}

func operationLabel(req engine.Request) string {
	if op, ok := req.Meta.(*spec.Operation); ok {
		return req.Method + " " + op.Path
	}
	return req.Method + " " + req.URL
}

func evidenceRows(identities []identity.Identity, responses []engine.Response, idx ...int) []EvidenceRow {
	seen := map[int]bool{}
	var out []EvidenceRow
	for _, i := range idx {
		if i < 0 || i >= len(identities) || seen[i] {
			continue
		}
		seen[i] = true
		out = append(out, rowFor(identities[i], responses[i]))
	}
	// Always include anon + invalid for context when present.
	for i, id := range identities {
		if seen[i] {
			continue
		}
		if id.IsAnon || id.IsInvalid {
			out = append(out, rowFor(id, responses[i]))
		}
	}
	return out
}

func evidenceRowsAll(identities []identity.Identity, responses []engine.Response) []EvidenceRow {
	out := make([]EvidenceRow, len(identities))
	for i := range identities {
		out[i] = rowFor(identities[i], responses[i])
	}
	return out
}

func rowFor(id identity.Identity, r engine.Response) EvidenceRow {
	row := EvidenceRow{Role: id.Role, Status: r.Status, Length: r.Length}
	if r.Err != nil {
		row.Note = "error: " + r.Err.Error()
	}
	return row
}

func findingExists(findings []Finding, t string) bool {
	for _, f := range findings {
		if f.Type == t {
			return true
		}
	}
	return false
}
