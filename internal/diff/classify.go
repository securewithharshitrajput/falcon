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
	"regexp"
	"strings"

	"github.com/securewithharshitrajput/falcon/internal/engine"
	"github.com/securewithharshitrajput/falcon/internal/identity"
	"github.com/securewithharshitrajput/falcon/internal/spec"
)

// similarityThreshold is the minimum Jaccard overlap (0..1) of two bodies'
// token-shingle sets for them to count as "the same resource." 0.6 keeps
// genuinely-identical resources together through per-request cosmetic variance
// (a changed timestamp or latency number) while separating distinct users'
// data, whose field VALUES differ.
const similarityThreshold = 0.6

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

	// If the spec explicitly declares this operation public (op-level
	// `security: []`, or no security requirement anywhere), then "no auth
	// works" is the CONTRACT, not a bug. Suppress the whole access-control
	// family for it — only a server crash (pattern 5) stays meaningful.
	public := isDeclaredPublic(req)

	// The access-control findings overlap: an endpoint that serves protected
	// content to no-auth is simply open to the world, which also makes an
	// invalid token "work" and makes two users "see the same thing." Report
	// the single most-root-cause finding instead of three restatements of
	// the same hole. Precedence: broken-auth > invalid-token-accepted >
	// cross-user-access. `handled` records that a more-fundamental finding
	// already covers this endpoint.
	handled := false

	// Pattern 1: broken authentication.
	// If an authenticated identity was granted access AND no-auth was granted
	// access with a similar-shape body, the auth check isn't actually gating
	// this endpoint.
	if !public && anonResp != nil && grantsAccess(*anonResp) {
		for _, i := range authed {
			a := responses[i]
			if !grantsAccess(a) || !similarShape(a, *anonResp) {
				continue
			}
			findings = append(findings, Finding{
				Type:        "broken-authentication",
				Severity:    SeverityHigh,
				Operation:   op,
				Description: "no-auth request was served protected content with the same body shape as an authenticated request — the endpoint does not enforce authentication",
				Evidence:    evidenceRows(identities, responses, i, anonIdx),
			})
			handled = true
			break // one finding per endpoint is enough — the point is made
		}
	}

	// Pattern 2: invalid-token accepted.
	// A credential that is OBVIOUSLY garbage (same scheme as a real user, but
	// a canary value) was granted access → the middleware isn't actually
	// validating the credential, just checking that one is present.
	if !public && !handled && invalidResp != nil && grantsAccess(*invalidResp) {
		for _, i := range authed {
			if grantsAccess(responses[i]) && similarShape(responses[i], *invalidResp) {
				findings = append(findings, Finding{
					Type:        "invalid-token-accepted",
					Severity:    SeverityHigh,
					Operation:   op,
					Description: "a request with an obviously invalid credential was served the same protected content as a real-user request — credential validation is not actually performed",
					Evidence:    evidenceRows(identities, responses, i, invalidIdx),
				})
				handled = true
				break
			}
		}
	}

	// Pattern 3: cross-user access (IDOR).
	// Two real users were both granted access AND got the same body shape →
	// user B sees user A's resource.
	if !public && !handled {
		for ai := 0; ai < len(authed) && !handled; ai++ {
			for bi := ai + 1; bi < len(authed); bi++ {
				a, b := responses[authed[ai]], responses[authed[bi]]
				if !grantsAccess(a) || !grantsAccess(b) {
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
					Description: "two distinct user identities were served the same body shape — same resource visible to both (IDOR if the path addresses a specific resource)",
					Evidence:    evidenceRows(identities, responses, authed[ai], authed[bi]),
				})
				handled = true
				break
			}
		}
	}

	// Pattern 4: inconsistent auth across identities (anomaly).
	// Some real users were granted access, others got 403/401 for the SAME
	// request where the path is NOT ownership-scoped → the authorization
	// policy varies by user in an un-obvious way. On a parameterized path
	// like /users/{id} this is just normal owner-only semantics and must NOT
	// fire, or every well-designed REST API would be flagged on every
	// resource endpoint.
	if !public && !handled && len(authed) >= 2 && !pathHasID(req.URL, req) {
		success, denied := 0, 0
		for _, i := range authed {
			if grantsAccess(responses[i]) {
				success++
			} else if isAuthDenied(responses[i]) {
				denied++
			}
		}
		if success > 0 && denied > 0 {
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

// grantsAccess reports whether a response actually served protected content —
// a 2xx that is NOT a "soft deny." Many APIs (GraphQL-flavored, legacy, some
// gateways) answer an unauthorized request with HTTP 200 and an error body
// like {"error":"forbidden"}; treating that as success produces phantom
// broken-auth / IDOR findings, so it must be excluded.
func grantsAccess(r engine.Response) bool {
	return isSuccess(r) && !isSoftDeny(r.Body)
}

// denyCodePattern matches an explicit 401/403 status embedded in a body, e.g.
// `"code":403`, `"status": 401`, `statusCode=403`.
var denyCodePattern = regexp.MustCompile(`(?:code|status|statuscode|http_status)"?\s*[:=]\s*"?(?:401|403)\b`)

// denyPhrases are substrings that, in a SHORT body, signal an authorization
// refusal rather than real content.
var denyPhrases = []string{
	"forbidden", "unauthorized", "unauthenticated", "access denied",
	"permission denied", "not authorized", "not allowed", "login required",
	"must be logged in", "invalid token", "invalid credentials", "no permission",
}

// isSoftDeny reports whether a 2xx body is really an authorization refusal.
// Only short bodies qualify — a large data payload that happens to contain the
// word "forbidden" is not a deny — so this cannot mask a real content leak.
func isSoftDeny(body []byte) bool {
	n := Normalize(body)
	if len(n) == 0 || len(n) > 256 {
		return false
	}
	s := string(n)
	if denyCodePattern.MatchString(s) {
		return true
	}
	for _, kw := range denyPhrases {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// isDeclaredPublic reports whether the spec marks this operation as needing no
// authentication (op-level `security: []`, or no requirement anywhere). For
// such endpoints, unauthenticated success is the documented contract.
func isDeclaredPublic(req engine.Request) bool {
	if op, ok := req.Meta.(*spec.Operation); ok {
		return op.Public
	}
	return false
}

func isAuthDenied(r engine.Response) bool {
	return r.Err == nil && (r.Status == 401 || r.Status == 403)
}

func isServerError(r engine.Response) bool {
	return r.Err == nil && r.Status >= 500 && r.Status < 600
}

func similarShape(a, b engine.Response) bool {
	return Similarity(a.Body, b.Body) >= similarityThreshold
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
