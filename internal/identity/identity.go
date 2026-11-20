// Package identity models the test identities falcon runs the same request
// as: the authenticated users whose boundaries we want to verify, the
// no-auth anonymous caller, and a deliberately-invalid-token identity that
// catches "auth header present but not actually checked" bugs.
//
// The differential finding model needs a consistent set of identities per
// endpoint so we can reason "same request as A: 200; as B: 200; same body:
// IDOR" instead of ad-hoc one-off tests.
package identity

import (
	"encoding/base64"
	"strings"
)

// Identity is one principal falcon can authenticate as. Role is a short
// label ("admin", "user-a", "no-auth") that lands in findings so operators
// can read "user-b accessed user-a's resource" rather than "req[3] vs
// req[1]."
type Identity struct {
	Role      string
	Headers   map[string]string // auth headers to inject on every request
	IsAnon    bool              // explicit no-auth identity
	IsInvalid bool              // intentionally-bogus token — proves auth is actually checked
}

// Apply merges this identity's auth headers into req headers. Per-request
// headers (e.g. Content-Type) win over identity headers only when they
// name the same key; auth header names (Authorization, Cookie) should
// never clash with per-request ones in practice.
func (id Identity) Apply(headers map[string]string) map[string]string {
	if len(id.Headers) == 0 && headers == nil {
		return nil
	}
	out := make(map[string]string, len(id.Headers)+len(headers))
	for k, v := range id.Headers {
		out[k] = v
	}
	for k, v := range headers {
		out[k] = v
	}
	return out
}

// Bearer returns an identity that sends `Authorization: Bearer <token>`.
// The role string is what shows up in findings.
func Bearer(role, token string) Identity {
	return Identity{
		Role:    role,
		Headers: map[string]string{"Authorization": "Bearer " + token},
	}
}

// Cookie returns an identity that sends raw cookies, exactly as a browser
// would: `Cookie: name1=value1; name2=value2`.
func Cookie(role, cookies string) Identity {
	return Identity{
		Role:    role,
		Headers: map[string]string{"Cookie": cookies},
	}
}

// Basic returns an identity for HTTP Basic auth.
func Basic(role, user, pass string) Identity {
	enc := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return Identity{
		Role:    role,
		Headers: map[string]string{"Authorization": "Basic " + enc},
	}
}

// Header returns an identity authenticating via one arbitrary header
// (e.g. `X-API-Key: ...`) — several modern APIs use custom header names
// instead of standardized Authorization.
func Header(role, name, value string) Identity {
	return Identity{
		Role:    role,
		Headers: map[string]string{name: value},
	}
}

// Anonymous returns the no-auth identity: no headers injected at all.
// Having this as an explicit identity (rather than a nil special case)
// makes the diff logic uniform — "no-auth got 200 while user-a got 200"
// is just "two identities, same result" like any other comparison.
func Anonymous() Identity {
	return Identity{Role: "no-auth", IsAnon: true}
}

// canary is the obviously-invalid credential value falcon substitutes. It is
// deliberately human-readable so it's recognizable in a target's logs.
const canary = "falcon-canary-invalid-should-be-rejected"

// Invalid returns the deliberately-bogus-token identity using a bearer token.
// Prefer InvalidFrom, which matches the real users' auth scheme; this bearer
// form remains for callers (and tests) that specifically want it.
func Invalid() Identity {
	return Identity{
		Role:      "invalid-token",
		Headers:   map[string]string{"Authorization": "Bearer " + canary},
		IsInvalid: true,
	}
}

// InvalidFrom builds the invalid-token identity by copying the credential
// SHAPE of a real identity — the same header names and, for cookies, the same
// cookie names — but replacing every credential VALUE with an obvious canary.
// This is what makes "is the credential actually validated?" work beyond
// bearer tokens: a cookie-based API gets a bogus cookie, an X-API-Key API gets
// a bogus key, Basic auth gets bogus Basic creds. A real user that still
// validated its token returns a denial here; one that only checks for the
// header's PRESENCE returns the same content, which is the bug.
func InvalidFrom(base Identity) Identity {
	h := make(map[string]string, len(base.Headers))
	for name, val := range base.Headers {
		h[name] = garbleCredential(name, val)
	}
	if len(h) == 0 {
		h["Authorization"] = "Bearer " + canary
	}
	return Identity{Role: "invalid-token", Headers: h, IsInvalid: true}
}

// garbleCredential replaces a credential value with the canary while keeping
// enough structure that the server's auth middleware parses it the same way
// (scheme word for Authorization, cookie names for Cookie).
func garbleCredential(name, val string) string {
	switch {
	case strings.EqualFold(name, "Cookie"):
		parts := strings.Split(val, ";")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if k, _, ok := strings.Cut(p, "="); ok {
				out = append(out, k+"="+canary)
			} else {
				out = append(out, canary)
			}
		}
		if len(out) == 0 {
			return "session=" + canary
		}
		return strings.Join(out, "; ")
	case strings.EqualFold(name, "Authorization"):
		if scheme, _, ok := strings.Cut(val, " "); ok && scheme != "" {
			return scheme + " " + canary
		}
		return canary
	default:
		return canary
	}
}

// ParseAuth takes an operator-friendly auth string and returns an Identity.
// Accepted forms (same spirit as curl's -H and --user):
//
//	"bearer:<token>"          → Authorization: Bearer <token>
//	"cookie:<cookie-string>"  → Cookie: <...>
//	"basic:<user>:<pass>"     → Authorization: Basic <base64>
//	"header:<name>=<value>"   → <name>: <value>
//
// role is what the identity will be called in findings.
func ParseAuth(role, spec string) (Identity, error) {
	kind, rest, ok := strings.Cut(spec, ":")
	if !ok {
		return Identity{}, errParse("expected form kind:value, e.g. bearer:<token>")
	}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "bearer":
		if rest == "" {
			return Identity{}, errParse("bearer: missing token")
		}
		return Bearer(role, rest), nil
	case "cookie":
		if rest == "" {
			return Identity{}, errParse("cookie: missing value")
		}
		return Cookie(role, rest), nil
	case "basic":
		user, pass, ok := strings.Cut(rest, ":")
		if !ok {
			return Identity{}, errParse("basic: expected user:password")
		}
		return Basic(role, user, pass), nil
	case "header":
		name, value, ok := strings.Cut(rest, "=")
		if !ok {
			return Identity{}, errParse("header: expected Name=Value")
		}
		return Header(role, strings.TrimSpace(name), strings.TrimSpace(value)), nil
	}
	return Identity{}, errParse("unknown auth kind: " + kind)
}

type parseError string

func (e parseError) Error() string { return string(e) }
func errParse(s string) error      { return parseError(s) }
