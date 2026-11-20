package spec

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/securewithharshitrajput/falcon/internal/engine"
)

// ResourceOverride lets the operator substitute concrete values for path or
// query parameters when the spec's own examples aren't realistic or aren't
// present. A classic use: `users/{id}` → set `{"id": "42"}` so falcon hits
// a real resource that exists in the test environment.
type ResourceOverride struct {
	ByName  map[string]string // param name → value (highest priority)
	ByType  map[string]string // param type → fallback value (integer → "1", string → "test")
	Methods map[string]bool   // allowed HTTP methods (nil/empty = all); keys are upper-case
}

// methodAllowed reports whether an operation with the given method should be
// built. A nil/empty Methods set means "all methods".
func (o ResourceOverride) methodAllowed(method string) bool {
	if len(o.Methods) == 0 {
		return true
	}
	return o.Methods[strings.ToUpper(method)]
}

// Skipped is an operation falcon could not build a request for, with the
// reason and (where possible) the flag that would fix it. Skipping one
// operation never aborts the rest of the scan.
type Skipped struct {
	Method string
	Path   string
	Reason string
}

// defaultByType are the fallback values falcon synthesizes when neither the
// spec example nor the operator overrides supply one. The goal is a request
// the API will accept so the auth/authorization logic actually runs — not
// a request that passes business validation.
var defaultByType = map[string]string{
	"integer": "1",
	"number":  "1",
	"boolean": "true",
	"string":  "falcon-test",
	"":        "falcon-test",
}

// ResolveBase picks the base URL to test. The operator's -u wins; otherwise
// the spec's first server is used. A spec server that is only a path (e.g.
// "/api/v1", very common) is appended to -u unless -u already ends with it,
// so the requests still land under the API's real prefix.
func ResolveBase(doc *Doc, operator string) (string, error) {
	operator = strings.TrimRight(strings.TrimSpace(operator), "/")
	specBase := strings.TrimRight(doc.BaseURL, "/")
	relative := strings.HasPrefix(specBase, "/")

	switch {
	case operator != "" && relative:
		u, err := url.Parse(operator)
		if err != nil {
			return "", fmt.Errorf("invalid -u %q: %w", operator, err)
		}
		if strings.HasSuffix(strings.TrimRight(u.Path, "/"), specBase) {
			return operator, nil
		}
		return operator + specBase, nil
	case operator != "":
		return operator, nil
	case specBase == "":
		return "", fmt.Errorf("no base URL: pass -u or include a `servers:` entry in the spec")
	case relative:
		return "", fmt.Errorf("spec server %q is a relative path; pass -u https://host to say where the API runs", specBase)
	}
	return specBase, nil
}

// Build turns a parsed Doc into concrete engine.Request templates — one per
// Operation, with path parameters filled in, query parameters attached and
// header parameters set. Each returned Request's Meta is the source
// Operation (pointer), so the diff layer can refer back to it in findings.
//
// Operations that cannot be built (a required path parameter with no value
// anywhere) are returned in skipped instead of failing the whole build.
func Build(doc *Doc, baseURL string, over ResourceOverride) (reqs []engine.Request, skipped []Skipped, err error) {
	base, err := ResolveBase(doc, baseURL)
	if err != nil {
		return nil, nil, err
	}

	reqs = make([]engine.Request, 0, len(doc.Operations))
	for i := range doc.Operations {
		op := &doc.Operations[i]
		if !over.methodAllowed(op.Method) {
			continue
		}
		path, missing := fillPath(op.Path, op.Parameters, over)
		if missing != "" {
			skipped = append(skipped, Skipped{
				Method: op.Method,
				Path:   op.Path,
				Reason: fmt.Sprintf("required path param %q has no value in the spec; pass --resource %s=<value>", missing, missing),
			})
			continue
		}
		u := base + path
		if q := buildQuery(op.Parameters, over); q != "" {
			u += "?" + q
		}
		r := engine.Request{
			Method:  op.Method,
			URL:     u,
			Meta:    op,
			Headers: buildHeaders(op.Parameters, over),
		}
		if op.RequestBody != nil {
			r.Body = op.RequestBody.Example
			if r.Headers == nil {
				r.Headers = map[string]string{}
			}
			r.Headers["Content-Type"] = op.RequestBody.ContentType
		}
		reqs = append(reqs, r)
	}
	return reqs, skipped, nil
}

// fillPath substitutes every `{name}` placeholder in a spec path with a
// value drawn from (in priority order): operator-supplied override by name,
// spec example, operator-supplied fallback by type. It returns the name of
// the first required path parameter that has no value at all — falcon won't
// silently invent an ID, because a made-up ID tests nothing.
func fillPath(raw string, params []Parameter, over ResourceOverride) (string, string) {
	result := raw
	for _, p := range params {
		if p.In != "path" {
			continue
		}
		val, ok := resolveValue(p, over)
		if !ok {
			if p.Required || strings.Contains(raw, "{"+p.Name+"}") {
				return "", p.Name
			}
			continue
		}
		result = strings.ReplaceAll(result, "{"+p.Name+"}", url.PathEscape(val))
	}
	return result, ""
}

// buildQuery returns the query string, including only parameters that are
// REQUIRED or have an explicit value — non-required params with no source
// are left out so we don't send meaningless `?filter=falcon-test` noise.
func buildQuery(params []Parameter, over ResourceOverride) string {
	vals := url.Values{}
	for _, p := range params {
		if p.In != "query" {
			continue
		}
		if v, ok := valueOrDefault(p, over); ok {
			vals.Set(p.Name, v)
		}
	}
	return vals.Encode()
}

// buildHeaders returns the header parameters the spec declares (required
// ones, or ones with a value). Without these, an API that demands e.g. an
// X-Tenant-ID header answers 400 to every identity and its auth logic is
// never exercised. Auth headers are left to the identity layer.
func buildHeaders(params []Parameter, over ResourceOverride) map[string]string {
	var out map[string]string
	for _, p := range params {
		if p.In != "header" {
			continue
		}
		switch strings.ToLower(p.Name) {
		case "authorization", "cookie", "content-type", "accept", "user-agent":
			continue
		}
		if v, ok := valueOrDefault(p, over); ok {
			if out == nil {
				out = map[string]string{}
			}
			out[p.Name] = v
		}
	}
	return out
}

// valueOrDefault resolves a param's value, falling back to a type-based
// default only for required params.
func valueOrDefault(p Parameter, over ResourceOverride) (string, bool) {
	if v, ok := resolveValue(p, over); ok {
		return v, true
	}
	if !p.Required {
		return "", false
	}
	if v := defaultByType[p.Type]; v != "" {
		return v, true
	}
	return defaultByType[""], true
}

// resolveValue draws a concrete value for a parameter, in priority order:
// operator override by name, then the spec's own example, then an operator
// override by type. Reports false when no source supplies one.
func resolveValue(p Parameter, over ResourceOverride) (string, bool) {
	if v, ok := over.ByName[p.Name]; ok && v != "" {
		return v, true
	}
	if p.Example != "" {
		return p.Example, true
	}
	if v, ok := over.ByType[p.Type]; ok && v != "" {
		return v, true
	}
	return "", false
}
