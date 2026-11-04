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
	ByName map[string]string // param name → value (highest priority)
	ByType map[string]string // param type → fallback value (integer → "1", string → "test")
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

// Build turns a parsed Doc into concrete engine.Request templates — one per
// Operation, with path parameters filled in and query parameters attached.
// Each returned Request's Meta is the source Operation (pointer), so the
// diff layer can refer back to it in findings.
func Build(doc *Doc, baseURL string, over ResourceOverride) ([]engine.Request, error) {
	if baseURL == "" {
		baseURL = doc.BaseURL
	}
	if baseURL == "" {
		return nil, fmt.Errorf("no base URL: pass -u or include a `servers:` entry in the spec")
	}
	baseURL = strings.TrimRight(baseURL, "/")

	out := make([]engine.Request, 0, len(doc.Operations))
	for i := range doc.Operations {
		op := &doc.Operations[i]
		path, err := fillPath(op.Path, op.Parameters, over)
		if err != nil {
			return nil, fmt.Errorf("op %s %s: %w", op.Method, op.Path, err)
		}
		q := buildQuery(op.Parameters, over)
		u := baseURL + path
		if q != "" {
			u += "?" + q
		}
		r := engine.Request{
			Method: op.Method,
			URL:    u,
			Meta:   op,
		}
		if op.RequestBody != nil {
			r.Body = op.RequestBody.Example
			r.Headers = map[string]string{"Content-Type": op.RequestBody.ContentType}
		}
		out = append(out, r)
	}
	return out, nil
}

// fillPath substitutes every `{name}` placeholder in a spec path with a
// value drawn from (in priority order): operator-supplied override by name,
// spec example, operator-supplied fallback by type, type-based default.
// A required path parameter with no source at all is an error — the request
// couldn't be built without silently inventing an ID.
func fillPath(raw string, params []Parameter, over ResourceOverride) (string, error) {
	result := raw
	for _, p := range params {
		if p.In != "path" {
			continue
		}
		val, ok := resolveValue(p, over)
		if !ok && p.Required {
			return "", fmt.Errorf("required path param %q has no value (spec gave no example; pass --resource %s=<value>)", p.Name, p.Name)
		}
		if !ok {
			val = ""
		}
		result = strings.ReplaceAll(result, "{"+p.Name+"}", url.PathEscape(val))
	}
	return result, nil
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
		v, ok := resolveValue(p, over)
		if !ok && !p.Required {
			continue
		}
		if !ok {
			v = defaultByType[p.Type]
			if v == "" {
				v = defaultByType[""]
			}
		}
		vals.Set(p.Name, v)
	}
	return vals.Encode()
}

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
