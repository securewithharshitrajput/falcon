// Package spec parses an OpenAPI 3.x document into the minimal operation
// list falcon needs to fire requests: method, path, parameters, request
// body shape, security requirements. Deliberately NOT a full OpenAPI
// validator — falcon only reads what it needs to generate test cases and
// ignores schema vocabulary (discriminators, oneOf, polymorphism) that
// wouldn't change what gets sent on the wire.
package spec

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Operation is one testable endpoint: Method + Path + how to fill in its
// parameters and body. Falcon runs each Operation as every registered
// identity and diffs the responses.
type Operation struct {
	Method      string      // GET, POST, PUT, DELETE, PATCH
	Path        string      // raw spec path, e.g. "/users/{id}"
	OperationID string      // optional, from the spec; used in findings
	Summary     string      // optional, from the spec; used in findings
	Parameters  []Parameter // path + query + header params the spec declares
	RequestBody *Body       // nil when operation takes no body
	// SecuritySchemes declared on this op (empty means the op inherits the
	// doc-level security, which falcon treats as "needs auth by default").
	Security []string
}

// Parameter is one input the spec declares (path, query, or header).
type Parameter struct {
	Name     string
	In       string // "path" | "query" | "header"
	Required bool
	Example  string // operator-supplied or sample from spec; used in requests
	Type     string // "integer" | "string" | "boolean" (as declared; falcon treats unknown as string)
}

// Body is the request body shape — just enough for falcon to send something
// the API won't reject out of hand. The full JSON schema is ignored; we
// keep only the sample/example (if the spec provided one) and a content
// type.
type Body struct {
	ContentType string
	Example     []byte // JSON-encoded, ready to send
}

// Doc is the parsed OpenAPI document — the BaseURL (first server entry if
// present) plus the flat list of Operations ready for falcon to run.
type Doc struct {
	Title      string
	Version    string
	BaseURL    string
	Operations []Operation
}

// --- raw unmarshal types (we only care about a small subset) ---

type rawDoc struct {
	OpenAPI    string             `json:"openapi"`
	Info       rawInfo            `json:"info"`
	Servers    []rawServer        `json:"servers"`
	Paths      map[string]rawPath `json:"paths"`
	Components rawComponents      `json:"components"`
	Security   []map[string][]any `json:"security"`
}

type rawInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type rawServer struct {
	URL string `json:"url"`
}

type rawPath map[string]rawOperation // method -> op (plus "parameters" shared across methods)

type rawOperation struct {
	OperationID string             `json:"operationId"`
	Summary     string             `json:"summary"`
	Parameters  []rawParameter     `json:"parameters"`
	RequestBody *rawRequestBody    `json:"requestBody"`
	Security    []map[string][]any `json:"security"`
}

type rawParameter struct {
	Name     string                `json:"name"`
	In       string                `json:"in"`
	Required bool                  `json:"required"`
	Example  any                   `json:"example"`
	Schema   map[string]any        `json:"schema"`
	Examples map[string]rawExample `json:"examples"`
}

type rawExample struct {
	Value any `json:"value"`
}

type rawRequestBody struct {
	Required bool                    `json:"required"`
	Content  map[string]rawMediaType `json:"content"`
}

type rawMediaType struct {
	Schema   map[string]any        `json:"schema"`
	Example  any                   `json:"example"`
	Examples map[string]rawExample `json:"examples"`
}

type rawComponents struct {
	Schemas         map[string]any `json:"schemas"`
	SecuritySchemes map[string]any `json:"securitySchemes"`
}

// Parse takes raw OpenAPI 3.x JSON (callers can accept YAML and pre-convert
// if desired; keeping this JSON-only avoids a YAML dependency) and returns
// a flat Doc ready for fuzzing.
func Parse(data []byte) (*Doc, error) {
	if len(data) == 0 {
		return nil, errors.New("spec is empty")
	}
	var raw rawDoc
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("spec is not valid JSON: %w", err)
	}
	if !strings.HasPrefix(raw.OpenAPI, "3.") {
		return nil, fmt.Errorf("unsupported OpenAPI version %q (falcon speaks 3.x)", raw.OpenAPI)
	}
	doc := &Doc{
		Title:   raw.Info.Title,
		Version: raw.Info.Version,
	}
	if len(raw.Servers) > 0 {
		doc.BaseURL = strings.TrimRight(raw.Servers[0].URL, "/")
	}

	// Stable path iteration so test cases land in the same order across runs
	// — useful when diffing results between scans or when an operator reads
	// a repeat run's output.
	paths := make([]string, 0, len(raw.Paths))
	for p := range raw.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	methodOrder := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	for _, p := range paths {
		pathItem := raw.Paths[p]
		for _, method := range methodOrder {
			rawOp, ok := pathItem[strings.ToLower(method)]
			if !ok {
				continue
			}
			op := Operation{
				Method:      method,
				Path:        p,
				OperationID: rawOp.OperationID,
				Summary:     rawOp.Summary,
			}
			for _, rp := range rawOp.Parameters {
				op.Parameters = append(op.Parameters, convertParam(rp))
			}
			if rawOp.RequestBody != nil {
				op.RequestBody = convertBody(rawOp.RequestBody)
			}
			for _, scheme := range rawOp.Security {
				for name := range scheme {
					op.Security = append(op.Security, name)
				}
			}
			doc.Operations = append(doc.Operations, op)
		}
	}
	return doc, nil
}

func convertParam(rp rawParameter) Parameter {
	p := Parameter{
		Name:     rp.Name,
		In:       strings.ToLower(rp.In),
		Required: rp.Required,
	}
	if rp.Schema != nil {
		if t, ok := rp.Schema["type"].(string); ok {
			p.Type = t
		}
	}
	// Prefer explicit example → examples.* → nothing (caller supplies).
	if rp.Example != nil {
		p.Example = fmt.Sprintf("%v", rp.Example)
	} else {
		for _, ex := range rp.Examples {
			if ex.Value != nil {
				p.Example = fmt.Sprintf("%v", ex.Value)
				break
			}
		}
	}
	return p
}

func convertBody(rb *rawRequestBody) *Body {
	if rb == nil || len(rb.Content) == 0 {
		return nil
	}
	// Prefer application/json; then whatever the spec lists first.
	for _, ct := range []string{"application/json"} {
		if mt, ok := rb.Content[ct]; ok {
			if b := mediaExample(mt); b != nil {
				return &Body{ContentType: ct, Example: b}
			}
		}
	}
	for ct, mt := range rb.Content {
		if b := mediaExample(mt); b != nil {
			return &Body{ContentType: ct, Example: b}
		}
	}
	return nil
}

func mediaExample(mt rawMediaType) []byte {
	if mt.Example != nil {
		if b, err := json.Marshal(mt.Example); err == nil {
			return b
		}
	}
	for _, ex := range mt.Examples {
		if ex.Value != nil {
			if b, err := json.Marshal(ex.Value); err == nil {
				return b
			}
		}
	}
	// Last resort: synthesize a minimal body from schema.properties if the
	// spec provides one; a real schema walker is a bigger job, so we only
	// emit `{}` and let the API accept or reject it.
	if mt.Schema != nil {
		return []byte(`{}`)
	}
	return nil
}
