// Package spec parses an OpenAPI 3.x document into the minimal operation
// list falcon needs to fire requests: method, path, parameters, request
// body shape, security requirements. Deliberately NOT a full OpenAPI
// validator — falcon only reads what it needs to generate test cases and
// ignores schema vocabulary (discriminators, oneOf, polymorphism) that
// wouldn't change what gets sent on the wire.
//
// It accepts both JSON and YAML specs (YAML is converted to JSON first,
// since JSON is a strict subset of what the rest of the parser needs), and
// resolves intra-document `$ref`s for parameters and request bodies so the
// many real-world specs that factor those into `components` still produce
// usable request templates.
package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
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
	// Public is true when the spec declares this operation needs no auth —
	// op-level `security: []`, or no security requirement anywhere in the
	// document. For such endpoints an unauthenticated success is the
	// documented contract, not a broken-auth finding.
	Public bool
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
	OpenAPI    string                     `json:"openapi"`
	Info       rawInfo                    `json:"info"`
	Servers    []rawServer                `json:"servers"`
	Paths      map[string]json.RawMessage `json:"paths"`
	Components rawComponents              `json:"components"`
	Security   []map[string][]any         `json:"security"`
}

type rawInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type rawServer struct {
	URL string `json:"url"`
}

// rawPathItem is one entry under `paths`. OpenAPI puts the HTTP methods and a
// shared `parameters` array (applied to every method) as sibling keys, plus
// an optional `$ref`. Modelling it as an explicit struct — rather than a
// map[string]rawOperation — is what lets a shared `parameters` array coexist
// with operations without the whole document failing to unmarshal.
type rawPathItem struct {
	Ref        string         `json:"$ref"`
	Parameters []rawParameter `json:"parameters"`
	Get        *rawOperation  `json:"get"`
	Put        *rawOperation  `json:"put"`
	Post       *rawOperation  `json:"post"`
	Patch      *rawOperation  `json:"patch"`
	Delete     *rawOperation  `json:"delete"`
	Head       *rawOperation  `json:"head"`
	Options    *rawOperation  `json:"options"`
}

func (p rawPathItem) op(method string) *rawOperation {
	switch method {
	case "GET":
		return p.Get
	case "PUT":
		return p.Put
	case "POST":
		return p.Post
	case "PATCH":
		return p.Patch
	case "DELETE":
		return p.Delete
	case "HEAD":
		return p.Head
	case "OPTIONS":
		return p.Options
	}
	return nil
}

type rawOperation struct {
	OperationID string             `json:"operationId"`
	Summary     string             `json:"summary"`
	Parameters  []rawParameter     `json:"parameters"`
	RequestBody *rawRequestBody    `json:"requestBody"`
	Security    []map[string][]any `json:"security"`
}

type rawParameter struct {
	Ref      string                `json:"$ref"`
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
	Ref      string                  `json:"$ref"`
	Required bool                    `json:"required"`
	Content  map[string]rawMediaType `json:"content"`
}

type rawMediaType struct {
	Schema   map[string]any        `json:"schema"`
	Example  any                   `json:"example"`
	Examples map[string]rawExample `json:"examples"`
}

type rawComponents struct {
	Schemas         map[string]any            `json:"schemas"`
	SecuritySchemes map[string]any            `json:"securitySchemes"`
	Parameters      map[string]rawParameter   `json:"parameters"`
	RequestBodies   map[string]rawRequestBody `json:"requestBodies"`
}

// Parse takes a raw OpenAPI 3.x document as JSON or YAML and returns a flat
// Doc ready for fuzzing. YAML is auto-detected and converted to JSON first.
func Parse(data []byte) (*Doc, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, errors.New("spec is empty")
	}

	// Accept YAML as well as JSON. JSON is a subset of YAML, so a document
	// that isn't obviously JSON is run through the YAML→JSON converter; this
	// keeps the rest of the parser JSON-only while handling the common case
	// of a .yaml/.yml OpenAPI file.
	if !looksLikeJSON(data) {
		converted, err := yamlToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("spec is not valid JSON or YAML: %w", err)
		}
		data = converted
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
		var item rawPathItem
		if err := json.Unmarshal(raw.Paths[p], &item); err != nil {
			return nil, fmt.Errorf("path %q: %w", p, err)
		}
		// Shared parameters apply to every operation under this path item.
		shared := make([]Parameter, 0, len(item.Parameters))
		for _, rp := range item.Parameters {
			shared = append(shared, convertParam(rp, raw.Components))
		}
		for _, method := range methodOrder {
			rawOp := item.op(method)
			if rawOp == nil {
				continue
			}
			op := Operation{
				Method:      method,
				Path:        p,
				OperationID: rawOp.OperationID,
				Summary:     rawOp.Summary,
			}
			// Operation-level params override shared params of the same
			// (name, in); start from shared then layer the op's own.
			merged := map[string]Parameter{}
			order := []string{}
			add := func(pr Parameter) {
				key := pr.In + "\x00" + pr.Name
				if _, ok := merged[key]; !ok {
					order = append(order, key)
				}
				merged[key] = pr
			}
			for _, pr := range shared {
				add(pr)
			}
			for _, rp := range rawOp.Parameters {
				add(convertParam(rp, raw.Components))
			}
			for _, key := range order {
				op.Parameters = append(op.Parameters, merged[key])
			}
			if body := resolveBody(rawOp.RequestBody, raw.Components); body != nil {
				op.RequestBody = convertBody(body)
			}
			for _, scheme := range rawOp.Security {
				for name := range scheme {
					op.Security = append(op.Security, name)
				}
			}
			// Declared-public requires an EXPLICIT empty security declaration:
			// op-level `security: []` (or `[{}]`), or — when the op states no
			// security of its own — a doc-level `security: []`. "No security
			// mentioned anywhere" is NOT treated as public: countless real
			// specs omit security entirely yet still require auth, and
			// suppressing every finding on those would hide real bugs. An
			// endpoint meant to be public can be marked with `security: []`.
			switch {
			case rawOp.Security != nil:
				op.Public = !hasRealRequirement(rawOp.Security)
			case raw.Security != nil:
				op.Public = !hasRealRequirement(raw.Security)
			default:
				op.Public = false
			}
			doc.Operations = append(doc.Operations, op)
		}
	}
	return doc, nil
}

// looksLikeJSON reports whether data's first meaningful byte starts a JSON
// document ('{' or '['), after skipping a UTF-8 BOM and leading whitespace.
func looksLikeJSON(data []byte) bool {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
	data = bytes.TrimLeft(data, " \t\r\n")
	return len(data) > 0 && (data[0] == '{' || data[0] == '[')
}

// yamlToJSON parses YAML into a generic value and re-encodes it as JSON. The
// normalize pass converts any map[any]any (which some YAML shapes still
// produce) into map[string]any so json.Marshal can encode it.
func yamlToJSON(data []byte) ([]byte, error) {
	var v any
	if err := yaml.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return json.Marshal(normalizeYAML(v))
}

func normalizeYAML(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = normalizeYAML(val)
		}
		return t
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[fmt.Sprintf("%v", k)] = normalizeYAML(val)
		}
		return out
	case []any:
		for i, val := range t {
			t[i] = normalizeYAML(val)
		}
		return t
	default:
		return v
	}
}

// resolveParamRef follows a `$ref` into components.parameters. Only
// intra-document refs of the form "#/components/parameters/<name>" are
// supported; anything else (external files, unusual pointers) resolves to
// the zero parameter, which the caller drops as unusable.
func resolveParamRef(ref string, comps rawComponents) (rawParameter, bool) {
	const prefix = "#/components/parameters/"
	if !strings.HasPrefix(ref, prefix) {
		return rawParameter{}, false
	}
	name := strings.TrimPrefix(ref, prefix)
	rp, ok := comps.Parameters[name]
	return rp, ok
}

// resolveBody follows a request-body `$ref` into components.requestBodies and
// returns the concrete body (or the input unchanged if it carries no ref).
func resolveBody(rb *rawRequestBody, comps rawComponents) *rawRequestBody {
	if rb == nil {
		return nil
	}
	if rb.Ref == "" {
		return rb
	}
	const prefix = "#/components/requestBodies/"
	if !strings.HasPrefix(rb.Ref, prefix) {
		return nil
	}
	name := strings.TrimPrefix(rb.Ref, prefix)
	if resolved, ok := comps.RequestBodies[name]; ok {
		return &resolved
	}
	return nil
}

// hasRealRequirement reports whether a `security` array actually mandates a
// credential. An empty array, or one whose every requirement object is empty
// (`[{}]`), means "no auth required."
func hasRealRequirement(sec []map[string][]any) bool {
	for _, req := range sec {
		if len(req) > 0 {
			return true
		}
	}
	return false
}

func convertParam(rp rawParameter, comps rawComponents) Parameter {
	if rp.Ref != "" {
		if resolved, ok := resolveParamRef(rp.Ref, comps); ok {
			rp = resolved
		}
	}
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
	// Deterministic fallback: pick the first content type in sorted order so
	// repeat runs build the same request.
	cts := make([]string, 0, len(rb.Content))
	for ct := range rb.Content {
		cts = append(cts, ct)
	}
	sort.Strings(cts)
	for _, ct := range cts {
		if b := mediaExample(rb.Content[ct]); b != nil {
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
