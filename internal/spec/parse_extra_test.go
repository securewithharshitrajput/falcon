package spec

import (
	"strings"
	"testing"
)

// A spec with a path-level shared `parameters` array (applied to every
// method) used to crash the entire parser because the raw path item was
// modelled as map[string]rawOperation and the array wouldn't unmarshal into
// a rawOperation. It must now parse, and the shared param must be visible to
// each operation under the path.
func TestParsePathLevelSharedParameters(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "openapi": "3.0.0",
	  "info": {"title": "x", "version": "1"},
	  "servers": [{"url": "http://x"}],
	  "paths": {
	    "/orders/{id}": {
	      "parameters": [
	        {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}, "example": 7}
	      ],
	      "get": {"operationId": "getOrder"},
	      "delete": {"operationId": "deleteOrder"}
	    }
	  }
	}`))
	if err != nil {
		t.Fatalf("Parse with path-level params failed: %v", err)
	}
	if len(doc.Operations) != 2 {
		t.Fatalf("expected 2 operations (get+delete), got %d", len(doc.Operations))
	}
	for _, op := range doc.Operations {
		found := false
		for _, p := range op.Parameters {
			if p.Name == "id" && p.In == "path" && p.Example == "7" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s %s did not inherit the shared `id` path param: %+v", op.Method, op.Path, op.Parameters)
		}
	}
	// And Build must fill it from the shared example — no "{id}" left over.
	reqs, err := Build(doc, "", ResourceOverride{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, r := range reqs {
		if strings.Contains(r.URL, "{id}") {
			t.Errorf("shared path param not filled: %s", r.URL)
		}
	}
}

// Operation-level parameters must override a shared parameter of the same
// (name, in).
func TestParseOperationParamOverridesShared(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "openapi": "3.0.0",
	  "info": {"title": "x", "version": "1"},
	  "servers": [{"url": "http://x"}],
	  "paths": {
	    "/items/{id}": {
	      "parameters": [{"name": "id", "in": "path", "required": true, "example": "shared"}],
	      "get": {"parameters": [{"name": "id", "in": "path", "required": true, "example": "op-level"}]}
	    }
	  }
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	reqs, _ := Build(doc, "", ResourceOverride{})
	if len(reqs) != 1 || !strings.Contains(reqs[0].URL, "/items/op-level") {
		t.Errorf("operation-level param should win over shared; got %v", reqs)
	}
}

// $ref parameters pointing into components.parameters must resolve.
func TestParseResolvesParameterRef(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "openapi": "3.0.0",
	  "info": {"title": "x", "version": "1"},
	  "servers": [{"url": "http://x"}],
	  "components": {
	    "parameters": {
	      "UserId": {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}, "example": 99}
	    }
	  },
	  "paths": {
	    "/users/{id}": {
	      "get": {"parameters": [{"$ref": "#/components/parameters/UserId"}]}
	    }
	  }
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(doc.Operations) != 1 || len(doc.Operations[0].Parameters) != 1 {
		t.Fatalf("ref param not resolved: %+v", doc.Operations)
	}
	p := doc.Operations[0].Parameters[0]
	if p.Name != "id" || p.In != "path" || p.Example != "99" {
		t.Errorf("resolved param wrong: %+v", p)
	}
}

// $ref request bodies pointing into components.requestBodies must resolve.
func TestParseResolvesRequestBodyRef(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "openapi": "3.0.0",
	  "info": {"title": "x", "version": "1"},
	  "servers": [{"url": "http://x"}],
	  "components": {
	    "requestBodies": {
	      "NewUser": {
	        "required": true,
	        "content": {"application/json": {"example": {"name": "zara"}}}
	      }
	    }
	  },
	  "paths": {
	    "/users": {
	      "post": {"requestBody": {"$ref": "#/components/requestBodies/NewUser"}}
	    }
	  }
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	reqs, _ := Build(doc, "", ResourceOverride{})
	if len(reqs) != 1 || !strings.Contains(string(reqs[0].Body), "zara") {
		t.Errorf("request body ref not resolved into a body: %q", func() string {
			if len(reqs) > 0 {
				return string(reqs[0].Body)
			}
			return "<none>"
		}())
	}
}

// YAML specs must parse the same as their JSON equivalents.
func TestParseYAMLSpec(t *testing.T) {
	yamlSpec := `
openapi: 3.0.0
info:
  title: yaml-demo
  version: "2.0"
servers:
  - url: https://api.example.com/
paths:
  /users/{id}:
    get:
      operationId: getUser
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
          example: 42
  /healthz:
    get:
      operationId: health
`
	doc, err := Parse([]byte(yamlSpec))
	if err != nil {
		t.Fatalf("Parse YAML: %v", err)
	}
	if doc.Title != "yaml-demo" || doc.Version != "2.0" {
		t.Errorf("info lost from YAML: %+v", doc)
	}
	if doc.BaseURL != "https://api.example.com" {
		t.Errorf("baseURL wrong from YAML: %q", doc.BaseURL)
	}
	if len(doc.Operations) != 2 {
		t.Fatalf("expected 2 ops from YAML, got %d", len(doc.Operations))
	}
	reqs, err := Build(doc, "", ResourceOverride{})
	if err != nil {
		t.Fatalf("Build from YAML spec: %v", err)
	}
	for _, r := range reqs {
		if strings.Contains(r.URL, "{id}") {
			t.Errorf("YAML path param not filled: %s", r.URL)
		}
	}
}

// --methods filtering: only the requested methods should be built, and a
// filtered-out method with an otherwise-unsatisfiable required param must
// NOT error (it's simply skipped).
func TestBuildMethodFilter(t *testing.T) {
	doc, _ := Parse([]byte(`{
	  "openapi": "3.0.0",
	  "info": {"title": "x", "version": "1"},
	  "servers": [{"url": "http://x"}],
	  "paths": {
	    "/a": {"get": {}, "post": {"requestBody": {"required": true, "content": {"application/json": {"example": {"k": 1}}}}}},
	    "/b/{sku}": {"delete": {"parameters": [{"name": "sku", "in": "path", "required": true}]}}
	  }
	}`))
	reqs, err := Build(doc, "", ResourceOverride{Methods: map[string]bool{"GET": true}})
	if err != nil {
		t.Fatalf("method-filtered Build should skip the unsatisfiable DELETE, got: %v", err)
	}
	if len(reqs) != 1 || reqs[0].Method != "GET" {
		t.Errorf("expected only the GET request, got %+v", reqs)
	}
}
