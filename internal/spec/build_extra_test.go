package spec

import (
	"testing"
)

func TestResolveBase(t *testing.T) {
	cases := []struct {
		name     string
		specBase string
		operator string
		want     string
		wantErr  bool
	}{
		{"spec absolute, no -u", "https://api.example.com/", "", "https://api.example.com", false},
		{"-u overrides spec", "https://api.example.com", "https://staging.example.com", "https://staging.example.com", false},
		{"relative spec joined onto -u", "/api/v1", "https://host.example.com", "https://host.example.com/api/v1", false},
		{"relative spec not double-appended", "/api/v1", "https://host.example.com/api/v1", "https://host.example.com/api/v1", false},
		{"relative spec, no -u is an error", "/api/v1", "", "", true},
		{"no base anywhere is an error", "", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := &Doc{BaseURL: c.specBase}
			got, err := ResolveBase(doc, c.operator)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Errorf("ResolveBase=%q, want %q", got, c.want)
			}
		})
	}
}

// Declared header parameters must be sent so an API that requires them is
// actually reachable; auth headers are left to the identity layer.
func TestBuildSendsHeaderParams(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "openapi": "3.0.0",
	  "info": {"title": "x", "version": "1"},
	  "servers": [{"url": "http://x"}],
	  "paths": {
	    "/orders": {
	      "get": {"parameters": [
	        {"name": "X-Tenant-ID", "in": "header", "required": true, "example": "acme"},
	        {"name": "Authorization", "in": "header", "required": true}
	      ]}
	    }
	  }
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	reqs, _, err := Build(doc, "", ResourceOverride{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 request, got %d", len(reqs))
	}
	if reqs[0].Headers["X-Tenant-ID"] != "acme" {
		t.Errorf("declared header param not sent: %v", reqs[0].Headers)
	}
	if _, ok := reqs[0].Headers["Authorization"]; ok {
		t.Errorf("auth header must be left to the identity layer, not set from the spec: %v", reqs[0].Headers)
	}
}

// Public is derived correctly from declared security.
func TestOperationPublicDerivation(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "openapi": "3.0.0",
	  "info": {"title": "x", "version": "1"},
	  "servers": [{"url": "http://x"}],
	  "security": [{"bearer": []}],
	  "paths": {
	    "/secure": {"get": {}},
	    "/open":   {"get": {"security": []}}
	  }
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byPath := map[string]bool{}
	for _, op := range doc.Operations {
		byPath[op.Path] = op.Public
	}
	if byPath["/secure"] {
		t.Error("/secure inherits doc-level auth requirement; must not be Public")
	}
	if !byPath["/open"] {
		t.Error("/open declares security: [] and must be Public")
	}
}

// With NO security declared anywhere, operations must NOT be treated as public
// (so real bugs on under-documented specs still surface).
func TestNoSecurityMeansNotPublic(t *testing.T) {
	doc, _ := Parse([]byte(`{
	  "openapi": "3.0.0",
	  "info": {"title": "x", "version": "1"},
	  "servers": [{"url": "http://x"}],
	  "paths": {"/thing": {"get": {}}}
	}`))
	if doc.Operations[0].Public {
		t.Error("absence of any security declaration must NOT be treated as public")
	}
}
