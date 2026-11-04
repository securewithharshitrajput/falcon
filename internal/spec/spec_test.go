package spec

import (
	"strings"
	"testing"
)

// A minimal realistic OpenAPI document covering:
//   - a GET with a path param (users/{id})
//   - a POST with a JSON body example
//   - a GET with no params at all (healthz)
//
// — the three endpoint shapes falcon has to synthesize differently.
const sampleSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "demo", "version": "1.2.3"},
  "servers": [{"url": "https://api.example.com/"}],
  "paths": {
    "/users/{id}": {
      "get": {
        "operationId": "getUser",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}, "example": 42}
        ]
      }
    },
    "/users": {
      "post": {
        "operationId": "createUser",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "example": {"name": "alice", "email": "a@b.c"}
            }
          }
        }
      }
    },
    "/healthz": {"get": {"operationId": "health"}}
  }
}`

func TestParseExtractsAllOperationsInStableOrder(t *testing.T) {
	doc, err := Parse([]byte(sampleSpec))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Title != "demo" || doc.Version != "1.2.3" {
		t.Errorf("info lost: %+v", doc)
	}
	if doc.BaseURL != "https://api.example.com" {
		t.Errorf("baseURL trailing slash not stripped: %q", doc.BaseURL)
	}
	if len(doc.Operations) != 3 {
		t.Fatalf("expected 3 ops, got %d", len(doc.Operations))
	}
	// Stable order: paths sorted alphabetically.
	wantOrder := []string{"/healthz", "/users", "/users/{id}"}
	for i, want := range wantOrder {
		if doc.Operations[i].Path != want {
			t.Errorf("op[%d].Path = %q, want %q", i, doc.Operations[i].Path, want)
		}
	}
}

func TestParseRejectsOpenAPI2(t *testing.T) {
	_, err := Parse([]byte(`{"swagger": "2.0", "info": {"title":"old"}}`))
	if err == nil || !strings.Contains(err.Error(), "3.x") {
		t.Errorf("expected explicit 3.x requirement error, got %v", err)
	}
}

func TestBuildFillsPathParamFromExample(t *testing.T) {
	doc, _ := Parse([]byte(sampleSpec))
	reqs, err := Build(doc, "", ResourceOverride{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, r := range reqs {
		if strings.Contains(r.URL, "{id}") {
			t.Errorf("unfilled path param in %s", r.URL)
		}
	}
}

func TestBuildErrorsOnMissingRequiredParamWithNoExample(t *testing.T) {
	broken := `{
	  "openapi": "3.0.0",
	  "info": {"title": "x", "version": "1"},
	  "servers": [{"url": "http://x"}],
	  "paths": {
	    "/items/{sku}": {
	      "get": {"parameters": [{"name":"sku","in":"path","required":true,"schema":{"type":"string"}}]}
	    }
	  }
	}`
	doc, _ := Parse([]byte(broken))
	_, err := Build(doc, "", ResourceOverride{})
	if err == nil {
		t.Fatal("expected error for required param with no example and no override")
	}
	if !strings.Contains(err.Error(), "--resource") {
		t.Errorf("error should point operator at --resource flag, got %v", err)
	}
}

func TestBuildHonorsResourceOverride(t *testing.T) {
	broken := `{
	  "openapi": "3.0.0",
	  "info": {"title": "x", "version": "1"},
	  "servers": [{"url": "http://x"}],
	  "paths": {
	    "/items/{sku}": {
	      "get": {"parameters": [{"name":"sku","in":"path","required":true,"schema":{"type":"string"}}]}
	    }
	  }
	}`
	doc, _ := Parse([]byte(broken))
	reqs, err := Build(doc, "", ResourceOverride{ByName: map[string]string{"sku": "ABC-1"}})
	if err != nil {
		t.Fatalf("expected override to satisfy required param, got %v", err)
	}
	if !strings.Contains(reqs[0].URL, "/items/ABC-1") {
		t.Errorf("override not applied in URL %q", reqs[0].URL)
	}
}

func TestBuildCopiesRequestBodyExample(t *testing.T) {
	doc, _ := Parse([]byte(sampleSpec))
	reqs, _ := Build(doc, "", ResourceOverride{})
	var postReq int = -1
	for i, r := range reqs {
		if r.Method == "POST" {
			postReq = i
			break
		}
	}
	if postReq < 0 {
		t.Fatal("no POST request generated")
	}
	if !strings.Contains(string(reqs[postReq].Body), "alice") {
		t.Errorf("POST body missing example value: %q", reqs[postReq].Body)
	}
	if reqs[postReq].Headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type not set, got %v", reqs[postReq].Headers)
	}
}
