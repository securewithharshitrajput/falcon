package main

// The lab: an in-process fake API with deliberately vulnerable AND correctly
// secured endpoints. Every endpoint has an exact expected set of findings, so
// this test catches both missed bugs (false negatives) and false alarms
// (false positives) across the whole pipeline: spec → build → engine →
// classify.

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/securewithharshitrajput/falcon/internal/engine"
	"github.com/securewithharshitrajput/falcon/internal/spec"
)

// labUser maps an auth header/cookie to a user name ("" = not a valid user).
func labUser(r *http.Request) string {
	switch r.Header.Get("Authorization") {
	case "Bearer token-a":
		return "alice"
	case "Bearer token-b":
		return "bob"
	}
	if c, err := r.Cookie("session"); err == nil {
		switch c.Value {
		case "sess-a":
			return "alice"
		case "sess-b":
			return "bob"
		}
	}
	return ""
}

func labUUID() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", rand.Uint32(), rand.Intn(1<<16), rand.Intn(1<<16), rand.Intn(1<<16), rand.Int63n(1<<48))
}

func labHandler() http.Handler {
	mux := http.NewServeMux()
	deny := func(w http.ResponseWriter, code int, msg string) {
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"error":%q}`, msg)
	}

	// VULN: no auth at all.
	mux.HandleFunc("/public/stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"visitors":1203,"signups":44}`)
	})
	// VULN: IDOR — any valid user reads account 1 (alice's).
	mux.HandleFunc("/accounts/1", func(w http.ResponseWriter, r *http.Request) {
		if labUser(r) == "" {
			deny(w, 401, "unauthenticated")
			return
		}
		fmt.Fprint(w, `{"owner":"alice","balance":948210,"iban":"DE00 1234","notes":"private"}`)
	})
	// SAFE: proper per-user data.
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		u := labUser(r)
		if u == "" {
			deny(w, 401, "unauthenticated")
			return
		}
		fmt.Fprintf(w, `{"user":%q,"email":"%s@example.com","plan":"pro"}`, u, u)
	})
	// SAFE: owner-only resource.
	mux.HandleFunc("/profiles/42", func(w http.ResponseWriter, r *http.Request) {
		switch labUser(r) {
		case "":
			deny(w, 401, "unauthenticated")
		case "bob":
			deny(w, 403, "forbidden")
		default:
			fmt.Fprint(w, `{"user":"alice","id":42,"secret":"alice-only"}`)
		}
	})
	// SAFE: denies with HTTP 200 + error JSON ("soft deny") for everyone.
	mux.HandleFunc("/invoices/9", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"forbidden","code":403}`)
	})
	// VULN: only checks that an Authorization header EXISTS.
	mux.HandleFunc("/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			deny(w, 401, "no auth")
			return
		}
		fmt.Fprint(w, `{"items":["report-q1","report-q2"],"count":2,"owner":"alice"}`)
	})
	// VULN: crashes for anyone but alice.
	mux.HandleFunc("/crash", func(w http.ResponseWriter, r *http.Request) {
		if labUser(r) == "alice" {
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		w.WriteHeader(500)
		fmt.Fprint(w, `{"error":"nil pointer in auth middleware"}`)
	})
	// SAFE: empty 200 for valid users.
	mux.HandleFunc("/avatars/1", func(w http.ResponseWriter, r *http.Request) {
		if labUser(r) == "" {
			deny(w, 401, "unauthenticated")
			return
		}
		w.WriteHeader(200)
	})
	// SHARED LIST: same items for both users, with volatile fields that
	// change on every request (uuid, unix time, latency) in minified JSON.
	mux.HandleFunc("/feed", func(w http.ResponseWriter, r *http.Request) {
		if labUser(r) == "" {
			deny(w, 401, "unauthenticated")
			return
		}
		fmt.Fprintf(w, `{"request_id":%q,"served_at":%d,"latency_ms":%d,"items":[{"id":1,"title":"hello"},{"id":2,"title":"world"}]}`,
			labUUID(), time.Now().UnixMilli(), 5+rand.Intn(90))
	})
	// SAFE (declared public in the spec with security: []).
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	// VULN: alice's inbox returned to any valid user, on a path with no id.
	mux.HandleFunc("/inbox", func(w http.ResponseWriter, r *http.Request) {
		if labUser(r) == "" {
			deny(w, 401, "unauthenticated")
			return
		}
		fmt.Fprintf(w, `{"owner":"alice@example.com","unread":3,"rid":%q}`, labUUID())
	})
	// Spec gives no example for {wid}; reachable only via --resource.
	mux.HandleFunc("/widgets/", func(w http.ResponseWriter, r *http.Request) {
		if labUser(r) == "" {
			deny(w, 401, "unauthenticated")
			return
		}
		fmt.Fprint(w, `{"widget":"w"}`)
	})
	// VULN (cookie API): only checks that a session cookie EXISTS.
	mux.HandleFunc("/c/me", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("session"); err != nil {
			deny(w, 401, "no session")
			return
		}
		fmt.Fprint(w, `{"user":"alice","plan":"pro","theme":"dark"}`)
	})
	// SAFE (cookie API): validates the session properly.
	mux.HandleFunc("/c/profile", func(w http.ResponseWriter, r *http.Request) {
		u := labUser(r)
		if u == "" {
			deny(w, 401, "bad session")
			return
		}
		fmt.Fprintf(w, `{"user":%q,"settings":{"lang":"en"}}`, u)
	})
	return mux
}

const labBearerSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "lab", "version": "1"},
  "security": [{"bearer": []}],
  "paths": {
    "/public/stats": {"get": {}},
    "/accounts/{id}": {"parameters": [{"name": "id", "in": "path", "required": true, "example": 1}], "get": {}},
    "/me": {"get": {}},
    "/profiles/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": true, "example": 42}]}},
    "/invoices/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": true, "example": 9}]}},
    "/session": {"get": {}},
    "/crash": {"get": {}},
    "/avatars/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": true, "example": 1}]}},
    "/feed": {"get": {}},
    "/health": {"get": {"security": []}},
    "/inbox": {"get": {}},
    "/widgets/{wid}": {"get": {"parameters": [{"name": "wid", "in": "path", "required": true}]}}
  }
}`

const labCookieSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "lab-cookie", "version": "1"},
  "paths": {
    "/c/me": {"get": {}},
    "/c/profile": {"get": {}}
  }
}`

// runLab runs the full pipeline against the lab server and returns, per
// operation label, the sorted list of "type/severity" findings.
func runLab(t *testing.T, specJSON, authA, authB string) map[string][]string {
	t.Helper()
	srv := httptest.NewServer(labHandler())
	defer srv.Close()

	doc, err := spec.Parse([]byte(specJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	templates, _, err := spec.Build(doc, srv.URL, spec.ResourceOverride{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ids, err := assembleIdentities(authA, authB, true, true)
	if err != nil {
		t.Fatalf("identities: %v", err)
	}
	eng := engine.New(engine.DefaultConfig())
	defer eng.Close()

	got := map[string][]string{}
	for _, tmpl := range templates {
		op := tmpl.Meta.(*spec.Operation)
		got[tmpl.Method+" "+op.Path] = []string{}
	}
	for _, f := range scan(context.Background(), eng, templates, ids) {
		got[f.Operation] = append(got[f.Operation], f.Type+"/"+f.Severity)
	}
	for k := range got {
		sort.Strings(got[k])
	}
	return got
}

func compareLab(t *testing.T, got, want map[string][]string) {
	t.Helper()
	ops := make([]string, 0, len(want))
	for op := range want {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		w := append([]string{}, want[op]...)
		sort.Strings(w)
		g, ok := got[op]
		if !ok {
			t.Errorf("%-22s not tested at all (want %v)", op, w)
			continue
		}
		if strings.Join(g, ",") != strings.Join(w, ",") {
			t.Errorf("%-22s got %v, want %v", op, g, w)
		}
	}
}

func TestLabBearerAPI(t *testing.T) {
	got := runLab(t, labBearerSpec, "bearer:token-a", "bearer:token-b")
	compareLab(t, got, map[string][]string{
		"GET /public/stats":  {"broken-authentication/high"},
		"GET /accounts/{id}": {"cross-user-access/high"},
		"GET /me":            {},
		"GET /profiles/{id}": {},
		"GET /invoices/{id}": {},
		"GET /session":       {"invalid-token-accepted/high"},
		"GET /crash":         {"auth-server-error/low"},
		"GET /avatars/{id}":  {},
		"GET /feed":          {"cross-user-access/medium"},
		"GET /health":        {},
		"GET /inbox":         {"cross-user-access/medium"},
	})
}

func TestLabCookieAPI(t *testing.T) {
	got := runLab(t, labCookieSpec, "cookie:session=sess-a", "cookie:session=sess-b")
	compareLab(t, got, map[string][]string{
		"GET /c/me":      {"invalid-token-accepted/high"},
		"GET /c/profile": {},
	})
}
