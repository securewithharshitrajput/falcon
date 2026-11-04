package identity

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBearerBuildsCorrectHeader(t *testing.T) {
	id := Bearer("user-a", "abc.def.ghi")
	got := id.Headers["Authorization"]
	if got != "Bearer abc.def.ghi" {
		t.Errorf("got %q, want %q", got, "Bearer abc.def.ghi")
	}
	if id.Role != "user-a" {
		t.Errorf("role lost: %q", id.Role)
	}
}

func TestBasicEncodesWithBase64(t *testing.T) {
	id := Basic("user-a", "alice", "s3cret")
	v := id.Headers["Authorization"]
	if !strings.HasPrefix(v, "Basic ") {
		t.Fatalf("unexpected prefix: %q", v)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, "Basic "))
	if err != nil {
		t.Fatalf("not valid base64: %v", err)
	}
	if string(raw) != "alice:s3cret" {
		t.Errorf("decoded = %q, want alice:s3cret", raw)
	}
}

func TestApplyMergesButIdentityLosesToPerRequest(t *testing.T) {
	// Current behavior: per-request headers win when both set the same key
	// (identity provides the default, per-request can override).
	id := Bearer("x", "token")
	merged := id.Apply(map[string]string{"Authorization": "custom"})
	if merged["Authorization"] != "custom" {
		t.Errorf("per-request header should win; got %q", merged["Authorization"])
	}
}

func TestParseAuthAllForms(t *testing.T) {
	cases := []struct {
		in         string
		wantHeader string
		wantValue  string
		wantErr    bool
	}{
		{"bearer:xyz", "Authorization", "Bearer xyz", false},
		{"cookie:session=abc", "Cookie", "session=abc", false},
		{"basic:u:p", "Authorization", "", false}, // value is base64, checked separately
		{"header:X-API-Key=k1", "X-API-Key", "k1", false},
		{"noprefix", "", "", true},
		{"bearer:", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			id, err := ParseAuth("user", c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if c.wantErr {
				return
			}
			got := id.Headers[c.wantHeader]
			if c.wantValue != "" && got != c.wantValue {
				t.Errorf("header %q = %q, want %q", c.wantHeader, got, c.wantValue)
			}
			if got == "" {
				t.Errorf("expected header %q to be set, got none", c.wantHeader)
			}
		})
	}
}

func TestAnonymousAndInvalidAreTagged(t *testing.T) {
	if !Anonymous().IsAnon {
		t.Error("Anonymous() must have IsAnon=true so Classify can route it")
	}
	if !Invalid().IsInvalid {
		t.Error("Invalid() must have IsInvalid=true so Classify can route it")
	}
	if len(Invalid().Headers) == 0 {
		t.Error("Invalid() must send some header — the whole point is to prove the server IGNORES it")
	}
}
