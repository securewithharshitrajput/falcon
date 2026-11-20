package identity

import (
	"strings"
	"testing"
)

// InvalidFrom must mirror the real user's auth SCHEME with a canary value, so
// "is the credential validated?" works beyond bearer tokens.
func TestInvalidFromMatchesScheme(t *testing.T) {
	t.Run("bearer", func(t *testing.T) {
		inv := InvalidFrom(Bearer("user-a", "real-token"))
		got := inv.Headers["Authorization"]
		if !strings.HasPrefix(got, "Bearer ") || strings.Contains(got, "real-token") {
			t.Errorf("bearer canary = %q, want a Bearer with a canary value", got)
		}
		if !inv.IsInvalid || inv.Role != "invalid-token" {
			t.Errorf("tagging wrong: %+v", inv)
		}
	})

	t.Run("cookie keeps names, replaces values", func(t *testing.T) {
		inv := InvalidFrom(Cookie("user-a", "session=abc123; csrf=xyz789"))
		got := inv.Headers["Cookie"]
		if !strings.Contains(got, "session=") || !strings.Contains(got, "csrf=") {
			t.Errorf("cookie canary should keep cookie names, got %q", got)
		}
		if strings.Contains(got, "abc123") || strings.Contains(got, "xyz789") {
			t.Errorf("cookie canary must not keep the real values, got %q", got)
		}
	})

	t.Run("basic", func(t *testing.T) {
		inv := InvalidFrom(Basic("user-a", "alice", "s3cret"))
		got := inv.Headers["Authorization"]
		if !strings.HasPrefix(got, "Basic ") || strings.Contains(got, "s3cret") {
			t.Errorf("basic canary = %q, want a Basic scheme with a canary value", got)
		}
	})

	t.Run("custom header", func(t *testing.T) {
		inv := InvalidFrom(Header("user-a", "X-API-Key", "KEY-A"))
		got := inv.Headers["X-API-Key"]
		if got == "" || strings.Contains(got, "KEY-A") {
			t.Errorf("custom-header canary = %q, want the same header name with a canary value", got)
		}
	})

	t.Run("no base creds falls back to bearer", func(t *testing.T) {
		inv := InvalidFrom(Identity{Role: "x"})
		if inv.Headers["Authorization"] == "" {
			t.Error("InvalidFrom with no base creds should still send a bogus bearer")
		}
	})
}
