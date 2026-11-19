package main

import (
	"bytes"
	"testing"

	"github.com/securewithharshitrajput/falcon/internal/diff"
	"github.com/securewithharshitrajput/falcon/internal/engine"
)

func TestParseMethods(t *testing.T) {
	cases := []struct {
		in      string
		want    []string // expected keys (order-independent); nil => all
		wantErr bool
	}{
		{"", nil, false},
		{"  ", nil, false},
		{"get", []string{"GET"}, false},
		{"GET, post ,Delete", []string{"GET", "POST", "DELETE"}, false},
		{"GET,TRACE", nil, true},
	}
	for _, c := range cases {
		got, err := parseMethods(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseMethods(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if c.want == nil {
			if got != nil {
				t.Errorf("parseMethods(%q) = %v, want nil (all)", c.in, got)
			}
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("parseMethods(%q) = %v, want %v", c.in, got, c.want)
		}
		for _, m := range c.want {
			if !got[m] {
				t.Errorf("parseMethods(%q) missing %q", c.in, m)
			}
		}
	}
}

func TestMeetsFailOn(t *testing.T) {
	findings := []diff.Finding{
		{Type: "role-differential", Severity: diff.SeverityInfo},
		{Type: "auth-server-error", Severity: diff.SeverityLow},
	}
	cases := []struct {
		failOn string
		want   bool
	}{
		{"none", false},
		{"info", true}, // an info finding exists
		{"low", true},  // a low finding exists
		{"medium", false},
		{"high", false},
	}
	for _, c := range cases {
		if got := meetsFailOn(findings, c.failOn); got != c.want {
			t.Errorf("meetsFailOn(%q) = %v, want %v", c.failOn, got, c.want)
		}
	}
	// "none" with a HIGH finding present still never trips.
	if meetsFailOn([]diff.Finding{{Severity: diff.SeverityHigh}}, "none") {
		t.Error(`--fail-on none must never trip, even on HIGH`)
	}
	// Empty findings never trip any threshold.
	if meetsFailOn(nil, "high") {
		t.Error("no findings must not trip --fail-on high")
	}
}

func TestValidFailOn(t *testing.T) {
	for _, ok := range []string{"none", "info", "LOW", " medium ", "High"} {
		if !validFailOn(ok) {
			t.Errorf("validFailOn(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "critical", "warn"} {
		if validFailOn(bad) {
			t.Errorf("validFailOn(%q) = true, want false", bad)
		}
	}
}

func TestWarnMutating(t *testing.T) {
	// No mutating methods → no warning, returns false.
	readOnly := []engine.Request{{Method: "GET"}, {Method: "HEAD"}}
	var buf bytes.Buffer
	if warnMutating(&buf, readOnly) {
		t.Error("read-only templates should not warn")
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected output: %q", buf.String())
	}

	// Mixed → warning naming the mutating methods, returns true.
	mixed := []engine.Request{{Method: "GET"}, {Method: "DELETE"}, {Method: "POST"}, {Method: "post"}}
	buf.Reset()
	if !warnMutating(&buf, mixed) {
		t.Error("mutating templates should warn")
	}
	out := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("DELETE×1")) || !bytes.Contains(buf.Bytes(), []byte("POST×2")) {
		t.Errorf("warning should count mutating methods, got: %q", out)
	}
}
