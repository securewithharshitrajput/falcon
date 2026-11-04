// falcon is an authenticated API fuzzer: point it at an OpenAPI 3.x spec
// plus two or more test identities, and it fires each endpoint as each
// identity, diffs the responses, and classifies known auth-failure
// patterns (broken authentication, invalid-token-accepted, cross-user
// access/IDOR, role-differential, 5xx under adversarial auth).
//
// Designed as the open-source counterpart to Burp's authenticated-scanner
// features: covers the most common auth-boundary bugs without a $4K/yr
// commercial dependency. For authorized testing only.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/securewithharshitrajput/falcon/internal/banner"
	"github.com/securewithharshitrajput/falcon/internal/diff"
	"github.com/securewithharshitrajput/falcon/internal/engine"
	"github.com/securewithharshitrajput/falcon/internal/identity"
	"github.com/securewithharshitrajput/falcon/internal/report"
	"github.com/securewithharshitrajput/falcon/internal/spec"
)

// stringListFlag lets a flag be repeated: --resource a=1 --resource b=2.
type stringListFlag []string

func (s *stringListFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringListFlag) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	var (
		specPath    = flag.String("spec", "", "path to OpenAPI 3.x JSON spec (required)")
		baseURL     = flag.String("u", "", "target base URL; overrides the spec's `servers:` entry")
		authA       = flag.String("auth-a", "", "auth for identity A (e.g. bearer:<token>, cookie:<...>, basic:<u>:<p>, header:<Name>=<Value>)")
		authB       = flag.String("auth-b", "", "auth for identity B — needed to detect cross-user access/IDOR")
		includeAnon = flag.Bool("anon", true, "also run every request with no auth (catches missing-auth endpoints)")
		includeInv  = flag.Bool("invalid-token", true, "also run every request with an obviously-invalid bearer token (catches middleware that doesn't actually validate)")
		concurrency = flag.Int("c", 10, "concurrent requests across all identities")
		timeout     = flag.Duration("timeout", 15*time.Second, "per-request timeout")
		insecure    = flag.Bool("k", false, "skip TLS verification (self-signed dev/staging certs only)")
		proxy       = flag.String("x", "", "route all requests through this HTTP proxy, e.g. http://127.0.0.1:8080 for Burp/ZAP")
		jsonOut     = flag.String("json", "", "write findings as JSON to this path")
		sarifOut    = flag.String("sarif", "", "write findings as SARIF 2.1.0 to this path")
		noBanner    = flag.Bool("no-banner", false, "suppress the startup banner")
	)
	var resources stringListFlag
	flag.Var(&resources, "resource", `fill a spec parameter with a concrete value, repeatable, format name=value (e.g. --resource id=42)`)
	flag.Parse()

	banner.Print(*noBanner)

	if *specPath == "" {
		fmt.Fprintln(os.Stderr, "usage: falcon --spec openapi.json --auth-a bearer:TOKA --auth-b bearer:TOKB [--resource id=42] [-u https://api.example.com]")
		fmt.Fprintln(os.Stderr, "\nFor authorized security testing only.")
		os.Exit(2)
	}

	// Load + parse the spec.
	data, err := os.ReadFile(*specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: could not read spec %s: %v\n", *specPath, err)
		os.Exit(2)
	}
	doc, err := spec.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: spec parse failed: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "falcon: loaded spec %q v%s — %d operation(s)\n", doc.Title, doc.Version, len(doc.Operations))

	effectiveBase := *baseURL
	if effectiveBase == "" {
		effectiveBase = doc.BaseURL
	}
	if effectiveBase == "" {
		fmt.Fprintln(os.Stderr, "falcon: no base URL (spec has no `servers:` and -u not given)")
		os.Exit(2)
	}

	// Build identities from flags. At least one authenticated identity is
	// required; the anonymous + invalid-token identities are additive.
	identities, err := assembleIdentities(*authA, *authB, *includeAnon, *includeInv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "falcon: identities: ")
	names := make([]string, len(identities))
	for i, id := range identities {
		names[i] = id.Role
	}
	fmt.Fprintln(os.Stderr, strings.Join(names, ", "))

	// Build the operator's --resource overrides.
	override := spec.ResourceOverride{
		ByName: parseResources(resources),
	}

	// Build the per-operation request templates.
	templates, err := spec.Build(doc, effectiveBase, override)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: cannot build request templates: %v\n", err)
		os.Exit(2)
	}

	// Engine.
	cfg := engine.DefaultConfig()
	cfg.Concurrency = *concurrency
	cfg.Timeout = *timeout
	cfg.InsecureSkipVerify = *insecure
	cfg.ProxyURL = *proxy
	eng := engine.New(cfg)
	defer eng.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	fmt.Fprintf(os.Stderr, "falcon: running %d operation(s) × %d identities = %d requests...\n",
		len(templates), len(identities), len(templates)*len(identities))

	var allFindings []diff.Finding
	for _, tmpl := range templates {
		if ctx.Err() != nil {
			break
		}
		reqs := make([]engine.Request, len(identities))
		for i, id := range identities {
			r := tmpl
			r.Headers = id.Apply(tmpl.Headers)
			reqs[i] = r
		}
		resps := eng.DoAll(ctx, reqs)
		allFindings = append(allFindings, diff.Classify(tmpl, identities, resps)...)
	}

	dur := time.Since(start).Round(time.Millisecond)
	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "falcon: interrupted after %s — showing partial results\n\n", dur)
	} else {
		fmt.Fprintf(os.Stderr, "falcon: done in %s\n\n", dur)
	}

	rep := report.Build(effectiveBase, allFindings)
	report.WriteSummary(os.Stdout, rep)

	writeOutput("JSON", *jsonOut, rep, report.WriteJSON)
	writeOutput("SARIF", *sarifOut, rep, report.WriteSARIF)
}

// assembleIdentities builds the identity list, requiring at least one
// authenticated identity so differential results are meaningful. Returns
// a clear error naming the missing input rather than a cryptic nil panic.
func assembleIdentities(authA, authB string, anon, invalid bool) ([]identity.Identity, error) {
	var ids []identity.Identity
	if authA != "" {
		id, err := identity.ParseAuth("user-a", authA)
		if err != nil {
			return nil, fmt.Errorf("--auth-a: %w", err)
		}
		ids = append(ids, id)
	}
	if authB != "" {
		id, err := identity.ParseAuth("user-b", authB)
		if err != nil {
			return nil, fmt.Errorf("--auth-b: %w", err)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("at least one of --auth-a / --auth-b is required (falcon's whole point is DIFFERENTIAL testing; without a real user it's just a crawler)")
	}
	if anon {
		ids = append(ids, identity.Anonymous())
	}
	if invalid {
		ids = append(ids, identity.Invalid())
	}
	return ids, nil
}

func parseResources(entries []string) map[string]string {
	out := map[string]string{}
	for _, e := range entries {
		if k, v, ok := strings.Cut(e, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func writeOutput(label, path string, d report.Document, write func(io.Writer, report.Document) error) {
	if path == "" {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: could not write %s report: %v\n", label, err)
		os.Exit(1)
	}
	defer f.Close()
	if err := write(f, d); err != nil {
		fmt.Fprintf(os.Stderr, "falcon: error encoding %s: %v\n", label, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "falcon: wrote %s report to %s\n", label, path)
}
