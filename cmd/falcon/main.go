// falcon is an authenticated API fuzzer: point it at an OpenAPI 3.x spec
// (JSON or YAML) plus two or more test identities, and it fires each
// endpoint as each identity, diffs the responses, and classifies known
// auth-failure patterns (broken authentication, invalid-token-accepted,
// cross-user access/IDOR, role-differential, 5xx under adversarial auth).
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
	"sort"
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

// Exit codes. 0 = clean, 2 = usage/config error, 1 = output write error,
// 3 = findings met the --fail-on threshold (useful in CI gates).
const (
	exitFindings = 3
)

// stringListFlag lets a flag be repeated: --resource a=1 --resource b=2.
type stringListFlag []string

func (s *stringListFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringListFlag) Set(v string) error { *s = append(*s, v); return nil }

// mutatingMethods are the HTTP verbs that can change server state. Falcon
// warns before firing these at a live API so an operator doesn't delete test
// data by surprise.
var mutatingMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		specPath    = flag.String("spec", "", "path to OpenAPI 3.x spec, JSON or YAML (required)")
		baseURL     = flag.String("u", "", "target base URL; overrides the spec's `servers:` entry")
		authA       = flag.String("auth-a", "", "auth for identity A (e.g. bearer:<token>, cookie:<...>, basic:<u>:<p>, header:<Name>=<Value>)")
		authB       = flag.String("auth-b", "", "auth for identity B — needed to detect cross-user access/IDOR")
		includeAnon = flag.Bool("anon", true, "also run every request with no auth (catches missing-auth endpoints)")
		includeInv  = flag.Bool("invalid-token", true, "also run every request with an obviously-invalid bearer token (catches middleware that doesn't actually validate)")
		methods     = flag.String("methods", "", "comma-separated HTTP methods to test (e.g. GET,HEAD); empty = all methods in the spec")
		concurrency = flag.Int("c", 10, "concurrent requests across all identities and operations")
		timeout     = flag.Duration("timeout", 15*time.Second, "per-request timeout")
		insecure    = flag.Bool("k", false, "skip TLS verification (self-signed dev/staging certs only)")
		proxy       = flag.String("x", "", "route all requests through this HTTP proxy, e.g. http://127.0.0.1:8080 for Burp/ZAP")
		jsonOut     = flag.String("json", "", "write findings as JSON to this path")
		sarifOut    = flag.String("sarif", "", "write findings as SARIF 2.1.0 to this path")
		failOn      = flag.String("fail-on", "none", "exit non-zero if any finding is at or above this severity: none|info|low|medium|high")
		noBanner    = flag.Bool("no-banner", false, "suppress the startup banner")
		showVersion = flag.Bool("version", false, "print falcon's version and exit")
	)
	var resources stringListFlag
	flag.Var(&resources, "resource", `fill a spec parameter with a concrete value, repeatable, format name=value (e.g. --resource id=42)`)
	flag.Parse()

	if *showVersion {
		fmt.Printf("falcon v%s\n", banner.Version)
		return 0
	}

	banner.Print(*noBanner)

	if !validFailOn(*failOn) {
		fmt.Fprintf(os.Stderr, "falcon: invalid --fail-on %q (want one of: none, info, low, medium, high)\n", *failOn)
		return 2
	}

	if *specPath == "" {
		fmt.Fprintln(os.Stderr, "usage: falcon --spec openapi.yaml --auth-a bearer:TOKA --auth-b bearer:TOKB [--resource id=42] [-u https://api.example.com]")
		fmt.Fprintln(os.Stderr, "\nFor authorized security testing only.")
		return 2
	}

	// Load + parse the spec (JSON or YAML, auto-detected).
	data, err := os.ReadFile(*specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: could not read spec %s: %v\n", *specPath, err)
		return 2
	}
	doc, err := spec.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: spec parse failed: %v\n", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "falcon: loaded spec %q v%s — %d operation(s)\n", doc.Title, doc.Version, len(doc.Operations))

	effectiveBase := *baseURL
	if effectiveBase == "" {
		effectiveBase = doc.BaseURL
	}
	if effectiveBase == "" {
		fmt.Fprintln(os.Stderr, "falcon: no base URL (spec has no `servers:` and -u not given)")
		return 2
	}

	// Build identities from flags. At least one authenticated identity is
	// required; the anonymous + invalid-token identities are additive.
	identities, err := assembleIdentities(*authA, *authB, *includeAnon, *includeInv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: %v\n", err)
		return 2
	}
	names := make([]string, len(identities))
	for i, id := range identities {
		names[i] = id.Role
	}
	fmt.Fprintf(os.Stderr, "falcon: identities: %s\n", strings.Join(names, ", "))

	// Build the operator's --resource and --methods overrides.
	methodSet, err := parseMethods(*methods)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: %v\n", err)
		return 2
	}
	override := spec.ResourceOverride{
		ByName:  parseResources(resources),
		Methods: methodSet,
	}

	// Build the per-operation request templates.
	templates, err := spec.Build(doc, effectiveBase, override)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: cannot build request templates: %v\n", err)
		return 2
	}
	if len(templates) == 0 {
		fmt.Fprintln(os.Stderr, "falcon: no operations to test (spec had none, or --methods filtered them all out)")
		return 2
	}

	// Safety: warn loudly before sending state-changing requests to a live
	// target so a scan doesn't quietly mutate or delete test data.
	if warnMutating(os.Stderr, templates) && *methods == "" {
		fmt.Fprintln(os.Stderr, "falcon: (restrict with --methods GET,HEAD to run read-only)")
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

	allFindings := scan(ctx, eng, templates, identities)

	dur := time.Since(start).Round(time.Millisecond)
	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "falcon: interrupted after %s — showing partial results\n\n", dur)
	} else {
		fmt.Fprintf(os.Stderr, "falcon: done in %s\n\n", dur)
	}

	rep := report.Build(effectiveBase, allFindings)
	report.WriteSummary(os.Stdout, rep)

	if !writeOutput("JSON", *jsonOut, rep, report.WriteJSON) {
		return 1
	}
	if !writeOutput("SARIF", *sarifOut, rep, report.WriteSARIF) {
		return 1
	}

	if meetsFailOn(rep.Findings, *failOn) {
		fmt.Fprintf(os.Stderr, "falcon: findings at or above severity %q — exiting %d\n", *failOn, exitFindings)
		return exitFindings
	}
	return 0
}

// scan fires every (operation × identity) request through one bounded
// concurrent batch — so -c actually governs throughput across the whole
// spec — then regroups the responses per operation and classifies each
// matrix. Classification order doesn't matter: the report sorts findings.
func scan(ctx context.Context, eng *engine.Engine, templates []engine.Request, identities []identity.Identity) []diff.Finding {
	type coord struct{ op, id int }
	flat := make([]engine.Request, 0, len(templates)*len(identities))
	coords := make([]coord, 0, cap(flat))
	for oi, tmpl := range templates {
		for ii, id := range identities {
			r := tmpl
			r.Headers = id.Apply(tmpl.Headers)
			flat = append(flat, r)
			coords = append(coords, coord{oi, ii})
		}
	}

	resps := eng.DoAll(ctx, flat)

	matrix := make([][]engine.Response, len(templates))
	for i := range matrix {
		matrix[i] = make([]engine.Response, len(identities))
	}
	for k, c := range coords {
		matrix[c.op][c.id] = resps[k]
	}

	var allFindings []diff.Finding
	for oi, tmpl := range templates {
		allFindings = append(allFindings, diff.Classify(tmpl, identities, matrix[oi])...)
	}
	return allFindings
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

// parseMethods turns a "GET,POST" style flag into an upper-cased allow-set.
// An empty flag means "all methods" (nil set). Unknown verbs are rejected so
// a typo doesn't silently drop every operation.
func parseMethods(s string) (map[string]bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	known := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}
	out := map[string]bool{}
	for _, m := range strings.Split(s, ",") {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			continue
		}
		if !known[m] {
			return nil, fmt.Errorf("--methods: unknown HTTP method %q", m)
		}
		out[m] = true
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// warnMutating prints a one-line warning naming the state-changing methods
// that will be fired, and reports whether any were present.
func warnMutating(w io.Writer, templates []engine.Request) bool {
	seen := map[string]int{}
	for _, t := range templates {
		if mutatingMethods[strings.ToUpper(t.Method)] {
			seen[strings.ToUpper(t.Method)]++
		}
	}
	if len(seen) == 0 {
		return false
	}
	methods := make([]string, 0, len(seen))
	total := 0
	for m, n := range seen {
		methods = append(methods, fmt.Sprintf("%s×%d", m, n))
		total += n
	}
	sort.Strings(methods)
	fmt.Fprintf(w, "falcon: WARNING — %d state-changing request(s) will be sent to the target (%s)\n", total, strings.Join(methods, ", "))
	return true
}

var failOnRank = map[string]int{
	"none":   0,
	"info":   1,
	"low":    2,
	"medium": 3,
	"high":   4,
}

func validFailOn(s string) bool {
	_, ok := failOnRank[strings.ToLower(strings.TrimSpace(s))]
	return ok
}

// meetsFailOn reports whether any finding's severity is at or above the
// configured threshold. "none" never trips.
func meetsFailOn(findings []diff.Finding, failOn string) bool {
	threshold := failOnRank[strings.ToLower(strings.TrimSpace(failOn))]
	if threshold == 0 {
		return false
	}
	for _, f := range findings {
		if failOnRank[f.Severity] >= threshold {
			return true
		}
	}
	return false
}

// writeOutput writes a report to path (if set). Returns false on failure so
// the caller can choose the process exit code without os.Exit here.
func writeOutput(label, path string, d report.Document, write func(io.Writer, report.Document) error) bool {
	if path == "" {
		return true
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falcon: could not write %s report: %v\n", label, err)
		return false
	}
	defer f.Close()
	if err := write(f, d); err != nil {
		fmt.Fprintf(os.Stderr, "falcon: error encoding %s: %v\n", label, err)
		return false
	}
	fmt.Fprintf(os.Stderr, "falcon: wrote %s report to %s\n", label, path)
	return true
}
