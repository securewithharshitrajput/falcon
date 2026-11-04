// Package banner prints falcon's startup banner: a block-letter logo with a
// rotating tip. Goes to stderr; stdout stays clean for findings output so
// `falcon ... > findings.json` works without needing a -quiet flag.
package banner

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
)

const (
	Version = "0.1.0"
	Name    = "FALCON"
	Tagline = "authenticated API fuzzer — IDOR, broken auth, token-skip"
)

var tips = []string{
	"tip: --auth-a bearer:TOKA  --auth-b bearer:TOKB  — two identities so IDOR is testable",
	"tip: --resource id=42 fills {id} path params with a value your API will accept",
	"tip: --invalid-token adds a canary identity that proves the server actually validates tokens",
	"tip: -x http://127.0.0.1:8080 routes everything through Burp/ZAP for inspection",
	"tip: --sarif out.sarif → upload to GitHub code scanning for a reviewable PR surface",
	"tip: the [HIGH] findings are real auth bugs — triage those before anything else",
	"tip: role-differential (INFO) catches RBAC inconsistencies — review by hand",
}

// 5-row block glyphs for the letters in FALCON.
var glyphs = map[byte][5]string{
	'F': {"███████", "██     ", "█████  ", "██     ", "██     "},
	'A': {"███████", "██   ██", "███████", "██   ██", "██   ██"},
	'L': {"██     ", "██     ", "██     ", "██     ", "███████"},
	'C': {"███████", "██     ", "██     ", "██     ", "███████"},
	'O': {"███████", "██   ██", "██   ██", "██   ██", "███████"},
	'N': {"██   ██", "███  ██", "██ █ ██", "██  ███", "██   ██"},
}

func renderLogo(word string) string {
	var rows [5]strings.Builder
	for i, ch := range []byte(word) {
		g, ok := glyphs[ch]
		if !ok {
			panic(fmt.Sprintf("banner: no glyph for %q in %q", ch, word))
		}
		for row := 0; row < 5; row++ {
			if i > 0 {
				rows[row].WriteString("  ")
			}
			rows[row].WriteString(g[row])
		}
	}
	var out strings.Builder
	out.WriteByte('\n')
	for _, r := range rows {
		out.WriteString(r.String())
		out.WriteByte('\n')
	}
	return out.String()
}

var logo = renderLogo(Name)

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// Print writes the banner to stderr. suppress forces the plain one-line form.
func Print(suppress bool) {
	if suppress {
		return
	}
	w := os.Stderr
	tip := tips[rand.Intn(len(tips))]
	if !isTerminal(w) {
		fmt.Fprintf(w, "falcon v%s — %s\n%s\n\n", Version, Tagline, tip)
		return
	}
	const (
		bold  = "\x1b[1m"
		cyan  = "\x1b[36m"
		dim   = "\x1b[2m"
		reset = "\x1b[0m"
	)
	fmt.Fprint(w, cyan+bold+logo+reset)
	fmt.Fprintf(w, "        %sv%s%s  %s%s%s\n", bold, Version, reset, dim, Tagline, reset)
	fmt.Fprintf(w, "        %s%s%s\n\n", dim, tip, reset)
}
