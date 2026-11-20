// Body similarity for falcon's differential classifier.
//
// The question the classifier asks is "did two responses carry the SAME
// resource?" — not "are these bytes equal." Responses routinely differ in
// cosmetic ways (a per-request CSRF token, a timestamp, a request id) while
// representing the same underlying data, and an IDOR is exactly the case
// where two identities get the same resource.
//
// falcon measures similarity as the Jaccard overlap of token-shingle sets
// after redacting volatile values. This is deliberately NOT SimHash: SimHash
// is a locality-sensitive hash tuned for large documents, and real API
// responses are SHORT JSON. On a short body a single changed token flips many
// SimHash bits, so genuinely-identical resources look different and IDORs slip
// through. Jaccard over shingles stays accurate at any body length.
package diff

import (
	"regexp"
	"strings"
)

// volatilePattern collapses tokens that change every request to a single
// placeholder before shingling — otherwise a fresh CSRF token or timestamp on
// every response makes every body look unique and the detector misses IDORs.
var volatilePattern = regexp.MustCompile(
	`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` + // UUID
		`|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?` + // ISO8601
		`|\b\d{10,13}\b` + // unix timestamps (seconds or ms)
		`|\b[A-Fa-f0-9]{32,}\b`, // long hex (session ids, nonces)
)

// Normalize returns a redacted, tokenized copy of body: volatile patterns
// replaced, lowercased, then tokenized on STRUCTURE (not just whitespace).
//
// Tokenizing on structure is essential: real API responses are minified JSON
// with no spaces, e.g. {"user":"alice","id":42}. Splitting only on whitespace
// would make the whole body a single token. Emitting maximal runs of
// [a-z0-9_] (plus UTF-8 continuation bytes) makes minified and pretty JSON
// tokenize identically into field names, string values and numbers.
func Normalize(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	s := volatilePattern.ReplaceAllString(string(body), "_")
	s = strings.ToLower(s)

	out := make([]byte, 0, len(s))
	inTok := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		isTokenByte := c == '_' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c >= 0x80
		if isTokenByte {
			out = append(out, c)
			inTok = true
		} else if inTok {
			out = append(out, ' ')
			inTok = false
		}
	}
	if n := len(out); n > 0 && out[n-1] == ' ' {
		out = out[:n-1]
	}
	return out
}

// tokens splits a normalized body into its token list.
func tokens(body []byte) []string {
	n := Normalize(body)
	if len(n) == 0 {
		return nil
	}
	return strings.Fields(string(n))
}

// shingleSet returns the set of overlapping 2-grams of tokens (adjacent token
// pairs). 2-grams keep some word order — so {"a":"x","b":"y"} and
// {"a":"y","b":"x"} aren't treated as identical — while staying robust on
// short bodies. A body of a single token degrades to that one token.
func shingleSet(body []byte) map[string]struct{} {
	tok := tokens(body)
	set := make(map[string]struct{}, len(tok))
	switch len(tok) {
	case 0:
		return set
	case 1:
		set[tok[0]] = struct{}{}
		return set
	}
	for i := 0; i+1 < len(tok); i++ {
		set[tok[i]+"\x00"+tok[i+1]] = struct{}{}
	}
	return set
}

// Similarity is the Jaccard overlap (|A∩B| / |A∪B|) of two bodies' shingle
// sets, in [0,1]. Two empty bodies are identical (1.0); an empty vs a
// non-empty body share nothing (0.0).
func Similarity(a, b []byte) float64 {
	sa, sb := shingleSet(a), shingleSet(b)
	if len(sa) == 0 && len(sb) == 0 {
		return 1.0
	}
	if len(sa) == 0 || len(sb) == 0 {
		return 0.0
	}
	// Iterate the smaller set for the intersection.
	small, large := sa, sb
	if len(large) < len(small) {
		small, large = large, small
	}
	inter := 0
	for s := range small {
		if _, ok := large[s]; ok {
			inter++
		}
	}
	union := len(sa) + len(sb) - inter
	return float64(inter) / float64(union)
}
