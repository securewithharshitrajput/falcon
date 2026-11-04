// SimHash for body similarity: a 64-bit locality-sensitive hash over word
// 3-gram shingles. Two responses whose bodies differ only in cosmetic
// bits (timestamps, request IDs, random slugs) still produce hashes within
// a few bits of each other, which lets the diff classifier say "same
// content shape, bit-level different" instead of either (a) comparing byte
// strings (misses common identity leaks, where User-A's name is rendered
// into the template) or (b) ignoring the body entirely (misses IDOR).
//
// Volatile patterns (UUIDs, numeric timestamps with a timezone, nonces)
// are redacted BEFORE shingling so a per-request CSRF token can't mask a
// genuine body match.
package diff

import (
	"bytes"
	"math/bits"
	"regexp"
	"strings"
)

// volatilePattern collapses tokens that change every request to a single
// placeholder before hashing — otherwise a fresh CSRF token on every
// response makes every body look unique and the detector misses IDORs.
var volatilePattern = regexp.MustCompile(
	`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` + // UUID
		`|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?` + // ISO8601
		`|\b\d{10,13}\b` + // unix timestamps (seconds or ms)
		`|\b[A-Fa-f0-9]{32,}\b`, // long hex (session ids, nonces)
)

// Normalize returns a hashable, redacted copy of body: lowercased, volatile
// patterns replaced, HTML/JSON whitespace collapsed.
func Normalize(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	s := volatilePattern.ReplaceAllString(string(body), "_")
	s = strings.ToLower(s)
	// collapse runs of whitespace to one space so formatting differences
	// (minified vs pretty JSON) don't change the shingle set
	return bytes.Join(bytes.Fields([]byte(s)), []byte(" "))
}

// Hash returns a 64-bit SimHash of body. Zero for an empty body (so two
// empties compare equal via Hamming(0,0) == 0).
func Hash(body []byte) uint64 {
	norm := Normalize(body)
	if len(norm) == 0 {
		return 0
	}
	words := bytes.Fields(norm)
	if len(words) < 3 {
		return fnv64(norm)
	}
	var vec [64]int
	for i := 0; i <= len(words)-3; i++ {
		shingle := bytes.Join(words[i:i+3], []byte(" "))
		h := fnv64(shingle)
		for b := 0; b < 64; b++ {
			if h&(1<<uint(b)) != 0 {
				vec[b]++
			} else {
				vec[b]--
			}
		}
	}
	var out uint64
	for b := 0; b < 64; b++ {
		if vec[b] > 0 {
			out |= 1 << uint(b)
		}
	}
	return out
}

// Hamming is the bit-distance between two SimHashes. Two bodies of the same
// "shape" typically fall within 0–8 bits of each other; anything over ~16
// is unrelated content.
func Hamming(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

// fnv64 is a tiny stdlib-free FNV-1a 64-bit hash used only as the SimHash
// building block. Pulling in hash/fnv would work too; this keeps the
// package self-contained.
func fnv64(b []byte) uint64 {
	const (
		offset uint64 = 14695981039346656037
		prime  uint64 = 1099511628211
	)
	h := offset
	for _, c := range b {
		h ^= uint64(c)
		h *= prime
	}
	return h
}
