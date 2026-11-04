package diff

import "testing"

// TestSimHashIgnoresVolatileTokens is the whole reason SimHash exists in
// falcon: two API responses that differ only in request-id / timestamp /
// CSRF token must hash within similarityThreshold of each other, or IDOR
// detection falls apart (every response looks unique and no match ever
// fires).
func TestSimHashIgnoresVolatileTokens(t *testing.T) {
	a := []byte(`{"user":"alice","id":42,"request_id":"550e8400-e29b-41d4-a716-446655440000","ts":"2025-11-01T10:00:00Z"}`)
	b := []byte(`{"user":"alice","id":42,"request_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","ts":"2025-11-01T10:00:05Z"}`)
	d := Hamming(Hash(a), Hash(b))
	if d > similarityThreshold {
		t.Errorf("SimHash distance = %d, want <= %d — volatile tokens leaked into the hash", d, similarityThreshold)
	}
}

func TestSimHashDistinguishesDifferentUsers(t *testing.T) {
	// Two responses with GENUINELY different user data must be far apart —
	// otherwise falcon flags IDOR on every endpoint.
	alice := []byte(`{"user":"alice","email":"alice@example.com","role":"admin","notes":"she manages finance and HR"}`)
	bob := []byte(`{"user":"bob","email":"bob@example.com","role":"guest","notes":"he reads documentation only"}`)
	d := Hamming(Hash(alice), Hash(bob))
	if d <= similarityThreshold {
		t.Errorf("SimHash distance = %d, want > %d — distinct user payloads look identical", d, similarityThreshold)
	}
}

func TestHashEmptyBodyIsZero(t *testing.T) {
	if Hash(nil) != 0 {
		t.Error("empty body should hash to 0 so two empties compare equal")
	}
	if Hash([]byte{}) != 0 {
		t.Error("empty body should hash to 0")
	}
}
