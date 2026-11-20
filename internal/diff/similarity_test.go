package diff

import "testing"

// Two responses that differ only in request-id / timestamp / CSRF token must
// be similar, or IDOR detection falls apart (every response looks unique and
// no match ever fires).
func TestSimilarityIgnoresVolatileTokens(t *testing.T) {
	a := []byte(`{"user":"alice","id":42,"request_id":"550e8400-e29b-41d4-a716-446655440000","ts":"2025-11-01T10:00:00Z"}`)
	b := []byte(`{"user":"alice","id":42,"request_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","ts":"2025-11-01T10:00:05Z"}`)
	if s := Similarity(a, b); s < similarityThreshold {
		t.Errorf("similarity = %.2f, want >= %.2f — volatile tokens leaked into the comparison", s, similarityThreshold)
	}
}

// The critical short-body case that SimHash got wrong: minified JSON whose
// only difference is one volatile-ish number must still read as the same
// resource.
func TestSimilaritySurvivesShortMinifiedBodies(t *testing.T) {
	a := []byte(`{"request_id":"2f14996c-08a2-c603-4d4c-f42bc88d7f83","latency_ms":6,"items":[{"id":1,"title":"hello"},{"id":2,"title":"world"}]}`)
	b := []byte(`{"request_id":"12a6beb6-fe59-86cc-e436-2c59e6b61516","latency_ms":10,"items":[{"id":1,"title":"hello"},{"id":2,"title":"world"}]}`)
	if s := Similarity(a, b); s < similarityThreshold {
		t.Errorf("similarity = %.2f, want >= %.2f — short minified bodies must still match", s, similarityThreshold)
	}
}

// Minified vs pretty-printed JSON of the same content must be similar.
func TestSimilarityMinifiedEqualsPretty(t *testing.T) {
	min := []byte(`{"user":"alice","role":"admin","team":"payments"}`)
	pretty := []byte("{\n  \"user\": \"alice\",\n  \"role\": \"admin\",\n  \"team\": \"payments\"\n}")
	if s := Similarity(min, pretty); s < 0.99 {
		t.Errorf("minified vs pretty similarity = %.2f, want ~1.0", s)
	}
}

func TestSimilarityDistinguishesDifferentUsers(t *testing.T) {
	// Two responses with GENUINELY different user data must be far apart —
	// otherwise falcon flags IDOR on every endpoint.
	alice := []byte(`{"user":"alice","email":"alice@example.com","role":"admin","notes":"she manages finance and HR"}`)
	bob := []byte(`{"user":"bob","email":"bob@example.com","role":"guest","notes":"he reads documentation only"}`)
	if s := Similarity(alice, bob); s >= similarityThreshold {
		t.Errorf("similarity = %.2f, want < %.2f — distinct user payloads look identical", s, similarityThreshold)
	}
}

// Same field NAMES but different VALUES (the owner-only /me case) must be
// distinguished, so a correctly-scoped per-user endpoint isn't flagged.
func TestSimilaritySeparatesSameShapeDifferentValues(t *testing.T) {
	a := []byte(`{"user":"alice","email":"alice@example.com","plan":"pro"}`)
	b := []byte(`{"user":"bob","email":"bob@example.com","plan":"pro"}`)
	if s := Similarity(a, b); s >= similarityThreshold {
		t.Errorf("similarity = %.2f, want < %.2f — different users' data must not match", s, similarityThreshold)
	}
}

func TestSimilarityEmptyBodies(t *testing.T) {
	if Similarity(nil, nil) != 1.0 {
		t.Error("two empty bodies should be identical (1.0)")
	}
	if Similarity(nil, []byte(`{"a":1}`)) != 0.0 {
		t.Error("empty vs non-empty should share nothing (0.0)")
	}
}
