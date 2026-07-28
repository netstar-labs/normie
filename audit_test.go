package normie

import "testing"

// idempotent canonicalizes twice under p and returns (canonical, ok, stable).
func idempotent(raw string, p Profile) (canon string, ok, stable bool) {
	o := &Options{Profile: p}
	r1 := Canon(raw, o)
	if !r1.Okay() {
		return "", false, true
	}
	r2 := Canon(r1.Canonical, o)
	return r1.Canonical, true, r2.Okay() && r2.Canonical == r1.Canonical && len(r2.Canonical) <= len(r1.Canonical)
}

// TestBackslashIdempotentGSB is the regression for audit BUG-1: a decoded
// backslash (%5C) must re-escape to %5C, not land verbatim in the path and fold
// to '/' on the next parse — which made the GSB canonical non-idempotent (a
// blocklist miss).
func TestBackslashIdempotentGSB(t *testing.T) {
	for _, raw := range []string{
		`http://example.com/a%5Cb`,
		`http://example.com/foo%5C..%5Cbar`,
		`http://example.com/x?a%5Cb`,
	} {
		c, ok, stable := idempotent(raw, ProfileGSB)
		if !ok || !stable {
			t.Errorf("GSB not idempotent for %q (canonical %q)", raw, c)
		}
		if !contains(c, "%5C") {
			t.Errorf("GSB %q -> %q: backslash not re-escaped to %%5C", raw, c)
		}
	}
}

// TestStoragePercentIdempotent is the regression for audit BUG-2: the storage
// profile must not re-escape the '%' of a surviving triplet (%20 -> %2520 ->
// %252520 ...), which grew the canonical form and corrupted stored artifacts.
func TestStoragePercentIdempotent(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/a%20b",
		"http://example.com/p?x=%26y",
		"http://exam%2Fple.com/",
		"http://example.com/%7Euser", // unreserved: decodes to ~
	} {
		if _, ok, stable := idempotent(raw, ProfileStorage); !ok || !stable {
			c, _, _ := idempotent(raw, ProfileStorage)
			t.Errorf("storage not idempotent for %q (canonical %q)", raw, c)
		}
	}
}

// TestForbiddenHostBytesRejected is the regression for audit finding 4: a host
// carrying a WHATWG forbidden code point (control bytes or < > ^ | ") is not a
// host a browser resolves, so it must be rejected rather than admitted as a
// spurious artifact.
func TestForbiddenHostBytesRejected(t *testing.T) {
	for _, raw := range []string{
		"http://ex%3Cmple.com/",          // %3C = '<'
		"http://ex%3Emple.com/",          // '>'
		"http://ex%7Cmple.com/",          // '|'
		"http://ex%5Emple.com/",          // '^'
		"http://ex%22mple.com/",          // '"'
		"http://google.com%00.evil.com/", // NUL control
	} {
		if r := Canon(raw, nil); r.Okay() {
			t.Errorf("admitted forbidden-host input %q -> host %q", raw, r.Host)
		}
	}
}

// TestStorageHostTripletCase is the regression for the storage host triplet-case
// bug the both-profiles fuzz surfaced (seed "0\x80"): a surviving %XX escape in
// the host must keep stable (uppercase) hex across passes, not be lower-cased by
// host case-folding (%EF one pass, %ef the next).
func TestStorageHostTripletCase(t *testing.T) {
	for _, raw := range []string{"0\x80", "http://EXAM%2Fple\x80.com/", "http://ä%2Fb/"} {
		if _, ok, stable := idempotent(raw, ProfileStorage); ok && !stable {
			c, _, _ := idempotent(raw, ProfileStorage)
			t.Errorf("storage host not idempotent for %q (canonical %q)", raw, c)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
