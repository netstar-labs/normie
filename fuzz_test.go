package normie

import (
	"strings"
	"testing"
)

var fuzzSeeds = []string{
	"http://example.com/",
	`http://example.com\@evil.com/`,
	"http://example.com#@evil.com",
	"http://%2525252525252525/",
	"http://0x7f.0.0.1/a/../b//c/./",
	"http://[2001:db8::1]:8080/x?y#z",
	"hxxp://evil[.]com/a",
	"http://host/%%%25%32%35asd%%",
	"mailto:a@b.com",
	"javascript://x/%0aalert(1)",
	"\x00\x01\x02",
	"http://" + strings.Repeat("a.", 200) + "com/",
	"://",
	"http://",
	"//",
	"@@@",
	"http://a@b@c@example.com/",
}

// FuzzCanon asserts the properties a canonical form must hold: it never
// panics, it converges in one pass, and it never emits a byte that would
// re-parse into a different host.
func FuzzCanon(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r := Canon(raw, nil)
		if !r.Okay() {
			return
		}

		// Idempotence. Without this a canonical form is not a key.
		r2 := Canon(r.Canonical, nil)
		if !r2.Okay() {
			t.Fatalf("pass 2 rejected %q (from %q): %v", r.Canonical, raw, r2.Reason)
		}
		if r2.Canonical != r.Canonical {
			t.Fatalf("not idempotent for %q:\n  1: %q\n  2: %q", raw, r.Canonical, r2.Canonical)
		}

		// Host stability: re-splitting the canonical form must recover the
		// same host. A failure here is the misattribution class of bug.
		if u := Split(r.Canonical); hostForKey(u.Host) != r.Host {
			t.Fatalf("host unstable for %q: canonical %q re-splits to %q, want %q",
				raw, r.Canonical, u.Host, r.Host)
		}

		// No structural delimiter may survive into a non-IP host.
		if !r.IP && strings.ContainsAny(r.Host, "/\\?#@[] ") {
			t.Fatalf("delimiter in host %q from %q", r.Host, raw)
		}

		// Canonical output is pure ASCII with no control bytes.
		for i := 0; i < len(r.Canonical); i++ {
			if c := r.Canonical[i]; c <= 0x20 || c >= 0x7f {
				t.Fatalf("unescaped byte %#02x at %d in %q (from %q)", c, i, r.Canonical, raw)
			}
		}
	})
}

// FuzzSplit asserts the splitter never panics and never invents bytes.
func FuzzSplit(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u := Split(raw)
		if len(u.Host) > len(raw) {
			t.Fatalf("host longer than input: %q from %q", u.Host, raw)
		}
	})
}

func FuzzParseIPv4(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1", "1.2.3.4.5", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, ok := ParseIPv4(s)
		if ok && !a.Is4() {
			t.Fatalf("ParseIPv4(%q) returned non-v4 %v", s, a)
		}
	})
}
