package normie

import "testing"

func TestRefang(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hxxp://example[.]com/a", "http://example.com/a"},
		{"hxxps://example(.)com/a", "https://example.com/a"},
		{"hXXp://evil[.]net", "http://evil.net"},
		{"example[dot]com", "example.com"},
		{"http://example\u3002com/", "http://example.com/"},
		{"http://example.com/", "http://example.com/"},
	}
	for _, c := range cases {
		if got := Refang(c.in); got != c.want {
			t.Errorf("Refang(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRefangViaCanon(t *testing.T) {
	r := Canon("hxxps://www.Evil[.]com/path", &Options{Refang: true})
	if !r.Okay() {
		t.Fatalf("rejected: %v", r.Reason)
	}
	if r.Host != "www.evil.com" {
		t.Errorf("Host = %q", r.Host)
	}
	if !r.Trace.Has(StepRefang) {
		t.Error("refang not recorded in trace")
	}
	// Refang is opt-in: without it the input must not silently canonicalize.
	if r2 := Canon("hxxps://www.Evil[.]com/path", nil); r2.Host == "www.evil.com" {
		t.Error("refang applied without opt-in")
	}
}

func TestUnwrap(t *testing.T) {
	cases := []struct{ in, want, wrapper string }{
		{
			"https://na01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Fa&data=x",
			"https://evil.com/a", WrapSafeLinks,
		},
		{
			"https://www.google.com/url?q=https%3A%2F%2Fevil.com%2Fb&sa=D",
			"https://evil.com/b", WrapGoogleRedir,
		},
		{
			"https://urldefense.proofpoint.com/v2/url?u=http-3A__evil.com_c&d=DwMFaQ",
			"http://evil.com/c", WrapProofpointV2,
		},
		{
			"https://urldefense.com/v3/__https://evil.com/d__;!!abc$",
			"https://evil.com/d", WrapProofpointV3,
		},
		{
			"https://example-com.cdn.ampproject.org/c/s/example.com/page",
			"https://example.com/page", WrapGoogleAMP,
		},
	}
	for _, c := range cases {
		got, w, ok := Unwrap(c.in)
		if !ok {
			t.Errorf("Unwrap(%q) failed", c.in)
			continue
		}
		if got != c.want || w != c.wrapper {
			t.Errorf("Unwrap(%q) = (%q, %q), want (%q, %q)", c.in, got, w, c.want, c.wrapper)
		}
	}
	if _, _, ok := Unwrap("https://example.com/plain"); ok {
		t.Error("unwrapped a non-wrapper URL")
	}
}

func TestUnwrapViaCanon(t *testing.T) {
	const raw = "https://www.google.com/url?q=https%3A%2F%2Fevil.com%2Fb"
	r := Canon(raw, &Options{Unwrap: true})
	if !r.Okay() {
		t.Fatalf("rejected: %v", r.Reason)
	}
	if r.Host != "evil.com" {
		t.Errorf("Host = %q, want evil.com", r.Host)
	}
	if !r.Trace.Has(StepUnwrap) {
		t.Error("unwrap not recorded")
	}
	// The wrapper is still recoverable by the caller from the original input.
	if plain := Canon(raw, nil); plain.Host != "www.google.com" {
		t.Errorf("without opt-in Host = %q, want www.google.com", plain.Host)
	}
}
