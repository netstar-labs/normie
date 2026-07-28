package normie

import (
	"strings"
	"testing"
)

// gsbVectors are canonicalization cases from the published Safe Browsing
// specification.
//
// NOTE ON PROVENANCE: this table was written from the specification's stated
// rules and the widely reproduced example set; it was NOT machine-extracted
// from developers.google.com, because this build environment has no egress to
// that host. Before this library is trusted in production, re-derive the table
// from the live spec page and diff it against this one. Any disagreement is a
// bug in this file until proven otherwise.
var gsbVectors = []struct{ in, want string }{
	{"http://host/%25%32%35", "http://host/%25"},
	{"http://host/%25%32%35%25%32%35", "http://host/%25%25"},
	{"http://host/%2525252525252525", "http://host/%25"},
	{"http://host/asdf%25%32%35asd", "http://host/asdf%25asd"},
	{"http://host/%%%25%32%35asd%%", "http://host/%25%25%25asd%25%25"},
	{"http://www.google.com/", "http://www.google.com/"},
	{"http://168.188.99.26/.secure/www.ebay.com/", "http://168.188.99.26/.secure/www.ebay.com/"},
	{"http://3279880203/blah", "http://195.127.0.11/blah"},
	{"http://www.google.com/blah/..", "http://www.google.com/"},
	{"www.google.com/", "http://www.google.com/"},
	{"www.google.com", "http://www.google.com/"},
	{"http://www.evil.com/blah#frag", "http://www.evil.com/blah"},
	{"http://www.GOOgle.com/", "http://www.google.com/"},
	{"http://www.google.com.../", "http://www.google.com/"},
	// KNOWN DIVERGENCE — resolve against the live spec and Chromium before
	// trusting either behaviour. A trailing C0 control is trimmed here, because
	// the WHATWG URL Standard trims leading and trailing C0-and-space and that
	// is what actually determines where a browser navigates. A GSB feed built
	// on the literal spec steps would emit "%02" instead. If the differential
	// harness shows Chromium keeping the byte, change the code, not this note.
	{"http://www.google.com/foo\tbar\rbaz\x02", "http://www.google.com/foobarbaz"},
	{"http://www.google.com/q?", "http://www.google.com/q?"},
	{"http://www.google.com/q?r?", "http://www.google.com/q?r?"},
	{"http://www.google.com/q?r?s", "http://www.google.com/q?r?s"},
	{"http://evil.com/foo#bar#baz", "http://evil.com/foo"},
	{"http://evil.com/foo;", "http://evil.com/foo;"},
	{"http://evil.com/foo?bar;", "http://evil.com/foo?bar;"},
	{"http://notrailingslash.com", "http://notrailingslash.com/"},
	{"http://www.gotaport.com:1234/", "http://www.gotaport.com:1234/"},
	{"  http://www.google.com/  ", "http://www.google.com/"},
	{"http:// leadingspace.com/", "http://%20leadingspace.com/"},
	{"http://%20leadingspace.com/", "http://%20leadingspace.com/"},
	{"https://www.securesite.com/", "https://www.securesite.com/"},
	{"http://host.com/ab%23cd", "http://host.com/ab%23cd"},
	{"http://host.com//twoslashes?more//slashes", "http://host.com/twoslashes?more//slashes"},
	{"http://user:pass@host.com/path", "http://host.com/path"},
}

func TestGSBVectors(t *testing.T) {
	o := &Options{Profile: ProfileGSB}
	for _, v := range gsbVectors {
		r := Canon(v.in, o)
		if !r.Okay() {
			t.Errorf("Canon(%q) rejected: %v\n  trace: %v", v.in, r.Reason, r.Trace)
			continue
		}
		if r.Canonical != v.want {
			t.Errorf("Canon(%q)\n   got %q\n  want %q\n  trace: %v", v.in, r.Canonical, v.want, r.Trace)
		}
	}
}

// TestCanonMisattribution is the end-to-end form of the splitter regression.
func TestCanonMisattribution(t *testing.T) {
	cases := []struct{ raw, host string }{
		{`http://example.com\@evil.com/`, "example.com"},
		{`http://example.com#@evil.com`, "example.com"},
		{`http://a@b@evil.com/`, "evil.com"},
	}
	for _, c := range cases {
		r := Canon(c.raw, nil)
		if !r.Okay() {
			t.Fatalf("Canon(%q) rejected: %v", c.raw, r.Reason)
		}
		if r.Host != c.host {
			t.Errorf("Canon(%q).Host = %q, want %q", c.raw, r.Host, c.host)
		}
	}
}

// TestCanonBypasses covers inputs the predecessor rejected outright. A rejected
// input is a bypass at the system level: it never gets checked against the
// blocklist while the browser resolves it fine.
func TestCanonBypasses(t *testing.T) {
	cases := []struct{ raw, host string }{
		{"http://%65xample.com/", "example.com"},
		{"http://example%2ecom/", "example.com"},
		{"http://exa\tmple.com/", "example.com"},
		{"http://exam\rple.com/", "example.com"},
		{"http://2130706433/", "127.0.0.1"},
		{"http://0x7f.0.0.1/", "127.0.0.1"},
		{"http://0177.0.0.1/", "127.0.0.1"},
		{"http://127.1/", "127.0.0.1"},
	}
	for _, c := range cases {
		r := Canon(c.raw, nil)
		if !r.Okay() {
			t.Errorf("Canon(%q) rejected: %v", c.raw, r.Reason)
			continue
		}
		if r.Host != c.host {
			t.Errorf("Canon(%q).Host = %q, want %q", c.raw, r.Host, c.host)
		}
	}
}

// TestNonSpecialScheme pins that javascript: is surfaced, not silently
// attributed to the host it happens to contain.
func TestNonSpecialScheme(t *testing.T) {
	r := Canon("javascript://example.com/%0aalert(1)", nil)
	if r.Reason != ErrNonSpecial {
		t.Errorf("Reason = %v, want ErrNonSpecial", r.Reason)
	}
	if r.Okay() {
		t.Error("javascript: URL reported as okay")
	}
	if r2 := Canon("mailto:user@example.com", nil); r2.Reason != ErrOpaque {
		t.Errorf("mailto Reason = %v, want ErrOpaque", r2.Reason)
	}
}

// TestHostDelimiterInjection pins that an escape decoding into a structural
// delimiter is rejected rather than stored.
func TestHostDelimiterInjection(t *testing.T) {
	for _, raw := range []string{
		"http://example.com%2fpath",
		"http://example.com%5cpath",
		"http://example.com%3fq",
		"http://example.com%40evil.com",
	} {
		if r := Canon(raw, nil); r.Okay() {
			t.Errorf("Canon(%q) accepted with host %q, want rejection", raw, r.Host)
		}
	}
}

// TestUnescapeDepth pins that a nesting bomb is rejected, not truncated.
func TestUnescapeDepth(t *testing.T) {
	// Nested escapes: each pass peels exactly one layer, so this needs forty.
	deep := "http://host/%25" + strings.Repeat("25", 40)
	r := Canon(deep, &Options{UnescapeDepth: 4})
	if r.Reason != ErrUnescapeDepth {
		t.Errorf("Reason = %v, want ErrUnescapeDepth", r.Reason)
	}
}

// TestIdempotence is the property that makes a canonical form a usable key.
func TestIdempotence(t *testing.T) {
	inputs := make([]string, 0, len(gsbVectors)+8)
	for _, v := range gsbVectors {
		inputs = append(inputs, v.in)
	}
	inputs = append(inputs,
		`http://example.com\@evil.com/`,
		"http://0x7f.0.0.1/a/../b//c/./",
		"http://host.com//twoslashes?more//slashes",
		"HTTP://WWW.Example.COM:80/A/B?Q=1",
	)
	for _, in := range inputs {
		r1 := Canon(in, nil)
		if !r1.Okay() {
			continue
		}
		r2 := Canon(r1.Canonical, nil)
		if !r2.Okay() {
			t.Errorf("second pass rejected %q (from %q): %v", r1.Canonical, in, r2.Reason)
			continue
		}
		if r2.Canonical != r1.Canonical {
			t.Errorf("not idempotent for %q:\n  pass1 %q\n  pass2 %q", in, r1.Canonical, r2.Canonical)
		}
	}
}

func TestStorageProfile(t *testing.T) {
	r := Canon("HTTPS://User:Pw@WWW.Example.COM:443/A/./B?Q=1#frag", &Options{Profile: ProfileStorage})
	if !r.Okay() {
		t.Fatalf("rejected: %v", r.Reason)
	}
	// Storage keeps the fragment and path case, drops the default port, and
	// never retains credentials.
	if want := "https://www.example.com/A/B?Q=1#frag"; r.Canonical != want {
		t.Errorf("got %q, want %q", r.Canonical, want)
	}
	if strings.Contains(r.Canonical, "Pw") {
		t.Error("credentials retained in canonical form")
	}
	if !r.Trace.Has(StepDropUserinfo) {
		t.Error("userinfo drop not recorded in trace")
	}
	if r.Profile != ProfileStorage {
		t.Errorf("Profile = %q", r.Profile)
	}
}

func TestProfileDivergence(t *testing.T) {
	const raw = "http://example.com/a%2e%2e/b#frag"
	g := Canon(raw, &Options{Profile: ProfileGSB})
	s := Canon(raw, &Options{Profile: ProfileStorage})
	if g.Canonical == s.Canonical {
		t.Fatalf("profiles must diverge on this input, both gave %q", g.Canonical)
	}
	if strings.Contains(g.Canonical, "#") {
		t.Errorf("GSB profile retained fragment: %q", g.Canonical)
	}
	if !strings.Contains(s.Canonical, "#frag") {
		t.Errorf("storage profile dropped fragment: %q", s.Canonical)
	}
}

func TestIPClassification(t *testing.T) {
	cases := []struct {
		raw string
		cls IPClass
	}{
		{"http://8.8.8.8/", IPPublic},
		{"http://127.0.0.1/", IPLoopback},
		{"http://2130706433/", IPLoopback},
		{"http://192.168.1.1/", IPPrivate},
		{"http://10.0.0.1/", IPPrivate},
		{"http://100.64.0.1/", IPCGNAT},
		{"http://169.254.1.1/", IPLinkLocal},
		{"http://[2001:db8::1]/", IPPublic},
		{"http://[::1]/", IPLoopback},
	}
	for _, c := range cases {
		r := Canon(c.raw, nil)
		if !r.IP {
			t.Errorf("Canon(%q).IP = false", c.raw)
			continue
		}
		if r.IPClass != c.cls {
			t.Errorf("Canon(%q).IPClass = %v, want %v", c.raw, r.IPClass, c.cls)
		}
		// Non-routable literals must still canonicalize: an internal C2
		// address is an artifact worth recording, not an error.
		if !r.Okay() {
			t.Errorf("Canon(%q) rejected a %v literal: %v", c.raw, c.cls, r.Reason)
		}
	}
}

func TestTraceEvidence(t *testing.T) {
	r := Canon(`http://EXAMPLE.com\@x/%25%32%35`, nil)
	if !r.Okay() {
		t.Fatalf("rejected: %v", r.Reason)
	}
	if len(r.Trace) == 0 {
		t.Fatal("empty trace")
	}
	if !r.Trace.Has(StepFoldBackslash) {
		t.Error("backslash fold not recorded")
	}
	if !r.Trace.Has(StepHostLower) {
		t.Error("host lowercase not recorded")
	}
	if s := r.Trace.String(); s == "" || s == "(none)" {
		t.Error("trace did not render")
	}
}

func TestIDNAHook(t *testing.T) {
	// Without a hook, non-ASCII host bytes are escaped (spec-literal).
	r := Canon("http://ex\u00e4mple.com/", nil)
	if !r.Okay() {
		t.Fatalf("rejected: %v", r.Reason)
	}
	if !strings.Contains(r.Host, "%C3%A4") {
		t.Errorf("expected escaped host, got %q", r.Host)
	}

	// With a hook, the A-label wins.
	o := &Options{IDNA: func(h string) (string, error) {
		if h == "ex\u00e4mple.com" {
			return "xn--exmple-cua.com", nil
		}
		return h, nil
	}}
	r2 := Canon("http://ex\u00e4mple.com/", o)
	if !r2.Okay() {
		t.Fatalf("rejected: %v", r2.Reason)
	}
	if r2.Host != "xn--exmple-cua.com" {
		t.Errorf("Host = %q, want xn--exmple-cua.com", r2.Host)
	}
	if !r2.Trace.Has(StepIDNA) {
		t.Error("idna step not recorded")
	}
}

func TestHadNonASCII(t *testing.T) {
	// Non-ASCII host -> flagged (the targeted-migration selector), with or without
	// an IDNA hook.
	if r := Canon("http://exämple.com/", nil); !r.HadNonASCII {
		t.Error("HadNonASCII = false for an IDN host (no hook)")
	}
	hook := &Options{IDNA: func(h string) (string, error) { return "xn--exmple-cua.com", nil }}
	if r := Canon("http://exämple.com/", hook); !r.HadNonASCII {
		t.Error("HadNonASCII = false for an IDN host (with hook)")
	}
	// Pure-ASCII host and an IP literal -> not flagged.
	if r := Canon("http://example.com/", nil); r.HadNonASCII {
		t.Error("HadNonASCII = true for an ASCII host")
	}
	if r := Canon("http://192.168.0.1/", nil); r.HadNonASCII {
		t.Error("HadNonASCII = true for an IP literal")
	}
}

func TestCanonPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "/"},
		{"/", "/"},
		{"/a/b", "/a/b"},
		{"/a//b", "/a/b"},
		{"/a/./b", "/a/b"},
		{"/a/../b", "/b"},
		{"/a/b/..", "/a/"},
		{"/..", "/"},
		{"/../../..", "/"},
		{"/a/b/../../c/", "/c/"},
		{"//", "/"},
	}
	for _, c := range cases {
		if got := canonPath(c.in); got != c.want {
			t.Errorf("canonPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCollapseDots(t *testing.T) {
	cases := []struct{ in, want string }{
		{"www.google.com", "www.google.com"},
		{"www.google.com...", "www.google.com"},
		{"...www.google.com", "www.google.com"},
		{"www..google...com", "www.google.com"},
		{".", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := collapseDots(c.in); got != c.want {
			t.Errorf("collapseDots(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
