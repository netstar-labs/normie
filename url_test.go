package normie

import "testing"

// TestSplitMisattribution pins the two cases that produced a confidently wrong
// host in the byte-scanning predecessor. Both returned okay=true with the
// attacker's domain while a browser navigates to the victim's. These are the
// highest-severity failures a blocklist canonicalizer can have, because they
// are not fail-closed: they attribute an artifact to an innocent domain, or let
// an attacker evade a block by hiding their host in a path.
func TestSplitMisattribution(t *testing.T) {
	cases := []struct {
		raw, host, path string
	}{
		{`http://example.com\@evil.com/`, "example.com", "/@evil.com/"},
		{`http://example.com#@evil.com`, "example.com", ""},
		{`http://example.com\.evil.com/`, "example.com", "/.evil.com/"},
		{`http://a@b@evil.com/`, "evil.com", "/"},
		{`http:\\example.com\path`, "example.com", "/path"},
		{`http://example.com?@evil.com`, "example.com", ""},
	}
	for _, c := range cases {
		u := Split(c.raw)
		if u.Host != c.host {
			t.Errorf("Split(%q).Host = %q, want %q", c.raw, u.Host, c.host)
		}
		if u.Path != c.path {
			t.Errorf("Split(%q).Path = %q, want %q", c.raw, u.Path, c.path)
		}
	}
}

func TestSplitComponents(t *testing.T) {
	cases := []struct {
		raw                                   string
		scheme, user, host, port, path, query string
		frag                                  string
		special, opaque                       bool
	}{
		{
			raw:    "https://user:pw@www.Example.co.uk:8443/a/b?q=1#top",
			scheme: "https", user: "user:pw", host: "www.Example.co.uk", port: "8443",
			path: "/a/b", query: "q=1", frag: "top", special: true,
		},
		{raw: "example.com/path", scheme: "", host: "example.com", path: "/path"},
		{raw: "example.com:8080/x", scheme: "", host: "example.com", port: "8080", path: "/x"},
		{raw: "//example.com/x", host: "example.com", path: "/x"},
		{raw: "mailto:user@example.com", scheme: "mailto", path: "user@example.com", opaque: true},
		{raw: "data:text/html;base64,PHNjcmlwdD4=", scheme: "data", path: "text/html;base64,PHNjcmlwdD4=", opaque: true},
		{raw: "javascript://example.com/%0aalert(1)", scheme: "javascript", host: "example.com", path: "/%0aalert(1)"},
		{raw: "http://[2001:db8::1]:8080/x", scheme: "http", host: "2001:db8::1", port: "8080", path: "/x", special: true},
		{raw: "http://[2001:db8::1]/x", scheme: "http", host: "2001:db8::1", path: "/x", special: true},
		{raw: "  http://example.com/  ", scheme: "http", host: "example.com", path: "/", special: true},
		{raw: "http://exa\tmple.com/", scheme: "http", host: "example.com", path: "/", special: true},
		{raw: "http://exam\r\nple.com/", scheme: "http", host: "example.com", path: "/", special: true},
		{raw: "http://h/p#a?b", scheme: "http", host: "h", path: "/p", frag: "a?b", special: true},
	}
	for _, c := range cases {
		u := Split(c.raw)
		if u.Scheme != c.scheme || u.Host != c.host || u.Port != c.port ||
			u.Path != c.path || u.Query != c.query || u.Fragment != c.frag ||
			u.Special != c.special || u.Opaque != c.opaque {
			t.Errorf("Split(%q) =\n  %+v\nwant scheme=%q user=%q host=%q port=%q path=%q query=%q frag=%q special=%v opaque=%v",
				c.raw, u, c.scheme, c.user, c.host, c.port, c.path, c.query, c.frag, c.special, c.opaque)
		}
		if c.user != "" && u.User != c.user {
			t.Errorf("Split(%q).User = %q, want %q", c.raw, u.User, c.user)
		}
	}
}

func TestSchemeVsPort(t *testing.T) {
	if u := Split("example.com:8080/x"); u.Scheme != "" || u.Host != "example.com" || u.Port != "8080" {
		t.Errorf("bare host:port misparsed as scheme: %+v", u)
	}
	if u := Split("http://example.com:8080/x"); u.Scheme != "http" || u.Port != "8080" {
		t.Errorf("scheme+port misparsed: %+v", u)
	}
	if u := Split("custom:payload"); u.Scheme != "custom" || !u.Opaque {
		t.Errorf("opaque scheme misparsed: %+v", u)
	}
}
