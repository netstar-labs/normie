package expr

import (
	"reflect"
	"strings"
	"testing"
)

func TestGSBHosts(t *testing.T) {
	cases := []struct {
		host string
		isIP bool
		want []string
	}{
		{"a.b.c.d.e.f.g", false, []string{"a.b.c.d.e.f.g", "c.d.e.f.g", "d.e.f.g", "e.f.g", "f.g"}},
		{"a.b.c", false, []string{"a.b.c", "b.c"}},
		{"b.c", false, []string{"b.c"}},
		{"1.2.3.4", true, []string{"1.2.3.4"}},
	}
	for _, c := range cases {
		got := gsbHosts(c.host, c.isIP)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("gsbHosts(%q) = %v, want %v", c.host, got, c.want)
		}
		if len(got) > MaxHostSuffixes {
			t.Errorf("gsbHosts(%q) returned %d, cap is %d", c.host, len(got), MaxHostSuffixes)
		}
	}
}

func TestGSBPaths(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/1/2.html?param=1", []string{"/1/2.html?param=1", "/1/2.html", "/1/", "/"}},
		{"/1/2.html", []string{"/1/2.html", "/1/", "/"}},
		{"/", []string{"/"}},
		{"/a/b/c/d/e/f.html", []string{"/a/b/c/d/e/f.html", "/a/b/c/d/e/", "/a/b/c/d/", "/a/b/c/", "/a/b/"}},
	}
	for _, c := range cases {
		got := gsbPaths(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("gsbPaths(%q) = %v, want %v", c.in, got, c.want)
		}
		if len(got) > MaxPathPrefixes {
			t.Errorf("gsbPaths(%q) returned %d, cap is %d", c.in, len(got), MaxPathPrefixes)
		}
	}
}

func TestGSBExpandCap(t *testing.T) {
	got := GSB{}.Expand("a.b.c.d.e.f.g", "/1/2/3/4/5/6.html?q=1", false)
	if len(got) > 30 {
		t.Errorf("expansion produced %d expressions, GSB cap is 30", len(got))
	}
	if got[0] != "a.b.c.d.e.f.g/1/2/3/4/5/6.html?q=1" {
		t.Errorf("most specific expression first: got %q", got[0])
	}
}

// TestPSLBeatsGSB is the reason the strategy is an interface. GSB's fixed
// two-label suffix emits "co.uk", a public suffix that can never be a useful
// lookup key. The PSL strategy walks real boundaries and stops at the
// registrable domain.
func TestPSLBeatsGSB(t *testing.T) {
	const host = "a.b.example.co.uk"

	g := gsbHosts(host, false)
	found := false
	for _, h := range g {
		if h == "co.uk" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected GSB expansion to emit the bare public suffix co.uk")
	}

	// apex offset of "example.co.uk" within "a.b.example.co.uk"
	apex := strings.Index(host, "example.co.uk")
	p := PSL{Suffix: func(string) (int, bool) { return apex, true }}
	got := p.hosts(host, false)
	for _, h := range got {
		if h == "co.uk" || h == "uk" {
			t.Errorf("PSL expansion emitted bare public suffix %q: %v", h, got)
		}
	}
	if got[len(got)-1] != "example.co.uk" {
		t.Errorf("PSL expansion should end at the apex, got %v", got)
	}
}

func TestHashAndPrefix(t *testing.T) {
	h := HashExpr("example.com/")
	if len(h.Prefix(4)) != 4 {
		t.Error("prefix length")
	}
	if h.Uint32() == 0 {
		t.Error("suspicious zero prefix")
	}
	if len(h.String()) != 64 {
		t.Error("hex length")
	}

	ps := Prefixes(GSB{}, "a.b.c", "/1/2.html?q=1", false, 4)
	if len(ps) == 0 {
		t.Fatal("no prefixes")
	}
	seen := map[uint32]bool{}
	for _, p := range ps {
		if seen[p] {
			t.Error("Prefixes returned a duplicate")
		}
		seen[p] = true
	}
}

func TestExpanderNames(t *testing.T) {
	if (GSB{}).Name() != "gsb-expr/1" || (PSL{}).Name() != "netstar-expr/1" {
		t.Error("strategy names must be stable; they are persisted with hashes")
	}
}
