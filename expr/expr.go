// Package expr expands a canonical host and path into the set of expressions a
// lookup must test, and reduces them to hash prefixes.
//
// Expansion is a strategy, not a constant. The Safe Browsing decomposition —
// a naive fixed label-count walk that ignores registrable-domain boundaries
// entirely — is required for compatibility with GSB-format feeds and clients,
// but it is not the best available scheme for a pipeline that has a correct
// Public Suffix List implementation. Both live here behind Expander, and the
// GSB one must never become the only path.
package expr

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Expander turns a canonical host and path+query into the expressions to test.
type Expander interface {
	// Expand returns expressions in most-specific-first order. host is a bare
	// canonical host (no brackets, no port); pathQuery begins with '/'.
	Expand(host, pathQuery string, isIP bool) []string

	// Name identifies the strategy. Persist it with any derived hash, next to
	// the canonicalization profile.
	Name() string
}

// DefaultPrefixLen is the truncation length for hash prefixes, in bytes.
const DefaultPrefixLen = 4

// MaxHostSuffixes and MaxPathPrefixes are the GSB caps.
const (
	MaxHostSuffixes = 5
	MaxPathPrefixes = 6
)

// GSB implements the Safe Browsing decomposition: up to five host suffixes by
// label count, crossed with up to six path prefixes, for at most thirty
// expressions.
type GSB struct{}

func (GSB) Name() string { return "gsb-expr/1" }

func (GSB) Expand(host, pathQuery string, isIP bool) []string {
	hosts := gsbHosts(host, isIP)
	paths := gsbPaths(pathQuery)
	out := make([]string, 0, len(hosts)*len(paths))
	for _, h := range hosts {
		for _, p := range paths {
			out = append(out, h+p)
		}
	}
	return out
}

// gsbHosts returns the exact host followed by suffixes formed from the last
// five, four, three and two labels. An address literal yields only itself.
func gsbHosts(host string, isIP bool) []string {
	if host == "" {
		return nil
	}
	if isIP {
		return []string{host}
	}
	labels := strings.Split(host, ".")
	n := len(labels)
	out := make([]string, 0, MaxHostSuffixes)
	out = append(out, host)
	for k := 5; k >= 2; k-- {
		if n > k {
			out = append(out, strings.Join(labels[n-k:], "."))
		}
	}
	return out
}

// gsbPaths returns path+query, path, and the four longest path prefixes ending
// in '/', including root.
func gsbPaths(pathQuery string) []string {
	path, query := pathQuery, ""
	if i := strings.IndexByte(pathQuery, '?'); i >= 0 {
		path, query = pathQuery[:i], pathQuery[i:]
	}
	if path == "" {
		path = "/"
	}

	out := make([]string, 0, MaxPathPrefixes)
	seen := make(map[string]struct{}, MaxPathPrefixes)
	add := func(s string) bool {
		if _, dup := seen[s]; dup {
			return true
		}
		seen[s] = struct{}{}
		out = append(out, s)
		return len(out) < MaxPathPrefixes
	}

	if query != "" {
		if !add(path + query) {
			return out
		}
	}
	if !add(path) {
		return out
	}

	// Prefixes ending in '/', longest first, at most four.
	cuts := make([]string, 0, 8)
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			cuts = append(cuts, path[:i+1])
		}
	}
	count := 0
	for _, c := range cuts {
		if count == 4 {
			break
		}
		if _, dup := seen[c]; dup {
			continue
		}
		count++
		if !add(c) {
			return out
		}
	}
	return out
}

// PSL implements a registrable-domain-aware decomposition. It walks real
// domain boundaries instead of a fixed label count, so "a.b.example.co.uk"
// yields example.co.uk rather than the meaningless co.uk that GSB's two-label
// suffix produces.
//
// Suffix must return the byte offset at which the registrable domain (eTLD+1)
// begins, and whether the host's public suffix was recognized. The signature
// matches what a PSL implementation like netstar-labs/sanitize already
// computes, so no list handling is duplicated here.
type PSL struct {
	Suffix func(host string) (apex int, ok bool)

	// MaxSubdomains caps how many subdomain levels are walked above the apex.
	// Zero means four.
	MaxSubdomains int
}

func (PSL) Name() string { return "netstar-expr/1" }

func (p PSL) Expand(host, pathQuery string, isIP bool) []string {
	hosts := p.hosts(host, isIP)
	paths := gsbPaths(pathQuery)
	out := make([]string, 0, len(hosts)*len(paths))
	for _, h := range hosts {
		for _, pq := range paths {
			out = append(out, h+pq)
		}
	}
	return out
}

func (p PSL) hosts(host string, isIP bool) []string {
	if host == "" {
		return nil
	}
	if isIP || p.Suffix == nil {
		return []string{host}
	}
	apex, ok := p.Suffix(host)
	if !ok || apex < 0 || apex >= len(host) {
		return []string{host}
	}
	maxSub := p.MaxSubdomains
	if maxSub <= 0 {
		maxSub = 4
	}

	out := make([]string, 0, maxSub+1)
	out = append(out, host)
	// Walk left-to-right dropping one leading label at a time, stopping at the
	// registrable domain. Never emit a bare public suffix.
	for i := 0; i < apex && len(out) <= maxSub; {
		d := strings.IndexByte(host[i:apex], '.')
		if d < 0 {
			break
		}
		i += d + 1
		if i >= apex {
			break
		}
		out = append(out, host[i:])
	}
	if apexHost := host[apex:]; apexHost != host {
		out = append(out, apexHost)
	}
	return out
}

// Hash is a full SHA-256 of an expression.
type Hash [sha256.Size]byte

// String renders the hash as lowercase hex.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// Prefix returns the first n bytes of the hash.
func (h Hash) Prefix(n int) []byte {
	if n <= 0 || n > sha256.Size {
		n = DefaultPrefixLen
	}
	return h[:n]
}

// Uint32 returns the first four bytes as a big-endian uint32, the form a
// sorted prefix store indexes on.
func (h Hash) Uint32() uint32 {
	return uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
}

// HashExpr hashes a single expression.
func HashExpr(e string) Hash { return sha256.Sum256([]byte(e)) }

// Hashes expands and hashes in one call, preserving expansion order.
func Hashes(e Expander, host, pathQuery string, isIP bool) []Hash {
	exprs := e.Expand(host, pathQuery, isIP)
	out := make([]Hash, len(exprs))
	for i, s := range exprs {
		out[i] = HashExpr(s)
	}
	return out
}

// Prefixes expands, hashes, and truncates, deduplicating collisions while
// preserving first-seen order.
func Prefixes(e Expander, host, pathQuery string, isIP bool, n int) []uint32 {
	if n <= 0 {
		n = DefaultPrefixLen
	}
	hs := Hashes(e, host, pathQuery, isIP)
	out := make([]uint32, 0, len(hs))
	seen := make(map[uint32]struct{}, len(hs))
	for _, h := range hs {
		v := h.Uint32()
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
