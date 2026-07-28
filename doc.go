// Package normie canonicalizes untrusted URLs into stable, declared-profile
// lookup keys.
//
// The package answers one question: given a byte string that arrived from the
// wild, what will a browser actually resolve it to, and what is the canonical
// form under which we will store and look it up. It is deliberately split into
// two layers, because conflating them is how blocklists end up attributing an
// artifact to the wrong domain:
//
//	Split()  — a WHATWG-shaped URL grammar. Backslash folding, last-@ userinfo,
//	           C0 stripping, fragment-before-query termination. This layer
//	           reproduces browser *parsing*.
//
//	Canon()  — profile-specific normalization on top of the parse. This layer
//	           produces the lookup key.
//
// Two profiles ship. They are not interchangeable and every stored artifact
// must carry the profile identity that produced it:
//
//	ProfileGSB     — byte-compatible with the published Safe Browsing
//	                 canonicalization steps. Lossy: fragment and userinfo are
//	                 discarded. Use only to feed expression expansion.
//
//	ProfileStorage — RFC 3986 normalization that preserves scheme, userinfo
//	                 presence, port, and fragment. Use for the artifact graph,
//	                 pivoting, and anything an analyst reads.
//
// Zero external dependencies. Unicode host mapping (UTS-46) is an injected
// seam rather than a dependency; see Options.IDNA.
package normie

// Profile identifies a canonicalization contract. A hash or stored artifact is
// meaningless without one: a consumer cannot verify a prefix without knowing
// what produced it. Bump the version whenever observable output changes, and
// stamp it into feed metadata, API responses, and every persisted row.
type Profile string

const (
	// ProfileGSB is the Safe Browsing canonicalization contract.
	ProfileGSB Profile = "gsb-canon/1"

	// ProfileStorage is the lossless-ish normalization used for storage,
	// display, and pivoting.
	ProfileStorage Profile = "netstar-canon/1"
)

// Reason reports why a canonicalization attempt ended as it did. It replaces a
// bare ok/not-ok so a verdict can be defended: when a partner asks why a URL
// was attributed to a domain, Reason plus Trace is the answer.
type Reason uint8

const (
	OK               Reason = iota
	ErrEmpty                // input was empty after control-character stripping
	ErrNoHost               // no authority component could be located
	ErrBadHost              // host contained structural delimiters or illegal bytes
	ErrHostTooLong          // host exceeded 253 bytes
	ErrURLTooLong           // URL exceeded Options.MaxURLLen
	ErrUnescapeDepth        // percent-unescape did not converge within the bound
	ErrIDNA                 // host failed UTS-46 mapping
	ErrOpaque               // opaque scheme (mailto:, data:, javascript:) — no authority
	ErrNonSpecial           // scheme is not a navigable web scheme
	ErrEmptyLabel           // host contained an empty label after dot collapsing
	ErrBadPort              // port was present but not a number in 1-65535
)

var reasonText = [...]string{
	OK:               "ok",
	ErrEmpty:         "empty input",
	ErrNoHost:        "no host",
	ErrBadHost:       "malformed host",
	ErrHostTooLong:   "host too long",
	ErrURLTooLong:    "url too long",
	ErrUnescapeDepth: "unescape depth exceeded",
	ErrIDNA:          "idna mapping failed",
	ErrOpaque:        "opaque scheme",
	ErrNonSpecial:    "non-special scheme",
	ErrEmptyLabel:    "empty host label",
	ErrBadPort:       "malformed port",
}

func (r Reason) String() string {
	if int(r) < len(reasonText) && reasonText[r] != "" {
		return reasonText[r]
	}
	return "unknown"
}

// Okay reports whether the result is usable as a lookup key.
func (r Reason) Okay() bool { return r == OK }
