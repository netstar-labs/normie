package normie

import (
	"net/netip"
	"strconv"
	"strings"
)

// Default limits.
const (
	DefaultMaxURLLen  = 8192
	DefaultMaxHostLen = 253
	maxLabelLen       = 63
)

// Options configures a canonicalization run. The zero value is usable and
// behaves as ProfileGSB with the default limits.
type Options struct {
	// Profile selects the canonicalization contract. Defaults to ProfileGSB.
	Profile Profile

	// IDNA maps a Unicode host to its punycode A-label. Injected rather than
	// depended on, so this package stays dependency-free and the UTS-46
	// version stays pinned by the caller.
	//
	// When nil, non-ASCII host bytes are percent-escaped instead. That is what
	// the Safe Browsing spec literally prescribes, and it is byte-compatible
	// with feeds generated that way — but it is NOT what a browser does, since
	// Chrome runs IDNA in GURL before the Safe Browsing steps. Supply an IDNA
	// func for any pipeline that has to agree with browser resolution.
	IDNA func(host string) (string, error)

	// Refang controls whether defanged notation is rectified before parsing.
	// Threat-intel ingest is overwhelmingly defanged; browser-sourced input is
	// not. Off by default so canonicalization stays a pure function of the
	// bytes unless the caller opts in.
	Refang bool

	// Unwrap controls whether known redirector and mail-gateway wrappers are
	// unwrapped to their payload URL.
	Unwrap bool

	// DropPort removes the port from the canonical form. Off by default: the
	// port is excluded from host expressions regardless (see package expr), so
	// keeping it costs nothing and preserves evidence. Enable only to match a
	// specific upstream feed's convention.
	DropPort bool

	// UnescapeDepth bounds the repeated-unescape loop. Defaults to
	// DefaultUnescapeDepth.
	UnescapeDepth int

	MaxURLLen  int // defaults to DefaultMaxURLLen
	MaxHostLen int // defaults to DefaultMaxHostLen

	// AssumeScheme is applied to schemeless input. Defaults to "http".
	AssumeScheme string
}

func (o *Options) norm() Options {
	c := *o
	if c.Profile == "" {
		c.Profile = ProfileGSB
	}
	if c.UnescapeDepth <= 0 {
		c.UnescapeDepth = DefaultUnescapeDepth
	}
	if c.MaxURLLen <= 0 {
		c.MaxURLLen = DefaultMaxURLLen
	}
	if c.MaxHostLen <= 0 {
		c.MaxHostLen = DefaultMaxHostLen
	}
	if c.AssumeScheme == "" {
		c.AssumeScheme = "http"
	}
	return c
}

// Result is the outcome of a canonicalization run.
type Result struct {
	// Canonical is the assembled canonical URL under Profile. Empty when
	// Reason is not OK.
	Canonical string

	// Host is the canonical host on its own — the registrable input to
	// expression expansion and the artifact graph.
	Host string

	// PathQuery is the canonical path plus query, the second input to
	// expression expansion. Always begins with '/'.
	PathQuery string

	// Profile is the contract that produced Canonical. Persist it alongside
	// every derived hash; without it a stored prefix cannot be verified.
	Profile Profile

	// Reason reports success or the specific failure.
	Reason Reason

	// Trace is the ordered record of transformations applied.
	Trace Trace

	// URL is the split form after canonicalization.
	URL URL

	// IP and IPClass describe the host when it is an address literal.
	IP      bool
	IPClass IPClass
	Addr    netip.Addr

	// HadNonASCII reports whether the input host carried non-ASCII bytes (an IDN,
	// before UTS-46 mapping). Persist/index it: only non-ASCII hosts can change
	// under an IDNA re-vendor, so a pin bump recomputes just these rows instead of
	// the whole corpus (the targeted-migration selection in the idna drift model).
	HadNonASCII bool
}

// Okay reports whether the result is usable as a lookup key.
func (r Result) Okay() bool { return r.Reason == OK }

// Canon canonicalizes raw under opts. It never panics and never returns an
// error; failure is reported through Result.Reason, with Result.Trace showing
// how far it got.
func Canon(raw string, opts *Options) Result {
	var o Options
	if opts != nil {
		o = opts.norm()
	} else {
		o = (&Options{}).norm()
	}

	res := Result{Profile: o.Profile}

	if len(raw) > o.MaxURLLen {
		res.Reason = ErrURLTooLong
		return res
	}

	work := raw
	if o.Refang {
		if r := Refang(work); r != work {
			res.Trace.add(StepRefang, "url", work, r)
			work = r
		}
	}
	if o.Unwrap {
		if w, name, ok := Unwrap(work); ok {
			res.Trace.add(StepUnwrap, "url:"+name, work, w)
			work = w
		}
	}

	if trimmed := trimC0Space(work); trimmed != work {
		res.Trace.add(StepTrim, "url", work, trimmed)
		work = trimmed
	}
	if stripped := stripTabCRLF(work); stripped != work {
		res.Trace.add(StepStripControl, "url", work, stripped)
		work = stripped
	}
	if work == "" {
		res.Reason = ErrEmpty
		return res
	}
	if strings.IndexByte(work, '\\') >= 0 {
		res.Trace.add(StepFoldBackslash, "url", work, foldBackslash(work))
	}

	u := Split(work)

	if u.Opaque {
		res.URL = u
		res.Reason = ErrOpaque
		return res
	}
	if u.Scheme == "" {
		res.Trace.add(StepAssumeScheme, "scheme", "", o.AssumeScheme)
		u.Scheme = o.AssumeScheme
		u.Special = specialScheme[u.Scheme]
	}
	if !u.Special {
		// javascript://host/, custom://host/ — parsed, but not a navigable web
		// URL. Surfaced explicitly rather than silently canonicalized, which is
		// how "javascript://example.com/%0aalert(1)" ends up attributed to
		// example.com in naive pipelines.
		res.URL = u
		res.Host = u.Host
		res.Reason = ErrNonSpecial
		return res
	}
	if u.Host == "" {
		res.URL = u
		res.Reason = ErrNoHost
		return res
	}

	gsb := o.Profile == ProfileGSB

	// Fragment and userinfo are discarded by the GSB profile. Storage keeps the
	// fragment and records that credentials were present without retaining
	// them: a stored artifact should never carry a password.
	if u.HasFragment && gsb {
		res.Trace.add(StepDropFragment, "fragment", u.Fragment, "")
		u.Fragment, u.HasFragment = "", false
	}
	if u.HasUser {
		res.Trace.add(StepDropUserinfo, "userinfo", u.User, "")
		u.User = ""
	}
	// An unvalidated port is a hole straight into the canonical form: the
	// authority ends at '/', '?' or '#', so anything else — spaces, quotes,
	// control bytes — reaches the assembled URL untouched. Found by FuzzCanon
	// on the input "00X: 0", which produced the canonical "http://00x: 0/".
	// An empty port is dropped (browsers accept "http://h:/"); a non-numeric
	// one is a parse failure, as it is in a browser.
	if u.HasPort && u.Port == "" {
		u.HasPort = false
	}
	if u.HasPort && !validPort(u.Port) {
		res.URL, res.Reason = u, ErrBadPort
		return res
	}
	if u.HasPort && (o.DropPort || (!gsb && isDefaultPort(u.Scheme, u.Port))) {
		res.Trace.add(StepDropPort, "port", u.Port, "")
		u.Port, u.HasPort = "", false
	}

	// --- host -------------------------------------------------------------

	host := u.Host
	if gsb {
		un, _, done := unescapeRepeat(host, o.UnescapeDepth)
		if !done {
			res.URL, res.Reason = u, ErrUnescapeDepth
			return res
		}
		res.Trace.add(StepUnescape, "host", host, un)
		host = un
	} else {
		host = normalizePct(host)
	}

	if d := collapseDots(host); d != host {
		res.Trace.add(StepHostDots, "host", host, d)
		host = d
	}
	if l := strings.ToLower(host); l != host {
		res.Trace.add(StepHostLower, "host", host, l)
		host = l
	}
	if host == "" {
		res.URL, res.Reason = u, ErrNoHost
		return res
	}

	if addr, ok := ParseHostIP(host, u.Bracketed); ok {
		txt := canonIPText(addr)
		res.Trace.add(StepHostIP, "host", host, txt)
		res.IP, res.Addr, res.IPClass = true, addr, Classify(addr)
		host = txt
	} else {
		if !isASCII(host) {
			res.HadNonASCII = true
			if o.IDNA != nil {
				a, err := o.IDNA(host)
				if err != nil {
					res.URL, res.Reason = u, ErrIDNA
					return res
				}
				res.Trace.add(StepIDNA, "host", host, a)
				host = a
			}
			// With no IDNA hook the raw bytes fall through to the escape pass
			// below, which is what the Safe Browsing spec literally prescribes.
			// It diverges from browsers; see Options.IDNA.
		}
		if r := checkHost(host, o.MaxHostLen); r != OK {
			res.URL, res.Reason = u, r
			return res
		}
	}

	if !res.IP {
		var esc string
		if gsb {
			esc = escapeGSB(host)
		} else {
			esc = escapeRFC3986(host)
		}
		res.Trace.add(StepEscape, "host", host, esc)
		host = esc
	}
	u.Host = host

	// --- path and query ---------------------------------------------------

	path := u.Path
	if gsb {
		un, _, done := unescapeRepeat(path, o.UnescapeDepth)
		if !done {
			res.URL, res.Reason = u, ErrUnescapeDepth
			return res
		}
		res.Trace.add(StepUnescape, "path", path, un)
		path = un
	} else {
		path = normalizePct(path)
	}
	if p := canonPath(path); p != path {
		res.Trace.add(StepPathResolve, "path", path, p)
		path = p
	}

	query := u.Query
	if gsb {
		// The query is deliberately NOT dot-resolved or slash-collapsed; only
		// the path is. "http://h/a//b?c//d" keeps the double slash in c//d.
		un, _, done := unescapeRepeat(query, o.UnescapeDepth)
		if !done {
			res.URL, res.Reason = u, ErrUnescapeDepth
			return res
		}
		res.Trace.add(StepUnescape, "query", query, un)
		query = un
	} else {
		query = normalizePct(query)
	}

	if gsb {
		path, query = escapeGSB(path), escapeGSB(query)
	} else {
		path, query = escapeRFC3986(path), escapeRFC3986(query)
	}
	u.Path, u.Query = path, query

	// --- assemble ---------------------------------------------------------

	res.URL = u
	res.Host = hostForKey(host)
	res.PathQuery = path
	if u.HasQuery {
		res.PathQuery += "?" + query
	}
	res.Canonical = assemble(&u, gsb)

	if len(res.Canonical) > o.MaxURLLen {
		res.Reason = ErrURLTooLong
		res.Canonical = ""
		return res
	}

	res.Reason = OK
	return res
}

// hostForKey strips IPv6 brackets so the host is a bare key for expansion and
// graph storage.
func hostForKey(h string) string {
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		return h[1 : len(h)-1]
	}
	return h
}

func assemble(u *URL, gsb bool) string {
	var b strings.Builder
	b.Grow(len(u.Scheme) + len(u.Host) + len(u.Path) + len(u.Query) + 8)
	b.WriteString(u.Scheme)
	b.WriteString("://")
	b.WriteString(u.Host)
	if u.HasPort && u.Port != "" {
		b.WriteByte(':')
		b.WriteString(u.Port)
	}
	b.WriteString(u.Path)
	if u.HasQuery {
		b.WriteByte('?')
		b.WriteString(u.Query)
	}
	if !gsb && u.HasFragment {
		b.WriteByte('#')
		b.WriteString(u.Fragment)
	}
	return b.String()
}

// collapseDots removes leading and trailing dots and collapses runs of dots to
// a single dot, so "..www.google.com.../" yields "www.google.com".
func collapseDots(h string) string {
	if !strings.Contains(h, "..") && !strings.HasPrefix(h, ".") && !strings.HasSuffix(h, ".") {
		return h
	}
	b := make([]byte, 0, len(h))
	prevDot := true // leading dots are dropped
	for i := 0; i < len(h); i++ {
		if h[i] == '.' {
			if prevDot {
				continue
			}
			prevDot = true
			b = append(b, '.')
			continue
		}
		prevDot = false
		b = append(b, h[i])
	}
	for len(b) > 0 && b[len(b)-1] == '.' {
		b = b[:len(b)-1]
	}
	return string(b)
}

// canonPath resolves "." and ".." segments and collapses duplicate slashes,
// preserving a trailing slash. It never touches the query.
func canonPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	if !strings.Contains(p, "//") && !strings.Contains(p, "/.") {
		return p
	}
	trailing := strings.HasSuffix(p, "/") ||
		strings.HasSuffix(p, "/.") ||
		strings.HasSuffix(p, "/..")

	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		switch s {
		case "", ".":
			// duplicate slash or no-op segment
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
		}
	}
	res := "/" + strings.Join(out, "/")
	if trailing && !strings.HasSuffix(res, "/") {
		res += "/"
	}
	return res
}

// checkHost validates a canonical non-IP host. Structural delimiters surviving
// into the host mean an escape decoded into one — "example.com%2Fpath" becomes
// "example.com/path" — and must be rejected, not stored.
func checkHost(h string, maxLen int) Reason {
	if h == "" {
		return ErrNoHost
	}
	if len(h) > maxLen {
		return ErrHostTooLong
	}
	// Structural delimiters surviving into a host mean an escape decoded into
	// one. Space is deliberately NOT in this set: it is escaped, not rejected,
	// because "http:// leadingspace.com/" is a host a browser resolves.
	//
	// A single-label host is likewise not rejected here. It is unroutable on
	// the public internet but entirely real on an intranet, and an artifact a
	// pipeline should record and classify rather than drop.
	for i := 0; i < len(h); i++ {
		switch h[i] {
		case '/', '\\', '?', '#', '@', '[', ']', ':':
			return ErrBadHost
		}
	}
	// A host with no alphanumeric byte is not a name. Without this, a decoded
	// escape bomb canonicalizes to the host "%25" and enters the graph as a
	// real artifact.
	alnum := false
	for i := 0; i < len(h); i++ {
		if c := h[i]; isAlpha(c) || isDigit(c) {
			alnum = true
			break
		}
	}
	if !alnum {
		return ErrBadHost
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" {
			return ErrEmptyLabel
		}
		if len(label) > maxLabelLen {
			return ErrHostTooLong
		}
	}
	return OK
}

// validPort reports whether s is a bare decimal port in 1-65535. Leading
// zeros, signs, whitespace and any non-digit are rejected.
func validPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n >= 1 && n <= 65535
}

func isDefaultPort(scheme, port string) bool {
	switch scheme {
	case "http", "ws":
		return port == "80"
	case "https", "wss":
		return port == "443"
	case "ftp":
		return port == "21"
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// normalizePct is the storage-profile percent handling: decode only unreserved
// characters, uppercase every surviving triplet. Unlike the GSB profile it does
// NOT unescape repeatedly, because doing so changes what the URL means; storage
// must preserve the author's encoding.
func normalizePct(s string) string {
	if indexPercent(s) < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				c := h<<4 | l
				if isUnreserved(c) {
					b = append(b, c)
				} else {
					b = append(b, '%', upperhex[c>>4], upperhex[c&0x0f])
				}
				i += 3
				continue
			}
		}
		b = append(b, s[i])
		i++
	}
	return string(b)
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// PortNumber parses a canonical port, reporting 0 when absent or invalid.
func PortNumber(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0
	}
	return int(n)
}
