package normie

import "strings"

// URL is a split, not-yet-canonical URL. Fields hold raw bytes exactly as they
// appeared, minus the structural delimiters that separated them.
type URL struct {
	Scheme   string // lowercased, without ':'; "" when the input was schemeless
	User     string // raw userinfo, without the trailing '@'
	Host     string // without brackets for IPv6 literals
	Port     string // as text, without ':'
	Path     string // including the leading '/', "" when absent
	Query    string // without the leading '?'
	Fragment string // without the leading '#'

	HasUser     bool
	HasPort     bool
	HasQuery    bool
	HasFragment bool
	HasAuthy    bool // an authority component was present
	Special     bool // http, https, ws, wss, ftp, file
	Opaque      bool // scheme present, no authority (mailto:, data:, javascript:x)
	Bracketed   bool // host arrived as [v6]
}

// specialScheme is the WHATWG special-scheme set. Backslash folding and
// authority parsing only apply to these; everything else is treated as opaque
// unless it carries an explicit "//".
var specialScheme = map[string]bool{
	"http":  true,
	"https": true,
	"ws":    true,
	"wss":   true,
	"ftp":   true,
	"file":  true,
}

// IsSpecial reports whether s names a navigable web scheme.
func IsSpecial(s string) bool { return specialScheme[s] }

// Split parses raw into components using browser-shaped rules. It never fails;
// a nonsensical input yields a URL with an empty Host, which callers detect via
// Canon's Reason.
//
// The rules that matter, and that a naive IndexByte scan gets wrong:
//
//   - Leading and trailing C0 controls and spaces are trimmed; embedded TAB, CR
//     and LF are removed outright, anywhere in the string.
//   - For special schemes every backslash folds to a forward slash *before* any
//     delimiter search. Without this, "http://example.com\@evil.com/" parses to
//     host evil.com while the browser navigates to example.com.
//   - Userinfo is delimited by the *last* '@' inside the authority, not the
//     first. "http://a@b@evil.com/" is host evil.com.
//   - The authority ends at the first of '/', '?' or '#'. Without '#' in that
//     set, "http://example.com#@evil.com" parses to host evil.com while the
//     browser navigates to example.com.
//   - A colon whose right-hand side is all digits is a port, not a scheme, so
//     "example.com:8080/x" keeps its host.
func Split(raw string) URL {
	var u URL

	s := trimC0Space(raw)
	s = stripTabCRLF(s)
	if s == "" {
		return u
	}

	// Scheme. Only accept when what follows is not a bare port, otherwise
	// "example.com:8080/x" would parse as scheme "example.com".
	if i := schemeEnd(s); i > 0 && !portFollows(s[i+1:]) {
		u.Scheme = strings.ToLower(s[:i])
		s = s[i+1:]
	}
	u.Special = specialScheme[u.Scheme]

	switch {
	case u.Special || u.Scheme == "":
		// Special and schemeless inputs always have an authority. Fold
		// backslashes first so they cannot be mistaken for path or userinfo
		// delimiters, then eat any run of leading slashes.
		s = foldBackslash(s)
		s = strings.TrimLeft(s, "/")
		u.HasAuthy = true

	case strings.HasPrefix(s, "//"):
		// Non-special but hierarchical: javascript://host/..., custom://host/...
		// Parsed for the host so callers can see it, but Special stays false so
		// the scheme can be rejected rather than silently treated as navigable.
		s = s[2:]
		u.HasAuthy = true

	default:
		// mailto:, data:, javascript:alert(1) — no authority at all.
		u.Opaque = true
		u.Path = s
		return u
	}

	// The authority ends at the first structural delimiter. '#' belongs in this
	// set; omitting it is the fragment misattribution bug.
	end := len(s)
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '/' || c == '?' || c == '#' {
			end = i
			break
		}
	}
	auth, rest := s[:end], s[end:]

	// Userinfo: last '@' wins.
	if i := strings.LastIndexByte(auth, '@'); i >= 0 {
		u.User, u.HasUser = auth[:i], true
		auth = auth[i+1:]
	}

	u.Host, u.Port, u.HasPort, u.Bracketed = splitHostPort(auth)

	// Fragment is located before query: "http://h/p#a?b" has fragment "a?b".
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		u.Fragment, u.HasFragment = rest[i+1:], true
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		u.Query, u.HasQuery = rest[i+1:], true
		rest = rest[:i]
	}
	u.Path = rest

	return u
}

// splitHostPort separates an authority remainder into host and port, handling
// bracketed IPv6, bare (unbracketed) IPv6 literals, and ordinary host:port.
func splitHostPort(auth string) (host, port string, hasPort, bracketed bool) {
	if strings.HasPrefix(auth, "[") {
		bracketed = true
		if j := strings.IndexByte(auth, ']'); j >= 0 {
			host = auth[1:j]
			if len(auth) > j+1 && auth[j+1] == ':' {
				port, hasPort = auth[j+2:], true
			}
			return
		}
		return auth[1:], "", false, true
	}
	c := strings.LastIndexByte(auth, ':')
	if c < 0 {
		return auth, "", false, false
	}
	if strings.IndexByte(auth, ':') != c {
		// More than one colon and no brackets: a bare IPv6 literal. Keep intact.
		return auth, "", false, false
	}
	return auth[:c], auth[c+1:], true, false
}

// schemeEnd returns the index of the ':' terminating a valid RFC 3986 scheme,
// or -1. scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
func schemeEnd(s string) int {
	if len(s) == 0 || !isAlpha(s[0]) {
		return -1
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case isAlpha(c) || isDigit(c) || c == '+' || c == '-' || c == '.':
			continue
		case c == ':':
			return i
		default:
			return -1
		}
	}
	return -1
}

// portFollows reports whether s begins with a run of digits terminated by a
// structural delimiter or end of string, i.e. the preceding colon was a port
// separator rather than a scheme terminator.
func portFollows(s string) bool {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	if i == 0 {
		return false
	}
	if i == len(s) {
		return true
	}
	switch s[i] {
	case '/', '?', '#', '\\':
		return true
	}
	return false
}

// foldBackslash converts every backslash to a forward slash, as browsers do for
// special schemes before parsing.
func foldBackslash(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] == '\\' {
			b[i] = '/'
		}
	}
	return string(b)
}

// stripTabCRLF removes every TAB, CR and LF. They are deleted, not replaced
// with a space: "exa\tmple.com" is example.com to a browser.
func stripTabCRLF(s string) string {
	if !strings.ContainsAny(s, "\t\r\n") {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\t', '\r', '\n':
		default:
			b = append(b, s[i])
		}
	}
	return string(b)
}

// trimC0Space trims leading and trailing C0 control characters and spaces.
func trimC0Space(s string) string {
	i, j := 0, len(s)
	for i < j && s[i] <= 0x20 {
		i++
	}
	for j > i && s[j-1] <= 0x20 {
		j--
	}
	return s[i:j]
}

func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
