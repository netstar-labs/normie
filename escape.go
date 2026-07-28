package normie

// DefaultUnescapeDepth bounds the repeated-unescape loop. The Safe Browsing
// spec says to unescape "repeatedly ... until it has no more percent-escapes",
// which as written is unbounded and is therefore a denial-of-service surface:
// "%2525252525..." shrinks by one layer per pass. Sixteen passes clears every
// published test vector (the deepest needs seven) with margin; anything deeper
// is treated as hostile and rejected via ErrUnescapeDepth rather than
// truncated, so a crafted input cannot silently canonicalize to a prefix of
// itself.
const DefaultUnescapeDepth = 16

// unescapeRepeat percent-decodes s until a pass makes no change. done reports
// whether it converged inside depth passes.
func unescapeRepeat(s string, depth int) (out string, passes int, done bool) {
	out = s
	for passes = 0; passes < depth; passes++ {
		next, changed := unescapeOnce(out)
		if !changed {
			return next, passes, true
		}
		out = next
	}
	// One more probe: converged exactly at the limit is still convergence.
	if _, changed := unescapeOnce(out); !changed {
		return out, passes, true
	}
	return out, passes, false
}

// unescapeOnce decodes every valid %XX in one pass. Invalid escapes (a '%' not
// followed by two hex digits) are emitted literally, matching browser
// behaviour; they are re-escaped later by escapeGSB.
func unescapeOnce(s string) (string, bool) {
	i := indexPercent(s)
	if i < 0 {
		return s, false
	}
	b := make([]byte, 0, len(s))
	b = append(b, s[:i]...)
	changed := false
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b = append(b, h<<4|l)
				i += 3
				changed = true
				continue
			}
		}
		b = append(b, s[i])
		i++
	}
	if !changed {
		return s, false
	}
	return string(b), true
}

func indexPercent(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			return i
		}
	}
	return -1
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

const upperhex = "0123456789ABCDEF"

// needsEscapeGSB is the Safe Browsing escape set: every byte <= 0x20, every
// byte >= 0x7f, plus '#' and '%'. Note '%' is in the set, which is what makes
// the unescape/escape round trip idempotent — a literal percent that survived
// unescaping comes back out as %25.
func needsEscapeGSB(c byte) bool {
	return c <= 0x20 || c >= 0x7f || c == '#' || c == '%'
}

// escapeGSB percent-escapes s with uppercase hex.
func escapeGSB(s string) string {
	n := 0
	for i := 0; i < len(s); i++ {
		if needsEscapeGSB(s[i]) {
			n++
		}
	}
	if n == 0 {
		return s
	}
	b := make([]byte, 0, len(s)+2*n)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if needsEscapeGSB(c) {
			b = append(b, '%', upperhex[c>>4], upperhex[c&0x0f])
			continue
		}
		b = append(b, c)
	}
	return string(b)
}

// escapeRFC3986 is the storage-profile escape set. It is narrower than the GSB
// set: printable ASCII that is legal in the component is left alone so an
// analyst reads something recognizable, but controls, space, non-ASCII and '%'
// are still normalized to uppercase-hex triplets.
func escapeRFC3986(s string) string {
	n := 0
	for i := 0; i < len(s); i++ {
		if needsEscape3986(s[i]) {
			n++
		}
	}
	if n == 0 {
		return s
	}
	b := make([]byte, 0, len(s)+2*n)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if needsEscape3986(c) {
			b = append(b, '%', upperhex[c>>4], upperhex[c&0x0f])
			continue
		}
		b = append(b, c)
	}
	return string(b)
}

func needsEscape3986(c byte) bool {
	return c <= 0x20 || c >= 0x7f || c == '%' || c == '"' || c == '<' || c == '>' || c == '\\' || c == '^' || c == '`' || c == '{' || c == '|' || c == '}'
}
