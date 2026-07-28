package normie

import (
	"strings"
)

// refangPairs are ordered: longer and more specific forms first, so "[://]"
// is consumed before "[:]" can match its interior.
//
// Unicode dot substitutes are handled here rather than left to UTS-46 because
// refanging must happen before parsing, and the splitter is byte-oriented.
var refangPairs = []struct{ from, to string }{
	{"[://]", "://"},
	{"[:\\/\\/]", "://"},
	{"(://)", "://"},
	{"hxxps", "https"},
	{"hxxp", "http"},
	{"hXXps", "https"},
	{"hXXp", "http"},
	{"h**ps", "https"},
	{"h**p", "http"},
	{"[dot]", "."},
	{"(dot)", "."},
	{"{dot}", "."},
	{" dot ", "."},
	{"[.]", "."},
	{"(.)", "."},
	{"{.}", "."},
	{"\\.", "."},
	{"[at]", "@"},
	{"(at)", "@"},
	{"[@]", "@"},
	{"[:]", ":"},
	{"\u3002", "."}, // ideographic full stop
	{"\uFF0E", "."}, // fullwidth full stop
	{"\uFF61", "."}, // halfwidth ideographic full stop
}

// Refang rectifies defanged indicator notation to a parseable URL. Threat-intel
// ingest is overwhelmingly defanged, and a canonicalizer that rejects "hxxp"
// simply drops most of its input.
//
// Refanging is deliberately separate from Canon and off by default. It is a
// lossy guess about intent, not a normalization: "example[.]com" is
// unambiguous, but a path segment that legitimately contains "[.]" would be
// rewritten. Callers that enable it get a StepRefang entry in the trace so the
// guess is visible.
func Refang(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, p := range refangPairs {
		if strings.Contains(out, p.from) {
			out = strings.ReplaceAll(out, p.from, p.to)
		}
	}
	// Case-insensitive scheme defangs that survive the literal pass.
	if len(out) >= 4 {
		lower := strings.ToLower(out[:min(6, len(out))])
		switch {
		case strings.HasPrefix(lower, "hxxps"):
			out = "https" + out[5:]
		case strings.HasPrefix(lower, "hxxp"):
			out = "http" + out[4:]
		}
	}
	return out
}

// Wrapper names reported by Unwrap.
const (
	WrapProofpointV2 = "proofpoint-v2"
	WrapProofpointV3 = "proofpoint-v3"
	WrapSafeLinks    = "safelinks"
	WrapGoogleRedir  = "google-redirect"
	WrapGoogleAMP    = "google-amp"
)

// Unwrap extracts the payload URL from a known mail-gateway or redirector
// wrapper, reporting which wrapper matched.
//
// Callers should record BOTH the wrapper and the payload as related artifacts.
// Discarding the wrapper loses the delivery evidence; discarding the payload
// loses the target. Unwrap returns only the payload, so the caller keeps the
// original.
func Unwrap(raw string) (payload, wrapper string, ok bool) {
	u := Split(raw)
	if u.Host == "" {
		return "", "", false
	}
	host := strings.ToLower(u.Host)

	switch {
	case strings.Contains(host, "urldefense.proofpoint.com"), strings.Contains(host, "urldefense.com"):
		if v, ok := queryParam(u.Query, "u"); ok {
			return proofpointV2Decode(v), WrapProofpointV2, true
		}
		if p := proofpointV3(u.Path); p != "" {
			return p, WrapProofpointV3, true
		}

	case strings.HasSuffix(host, ".safelinks.protection.outlook.com"):
		if v, ok := queryParam(u.Query, "url"); ok {
			if d, err := pctDecode(v); err == nil {
				return d, WrapSafeLinks, true
			}
		}

	case host == "www.google.com" || host == "google.com" || strings.HasPrefix(host, "www.google."):
		if u.Path == "/url" {
			for _, key := range []string{"q", "url"} {
				if v, ok := queryParam(u.Query, key); ok {
					if d, err := pctDecode(v); err == nil {
						return d, WrapGoogleRedir, true
					}
				}
			}
		}

	case strings.HasSuffix(host, ".cdn.ampproject.org"):
		// host form: example-com.cdn.ampproject.org/c/s/example.com/path
		p := strings.TrimPrefix(u.Path, "/")
		p = strings.TrimPrefix(p, "c/")
		if strings.HasPrefix(p, "s/") {
			return "https://" + p[2:], WrapGoogleAMP, true
		}
		if p != "" {
			return "http://" + p, WrapGoogleAMP, true
		}
	}

	return "", "", false
}

// proofpointV3 pulls the payload out of a v3 path:
// /v3/__https://example.com/path__;base64!!token
func proofpointV3(path string) string {
	i := strings.Index(path, "__")
	if i < 0 {
		return ""
	}
	rest := path[i+2:]
	j := strings.Index(rest, "__;")
	if j < 0 {
		if j = strings.Index(rest, "__"); j < 0 {
			return ""
		}
	}
	return rest[:j]
}

// proofpointV2Decode reverses the v2 substitution alphabet, then percent
// decodes. v2 replaces '-' with '%' and '_' with '/'.
func proofpointV2Decode(s string) string {
	s = strings.ReplaceAll(s, "-", "%")
	s = strings.ReplaceAll(s, "_", "/")
	if d, err := pctDecode(s); err == nil {
		return d
	}
	return s
}

// queryParam finds the first value for key in a raw query string.
func queryParam(query, key string) (string, bool) {
	for query != "" {
		var pair string
		if i := strings.IndexAny(query, "&;"); i >= 0 {
			pair, query = query[:i], query[i+1:]
		} else {
			pair, query = query, ""
		}
		if pair == "" {
			continue
		}
		k, v := pair, ""
		if i := strings.IndexByte(pair, '='); i >= 0 {
			k, v = pair[:i], pair[i+1:]
		}
		if k == key {
			return v, true
		}
	}
	return "", false
}

// pctDecode does a single percent-decode pass, also converting '+' to space,
// as a query value would be encoded.
func pctDecode(s string) (string, error) {
	s = strings.ReplaceAll(s, "+", " ")
	out, _ := unescapeOnce(s)
	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
