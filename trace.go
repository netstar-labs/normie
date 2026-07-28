package normie

import "strings"

// StepKind names a single observable transformation.
type StepKind uint8

const (
	StepTrim StepKind = iota
	StepStripControl
	StepFoldBackslash
	StepRefang
	StepUnwrap
	StepAssumeScheme
	StepDropFragment
	StepDropUserinfo
	StepDropPort
	StepUnescape
	StepHostDots
	StepHostLower
	StepHostIP
	StepIDNA
	StepPathResolve
	StepEscape
	StepTruncate
)

var stepText = [...]string{
	StepTrim:          "trim",
	StepStripControl:  "strip-control",
	StepFoldBackslash: "fold-backslash",
	StepRefang:        "refang",
	StepUnwrap:        "unwrap",
	StepAssumeScheme:  "assume-scheme",
	StepDropFragment:  "drop-fragment",
	StepDropUserinfo:  "drop-userinfo",
	StepDropPort:      "drop-port",
	StepUnescape:      "unescape",
	StepHostDots:      "host-dots",
	StepHostLower:     "host-lower",
	StepHostIP:        "host-ip",
	StepIDNA:          "idna",
	StepPathResolve:   "path-resolve",
	StepEscape:        "escape",
	StepTruncate:      "truncate",
}

func (k StepKind) String() string {
	if int(k) < len(stepText) && stepText[k] != "" {
		return stepText[k]
	}
	return "unknown"
}

// Step is one recorded transformation. Before and After are the affected
// component only, not the whole URL, so a trace stays readable.
type Step struct {
	Kind   StepKind
	Field  string // "url", "host", "path", "query", "scheme"
	Before string
	After  string
}

// Trace is an ordered record of every transformation applied. It is the
// evidence behind a verdict: when a consumer disputes an attribution, the
// trace shows exactly which rewrite produced the stored host.
type Trace []Step

func (t *Trace) add(kind StepKind, field, before, after string) {
	if before == after {
		return
	}
	*t = append(*t, Step{Kind: kind, Field: field, Before: before, After: after})
}

// Has reports whether any step of the given kind was recorded.
func (t Trace) Has(kind StepKind) bool {
	for _, s := range t {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

// String renders the trace as a compact single line for logs.
func (t Trace) String() string {
	if len(t) == 0 {
		return "(none)"
	}
	var b strings.Builder
	for i, s := range t {
		if i > 0 {
			b.WriteString(" ; ")
		}
		b.WriteString(s.Kind.String())
		b.WriteByte('(')
		b.WriteString(s.Field)
		b.WriteString("): ")
		b.WriteString(s.Before)
		b.WriteString(" -> ")
		b.WriteString(s.After)
	}
	return b.String()
}
