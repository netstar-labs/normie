package normie

import (
	"net/netip"
	"strconv"
	"strings"
)

// IPClass classifies an address literal. It is metadata, not a verdict: an
// RFC1918 or loopback artifact is something a threat-intel pipeline wants to
// record and pivot on (internal C2, SSRF indicators), not silently discard.
type IPClass uint8

const (
	IPNone IPClass = iota
	IPPublic
	IPLoopback
	IPPrivate
	IPLinkLocal
	IPCGNAT
	IPMulticast
	IPUnspecified
	IPBroadcast
	IPReserved
)

var ipClassText = [...]string{
	IPNone:        "none",
	IPPublic:      "public",
	IPLoopback:    "loopback",
	IPPrivate:     "private",
	IPLinkLocal:   "link-local",
	IPCGNAT:       "cgnat",
	IPMulticast:   "multicast",
	IPUnspecified: "unspecified",
	IPBroadcast:   "broadcast",
	IPReserved:    "reserved",
}

func (c IPClass) String() string {
	if int(c) < len(ipClassText) && ipClassText[c] != "" {
		return ipClassText[c]
	}
	return "unknown"
}

// Routable reports whether the class is globally routable, i.e. an address a
// remote adversary could actually be reached at.
func (c IPClass) Routable() bool { return c == IPPublic }

// ParseIPv4 implements inet_aton semantics: one to four dot-separated parts,
// each independently radix-detected, with the final part absorbing all
// remaining octets.
//
// net/netip.ParseAddr accepts strict dotted-quad decimal only, which is why
// "http://2130706433/" (127.0.0.1), "http://0x7f.0.0.1/" and "http://127.1/"
// fall through host parsing and vanish from a pipeline built on it, while
// browsers resolve all three.
//
// Returns the address and true on success.
func ParseIPv4(s string) (netip.Addr, bool) {
	if s == "" || len(s) > 63 {
		return netip.Addr{}, false
	}

	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}

	vals := make([]uint64, 0, 4)
	for _, p := range parts {
		v, ok := parseIPv4Part(p)
		if !ok {
			return netip.Addr{}, false
		}
		vals = append(vals, v)
	}

	n := len(vals)
	// Every part but the last is a single octet.
	for i := 0; i < n-1; i++ {
		if vals[i] > 0xff {
			return netip.Addr{}, false
		}
	}
	// The last part absorbs the remaining 4-(n-1) octets.
	remaining := uint(4 - (n - 1))
	if remaining < 4 && vals[n-1] >= uint64(1)<<(8*remaining) {
		return netip.Addr{}, false
	}
	if remaining == 4 && vals[n-1] > 0xffffffff {
		return netip.Addr{}, false
	}

	var word uint32
	for i := 0; i < n-1; i++ {
		word |= uint32(vals[i]) << (8 * (3 - uint(i)))
	}
	word |= uint32(vals[n-1])

	return netip.AddrFrom4([4]byte{
		byte(word >> 24), byte(word >> 16), byte(word >> 8), byte(word),
	}), true
}

// parseIPv4Part decodes one component with C radix rules: "0x"/"0X" is hex, a
// leading "0" with more digits is octal, everything else is decimal. An empty
// component is invalid, which rejects "1..2" and a trailing dot.
func parseIPv4Part(p string) (uint64, bool) {
	// 12 is the longest meaningful component: a full 32-bit value in octal
	// ("037777777777") carries a leading zero plus eleven digits.
	if p == "" || len(p) > 12 {
		return 0, false
	}
	base := 10
	switch {
	case len(p) > 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'):
		base, p = 16, p[2:]
	case len(p) > 1 && p[0] == '0':
		base, p = 8, p[1:]
	}
	v, err := strconv.ParseUint(p, base, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ParseHostIP attempts to interpret host as an address literal, trying
// inet_aton first and then IPv6. bracketed indicates the host arrived in
// [...] form, which is required for IPv6 in a real URL but tolerated either
// way here because intel feeds are not well-formed.
func ParseHostIP(host string, bracketed bool) (netip.Addr, bool) {
	if host == "" {
		return netip.Addr{}, false
	}
	if !strings.ContainsAny(host, ":") {
		if a, ok := ParseIPv4(host); ok {
			return a, true
		}
		return netip.Addr{}, false
	}
	// Zone identifiers are stripped: they are host-local and never a useful
	// component of a global lookup key.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Classify buckets an address. Ordering matters: unspecified and loopback are
// checked before the broader private ranges.
func Classify(a netip.Addr) IPClass {
	if !a.IsValid() {
		return IPNone
	}
	a = a.Unmap()
	switch {
	case a.IsUnspecified():
		return IPUnspecified
	case a.IsLoopback():
		return IPLoopback
	case a.IsMulticast() || a.IsInterfaceLocalMulticast():
		return IPMulticast
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast():
		return IPLinkLocal
	}
	if a.Is4() {
		b := a.As4()
		switch {
		case b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255:
			return IPBroadcast
		case b[0] == 100 && b[1] >= 64 && b[1] <= 127:
			return IPCGNAT
		case b[0] == 192 && b[1] == 0 && b[2] == 2, // TEST-NET-1
			b[0] == 198 && b[1] == 51 && b[2] == 100, // TEST-NET-2
			b[0] == 203 && b[1] == 0 && b[2] == 113,  // TEST-NET-3
			b[0] == 192 && b[1] == 0 && b[2] == 0,    // IETF protocol assignments
			b[0] >= 240:                              // reserved / former class E
			return IPReserved
		case b[0] == 198 && (b[1] == 18 || b[1] == 19): // benchmarking
			return IPReserved
		}
	}
	if a.IsPrivate() {
		return IPPrivate
	}
	return IPPublic
}

// canonIPText renders an address in the form the canonical URL should carry:
// dotted decimal for v4, lowercase compressed and bracketed for v6.
func canonIPText(a netip.Addr) string {
	if a.Is4() {
		return a.String()
	}
	return "[" + a.String() + "]"
}
