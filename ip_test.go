package normie

import "testing"

func TestParseIPv4(t *testing.T) {
	ok := []struct{ in, want string }{
		{"127.0.0.1", "127.0.0.1"},
		{"2130706433", "127.0.0.1"},
		{"0x7f.0.0.1", "127.0.0.1"},
		{"0177.0.0.1", "127.0.0.1"},
		{"127.1", "127.0.0.1"},
		{"127.0.1", "127.0.0.1"},
		{"0x7f000001", "127.0.0.1"},
		{"017700000001", "127.0.0.1"},
		{"3279880203", "195.127.0.11"},
		{"0.0.0.0", "0.0.0.0"},
		{"255.255.255.255", "255.255.255.255"},
		{"4294967295", "255.255.255.255"},
		{"0x0", "0.0.0.0"},
	}
	for _, c := range ok {
		a, got := ParseIPv4(c.in)
		if !got {
			t.Errorf("ParseIPv4(%q) failed", c.in)
			continue
		}
		if a.String() != c.want {
			t.Errorf("ParseIPv4(%q) = %v, want %v", c.in, a, c.want)
		}
	}

	bad := []string{
		"", "1.2.3.4.5", "256.1.1.1", "1.2.3.256", "4294967296",
		"1..2", "1.2.3.", ".1.2.3", "1.2.3.4a", "0x", "09.1.1.1",
		"example.com", "1.2.3.-1",
	}
	for _, c := range bad {
		if a, got := ParseIPv4(c); got {
			t.Errorf("ParseIPv4(%q) unexpectedly succeeded: %v", c, a)
		}
	}
}

func TestParseHostIPv6(t *testing.T) {
	cases := []struct{ in, want string }{
		{"::1", "::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:DB8::1", "2001:db8::1"},
		{"fe80::1%eth0", "fe80::1"},
		{"::ffff:127.0.0.1", "127.0.0.1"},
	}
	for _, c := range cases {
		a, ok := ParseHostIP(c.in, true)
		if !ok {
			t.Errorf("ParseHostIP(%q) failed", c.in)
			continue
		}
		if a.String() != c.want {
			t.Errorf("ParseHostIP(%q) = %v, want %v", c.in, a, c.want)
		}
	}
}

func TestClassRoutable(t *testing.T) {
	if !IPPublic.Routable() {
		t.Error("public must be routable")
	}
	for _, c := range []IPClass{IPLoopback, IPPrivate, IPCGNAT, IPLinkLocal, IPReserved, IPUnspecified} {
		if c.Routable() {
			t.Errorf("%v must not be routable", c)
		}
	}
}
