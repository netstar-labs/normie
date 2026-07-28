package normie

import "testing"

var benchInputs = []string{
	"http://www.example.com/",
	"https://www.example.co.uk:8443/a/b/c.html?q=1&r=2",
	"http://host/%25%32%35/asdf/../x//y",
	"http://0x7f.0.0.1/a",
	`http://example.com\@evil.com/path`,
}

var sinkResult Result

func BenchmarkCanonSimple(b *testing.B) {
	const in = "http://www.example.com/"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkResult = Canon(in, nil)
	}
}

func BenchmarkCanonMixed(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkResult = Canon(benchInputs[i%len(benchInputs)], nil)
	}
}

func BenchmarkCanonEscapeHeavy(b *testing.B) {
	const in = "http://host/%25%32%35/asdf/../x//y?a=%25%32%35"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkResult = Canon(in, nil)
	}
}

var sinkURL URL

func BenchmarkSplit(b *testing.B) {
	const in = "https://user:pw@www.example.co.uk:8443/a/b/c.html?q=1#frag"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkURL = Split(in)
	}
}

func BenchmarkParseIPv4(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseIPv4("0x7f.0.0.1")
	}
}
