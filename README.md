# normie

Canonicalize untrusted URLs into stable, **declared-profile** lookup keys.

Zero external dependencies. Unicode host mapping is an injected seam, not a
dependency.

```
raw ──▶ Refang ──▶ Unwrap ──▶ Split ──▶ Canon ──▶ expr.Expand ──▶ SHA-256 prefixes
        (opt-in)   (opt-in)   grammar   profile   strategy
```

## Documentation

- **Start here** — [docs/introduction.md](docs/introduction.md) ·
  [docs/executive-summary.md](docs/executive-summary.md)
- **Deep dive** — [docs/architecture.md](docs/architecture.md)
- **Operations** — [docs/userguide.md](docs/userguide.md) ·
  [PROFILES.md](PROFILES.md) (version stamp + migration)
- **Examples** — [example/README.md](example/README.md)

## Why this exists

A canonicalizer built on `IndexByte` scanning does not implement a URL grammar,
it implements a guess. Two inputs that a browser resolves to `example.com`:

| input | naive byte-scan | browser | normie |
| --- | --- | --- | --- |
| `http://example.com\@evil.com/` | `evil.com` ✗ | `example.com` | `example.com` ✓ |
| `http://example.com#@evil.com`  | `evil.com` ✗ | `example.com` | `example.com` ✓ |

Both were `Okay = true` in the predecessor. That is the worst failure mode a
blocklist can have — it is not fail-closed. An attacker either seeds your
corpus with an attribution against an innocent domain, or evades a block on
their own by hiding their host where the parser reads a path.

A second class fails closed at the function but **fails open at the system**: a
rejected input is one that never gets checked against the blocklist while the
browser resolves it fine.

| input | naive | browser | normie |
| --- | --- | --- | --- |
| `http://%65xample.com/` | rejected | `example.com` | `example.com` ✓ |
| `http://exa⇥mple.com/` | rejected | `example.com` | `example.com` ✓ |
| `http://2130706433/` | rejected | `127.0.0.1` | `127.0.0.1` ✓ |
| `http://0x7f.0.0.1/` | rejected | `127.0.0.1` | `127.0.0.1` ✓ |
| `http://127.1/` | rejected | `127.0.0.1` | `127.0.0.1` ✓ |

`net/netip.ParseAddr` implements strict dotted-quad only, which is why the last
three vanish from any pipeline built on it. `ParseIPv4` here implements full
`inet_aton` radix rules.

## Two profiles, never one

Conflating the lookup form with the storage form is how the fragment and
userinfo end up in a hash, or how a stored artifact ends up carrying a
password. They are separate contracts and every persisted row carries the
identity of the one that produced it.

| | `ProfileGSB` (`gsb-canon/1`) | `ProfileStorage` (`netstar-canon/1`) |
| --- | --- | --- |
| purpose | lookup keys only | artifact graph, pivoting, analyst UI |
| fragment | dropped | preserved |
| userinfo | dropped | dropped, presence recorded |
| default port | preserved | dropped |
| percent handling | unescape repeatedly, then re-escape | RFC 3986 normalize only |
| escape set | `≤0x20`, `≥0x7f`, `#`, `%` | RFC 3986 |

**Stamp the profile on everything.** A hash prefix is unverifiable without it,
and the first time you fix a canonicalization bug, every stored hash is
silently stale with no way to identify which rows to recompute.

## Usage

```go
r := normie.Canon(raw, &normie.Options{
    Profile: normie.ProfileGSB,
    Refang:  true,  // hxxp://, [.], [dot] — off by default
    Unwrap:  true,  // SafeLinks, URLDefense, AMP — off by default
    IDNA:    idna.ToASCIIErr, // github.com/netstar-labs/idna — pinned UTS-46, matches func(host)(string,error)
})
if !r.Okay() {
    log.Printf("%s: %v (%v)", raw, r.Reason, r.Trace)
    return
}

hashes := expr.Hashes(expr.GSB{}, r.Host, r.PathQuery, r.IP)
```

`Result.Trace` is the evidence behind a verdict. When a consumer disputes an
attribution, the trace shows exactly which rewrite produced the stored host:

```
$ printf 'hxxps://www.Example[.]com/a/../b\n' | REFANG=on normie -trace
https://www.example.com/b   refang(url): hxxps://www.Example[.]com/a/../b -> https://www.Example.com/a/../b ;
                            host-lower(host): www.Example.com -> www.example.com ;
                            path-resolve(path): /a/../b -> /b
```

## Expansion is a strategy, not a constant

GSB's decomposition is a fixed label-count walk that ignores registrable-domain
boundaries entirely — `a.b.example.co.uk` yields the bare public suffix
`co.uk`, which can never be a useful key. It is required for compatibility with
GSB-format feeds and clients, and it must never become the only path.

`expr.PSL` walks real boundaries and stops at the apex. Supply it the offset
function a PSL implementation already computes:

```go
e := expr.PSL{Suffix: func(h string) (int, bool) {
    r := san.ToHost(&h)
    return r.Apex, r.Okay
}}
```

## Layout

| path | contents |
| --- | --- |
| `url.go` | `Split` — WHATWG-shaped grammar. Backslash folding, last-`@` userinfo, `#` as an authority terminator, scheme-vs-port disambiguation. Zero-alloc. |
| `ip.go` | `inet_aton` IPv4, IPv6 with zone stripping, and `IPClass`. Non-routable literals are classified, not discarded — an internal C2 address is an artifact. |
| `escape.go` | Bounded repeated unescape, GSB and RFC 3986 escape sets. |
| `canon.go` | Both profiles, host and path canonicalization, validation. |
| `defang.go` | `Refang` and wrapper `Unwrap`. Both opt-in and both traced: they are lossy guesses about intent, not normalizations. |
| `trace.go` | `Step`, `Trace`, and the reason codes. |
| `expr/` | Expansion strategies and hash prefixes. |
| `cmd/normie/` | stdin/stdout filter. Canonical to stdout, rejects with reasons to stderr. |

## Performance

```
BenchmarkSplit              144 ns/op       0 B/op    0 allocs/op
BenchmarkCanonSimple        736 ns/op     179 B/op    5 allocs/op
BenchmarkCanonMixed        1039 ns/op     339 B/op    8 allocs/op
BenchmarkCanonEscapeHeavy  1945 ns/op     936 B/op   27 allocs/op
```

`Split` is pure slicing. `Canon` allocates because every transformation stage
returns a new string; the next step is a caller-supplied scratch buffer API for
the ingest hot path. Not done yet — correctness first.

## Open items before production trust

These are known-unknown, not backlog. They should be closed before this feeds
anything a partner consumes.

1. **The GSB vector table in `canon_test.go` was written from the specification's
   stated rules, not machine-extracted from the live spec page** — this build
   environment has no egress to it. Re-derive it and diff. Any disagreement is a
   bug in the test file until proven otherwise.

2. **One known divergence is already flagged in that table**: a trailing C0
   control. WHATWG trims leading/trailing C0-and-space, which is what determines
   where a browser actually navigates; the literal GSB steps would escape it as
   `%02`. The code follows WHATWG. Confirm against Chromium.

3. **No differential harness against Chromium yet.** This is the test that finds
   real bugs — spec vectors are thin and would not have caught either
   misattribution above. `SafeBrowsingUrlUtil`/GURL over a large corpus.

4. **Port stripping convention.** The canonical form keeps the port; expression
   expansion excludes it regardless. If an upstream feed strips it, set
   `Options.DropPort`.

5. **IDNA divergence is real and load-bearing.** With no `Options.IDNA` hook,
   non-ASCII host bytes are percent-escaped — spec-literal, and byte-compatible
   with feeds generated that way, but *not* what a browser does, since Chrome
   runs IDNA in GURL before the GSB steps. Any pipeline that must agree with
   browser resolution has to supply the hook — use `idna.ToASCIIErr` from the
   shared, pinned `github.com/netstar-labs/idna` (its `Unicode()` is what
   `Result.HadNonASCII` and the profile stamp let you migrate on; see
   [PROFILES.md](PROFILES.md)).

## Testing

```
go test ./...                                   # 87% / 82% statement coverage
go test -run=XXX -fuzz=FuzzCanon -fuzztime=5m   # idempotence + host stability
go test -run=XXX -bench=. ./...
```

`FuzzCanon` asserts the properties that make a canonical form a key:
idempotence, host stability under re-parse, no structural delimiter surviving
into a host, and pure-ASCII non-control output. It found an unvalidated port
injecting raw bytes into the canonical form in under five seconds
(`testdata/fuzz/FuzzCanon/0ec76e5d7c509f08`, seed `"00X: 0"`, which produced
`http://00x: 0/`). That corpus entry is now a permanent regression.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
