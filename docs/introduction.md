# Meet normie — the URL a browser would actually resolve

A blocklist is only as honest as the parser in front of it. Hand a naive
byte-scanner `http://example.com\@evil.com/` and it hands back `evil.com`; a
browser navigates to `example.com`. That single disagreement is the worst thing a
security pipeline can do — it either attributes an artifact to an innocent domain,
or lets an attacker hide their host where the parser reads a path. normie exists to
make that disagreement impossible: given a byte string that arrived from the wild,
it answers *what will a browser actually resolve this to, and under what canonical
form will we store and look it up.*

## What it actually is

normie is a pure-Go, zero-dependency URL canonicalizer. It is deliberately two
layers, because conflating them is how a corpus ends up mis-attributing an
artifact. `Split` implements a **WHATWG-shaped URL grammar** — backslash folding,
last-`@` userinfo, `#`-as-authority-terminator, C0 stripping — reproducing how a
browser *parses*. `Canon` then applies **profile-specific normalization** on top of
that parse to produce the actual lookup key. It also parses IP literals the way a
browser does (`inet_aton` radix rules, so `2130706433`, `0x7f.0.0.1`, and `127.1`
all resolve to `127.0.0.1` instead of vanishing from the pipeline), and classifies
non-routable literals rather than discarding them — an internal C2 address is an
artifact, not noise.

## The line it draws: lookup vs storage

There is never one canonical form. The **lookup** form (a hash key) and the
**storage** form (the analyst-facing artifact) are different contracts, and every
persisted row carries the identity of the profile that produced it — `gsb-canon/1`
or `netstar-canon/1`. Stamp it on everything: the first time a canonicalization bug
is fixed, the stamp is the only way to know which stored hashes went stale.

## The boundary it keeps

normie canonicalizes and classifies; it does not resolve, fetch, or judge. Unicode
host mapping (UTS-46) is an *injected seam*, not a dependency, so the core carries
zero third-party code and the caller supplies a pinned mapping. It does not decide
what a host *means* or whether it is malicious — it produces the stable key those
questions are asked against. That discipline is what lets it be a pure function you
can drop into an ingest path and a query path and trust to agree.

*Read next:* [executive-summary.md](executive-summary.md) ·
[architecture.md](architecture.md) · [userguide.md](userguide.md) ·
[../PROFILES.md](../PROFILES.md) · [../example/README.md](../example/README.md)
