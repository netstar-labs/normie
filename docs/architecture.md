# normie — architecture

normie is a pipeline of pure string transformations with no I/O and no network. The
one injected seam is UTS-46 host mapping (`Options.IDNA`), so the core stays
dependency-free and the Unicode pin lives with the caller.

## Data flow

```
raw ─▶ Refang ─▶ Unwrap ─▶ Split ─▶ Canon ─▶ expr.Expand ─▶ hash prefixes
       (opt-in)  (opt-in)  grammar   profile   strategy
                                       │
                                   Options.IDNA  (injected UTS-46 seam)
```

Refang and Unwrap are **opt-in and traced** — they are lossy guesses about intent
(`hxxp://`, `[.]`, SafeLinks/URLDefense/AMP wrappers), not normalizations, so they
never run unless the caller asks and every rewrite is recorded.

## The two-layer split (the load-bearing design)

The code deliberately separates *parsing* from *key production*, because conflating
them is how a blocklist mis-attributes an artifact:

- **`Split` (`url.go`)** — a WHATWG-shaped URL grammar: backslash folding, userinfo
  ends at the **last** `@`, `#` terminates the authority, scheme-vs-port
  disambiguation, C0 stripping. Zero-alloc, pure slicing. This reproduces how a
  browser *parses* an authority — so a crafted `\@` or `#@` can't smuggle a
  different host past extraction.
- **`Canon` (`canon.go`)** — profile-specific normalization on top of the parse:
  host lower-casing, dot collapsing, path resolution, percent handling, IDNA via
  the seam, validation. This produces the actual lookup key.

## Two profiles, never one

The lookup form and the storage form are distinct contracts; every stored artifact
carries the profile identity (`Result.Profile`) that produced it.

| | `ProfileGSB` (`gsb-canon/1`) | `ProfileStorage` (`netstar-canon/1`) |
|---|---|---|
| purpose | lookup keys only | artifact graph, pivoting, analyst UI |
| fragment | dropped | preserved |
| userinfo | dropped | dropped, presence recorded |
| default port | preserved | dropped |
| percent | unescape repeatedly, then re-escape | RFC 3986 normalize only |
| escape set | `≤0x20`, `≥0x7f`, `#`, `%` | RFC 3986 |

The **version stamp** on the profile is what makes a canonicalization change
migratable — see [../PROFILES.md](../PROFILES.md). `Result.HadNonASCII` flags the
rows an IDNA re-vendor can affect, so a pin bump recomputes a tiny selection, not
the whole corpus.

## IP literals

`ip.go` implements full `inet_aton` radix rules (`2130706433`, `0x7f.0.0.1`,
`127.1` → `127.0.0.1`) — the forms `net/netip.ParseAddr` rejects and that therefore
vanish from any pipeline built on it. Non-routable literals are **classified**
(`IPClass`), not discarded: an internal address is a real artifact.

## Expansion is a strategy (`expr/`)

`expr` turns a canonical host + path into the hash prefixes a lookup needs.
`expr.GSB` is the fixed label-count decomposition required for GSB-format feeds —
but it ignores registrable-domain boundaries (it will emit a bare `co.uk`), so it
must never be the only path. `expr.PSL` walks real boundaries and stops at the apex,
given a suffix-offset function (which a PSL implementation such as `sanitize`
already computes).

## Trade-offs / open items

- **`Canon` allocates** (each stage returns a new string); `Split` does not. A
  scratch-buffer API for the ingest hot path is deferred — correctness first.
- **No differential harness against Chromium yet** — the GSB vector table is
  written from the spec, not machine-extracted; the real bug-finder is a GURL
  differential over a large corpus. Tracked in the README's "Open items."
- **IDNA divergence is real:** with no hook, non-ASCII host bytes are
  percent-escaped (spec-literal, *not* browser behaviour). Supply `idna.ToASCIIErr`
  from the shared pinned `netstar-labs/idna` for browser agreement.
