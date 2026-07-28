# normie — user guide

## Library

```go
import (
    "github.com/netstar-labs/normie"
    "github.com/netstar-labs/normie/expr"
    "github.com/netstar-labs/idna" // pinned UTS-46 host mapping
)

r := normie.Canon(raw, &normie.Options{
    Profile: normie.ProfileGSB,
    Refang:  true,             // hxxp://, [.], [dot] — off by default
    Unwrap:  true,             // SafeLinks, URLDefense, AMP — off by default
    IDNA:    idna.ToASCIIErr,  // browser-agreeing UTS-46; nil = spec-literal %-escape
})
if !r.Okay() {
    log.Printf("%s: %v (%v)", raw, r.Reason, r.Trace)
    return
}
hashes := expr.Hashes(expr.GSB{}, r.Host, r.PathQuery, r.IP)
```

### Options

| field | meaning |
|---|---|
| `Profile` | `ProfileGSB` (lookup key, default) or `ProfileStorage` (artifact/display) |
| `IDNA` | UTS-46 hook `func(host) (string, error)`; nil percent-escapes non-ASCII (spec-literal, not browser) |
| `Refang` | rectify defanged notation before parsing (traced; off by default) |
| `Unwrap` | unwrap known redirector/mail-gateway wrappers (traced; off by default) |
| `DropPort` | drop the port from the canonical form |
| `UnescapeDepth`, `MaxURLLen`, `MaxHostLen`, `AssumeScheme` | bounds + schemeless default (sane defaults applied) |

### Result

`Canonical`, `Host`, `PathQuery`, `Profile`, `Reason`, `Trace`, `URL`, and for IP
literals `IP`/`IPClass`/`Addr`. **`HadNonASCII`** flags an IDN host (before UTS-46) —
index it for targeted migration on an IDNA pin bump. `Okay()` reports usability as
a lookup key. `Canon` never panics and never returns an error — failure is
`Result.Reason`, with `Trace` showing how far it got.

**Always persist `Result.Profile`** next to any stored hash/host; a stored key is
unverifiable without the contract that produced it, and un-migratable when that
contract changes. See [../PROFILES.md](../PROFILES.md) for the version-stamp ledger
and the migration procedure.

## IDNA / UTS-46

Non-ASCII hosts need the injected hook to agree with browser resolution. Use
`idna.ToASCIIErr` from the shared, pinned `github.com/netstar-labs/idna` (Unicode
15.0.0). A nil hook percent-escapes instead — byte-compatible with GSB-format feeds,
but *not* what a browser resolves. `Result.HadNonASCII` + `idna.Unicode()` + the
profile stamp are the three things a migration keys on.

## Expansion strategies (`expr/`)

- `expr.GSB{}` — fixed label-count decomposition; required for GSB-format feeds, but
  ignores registrable-domain boundaries (never make it the only path).
- `expr.PSL{Suffix: …}` — walks real boundaries, stops at the apex; pass it a
  suffix-offset function (e.g. from `sanitize`):
  ```go
  e := expr.PSL{Suffix: func(h string) (int, bool) { r := san.ToHost(&h); return r.Apex, r.Okay }}
  ```

## CLI

```
printf 'hxxps://www.Example[.]com/a/../b\n' | REFANG=on normie -trace
```

`cmd/normie` is a stdin/stdout filter: canonical host/URL to stdout, rejects with
their reason to stderr. `-trace` prints the full transformation trace (the evidence
behind a verdict). Build it with `go build ./cmd/normie`.

## Testing

```
go test ./...                                   # unit + GSB vectors + misattribution/bypass
go test -run=XXX -fuzz=FuzzCanon -fuzztime=5m   # idempotence + host stability
go test -run=XXX -bench=. ./...
```

`FuzzCanon` asserts the key-invariants: idempotence, host stability under re-parse,
no structural delimiter surviving into a host, ASCII non-control output.
