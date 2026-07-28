# normie — executive summary

**What it is.** A pure-Go, zero-dependency library that canonicalizes untrusted
URLs into stable, declared-profile lookup keys — the parser that sits in front of a
blocklist or artifact store.

**Why it exists.** A URL canonicalizer built on ad-hoc byte scanning does not
implement a grammar, it implements a guess, and the guesses fail in the two worst
ways a security system can. It can extract the *wrong* host (`http://good.com\@evil.com/`
→ `evil.com`), silently attributing an artifact to an innocent domain or letting an
attacker hide their host in what the scanner reads as a path — a failure that is not
fail-closed. Or it can *reject* an input the browser resolves fine
(`http://%65xample.com/`, `http://2130706433/`), so the URL is never checked while
the victim still reaches it — fail-open at the system. normie reproduces browser
parsing (WHATWG grammar + full `inet_aton` IP rules) so the key it stores is the
host the victim actually lands on.

**The core discipline — two profiles, never one.** The lookup form and the storage
form are separate contracts: the lookup key drops the fragment and userinfo (so a
password never lands in a hash), while the storage form preserves them for the
analyst graph. Every persisted row is stamped with the profile that produced it
(`gsb-canon/1` / `netstar-canon/1`); the stamp is what makes a future
canonicalization fix migratable instead of silently corrupting the corpus.

**Boundaries.** No resolution, no fetching, no verdict. UTS-46 host mapping is an
injected seam (the caller supplies the shared, pinned `netstar-labs/idna`), keeping
the core dependency-free and the Unicode pin under the caller's control.

**Shape.** `Canon(raw, *Options) Result` — with opt-in refang/unwrap for
threat-intel input, a full transformation `Trace` as evidence, and `expr`
strategies that turn a canonical host/path into hash prefixes (GSB-compatible, or
PSL-boundary-aware). A thin `cmd/normie` stdin/stdout filter wraps it.
