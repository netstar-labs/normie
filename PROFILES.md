# Canonicalization profiles & the version stamp

Every A-label / hash / artifact normie produces is a **lookup key**, and a lookup
key is only meaningful next to the contract that produced it. That contract is the
`Profile` string (e.g. `gsb-canon/1`) — persist it on every stored row. This file
is the ledger of what each version means and the rule for bumping it.

## Profiles

| Profile constant | Value | Meaning |
|---|---|---|
| `ProfileGSB` | `gsb-canon/1` | Safe Browsing canonicalization contract (byte-compatible with the published GSB format). |
| `ProfileStorage` | `netstar-canon/1` | RFC 3986 normalization preserving scheme/userinfo for storage, display, pivoting. |
| `ProfileKey` | `netstar-key/1` | The key for a URL store: `gsb-canon/1` with the default port dropped for the scheme. Fragment and userinfo dropped, path unescaped repeatedly. |

## The version stamp encodes the UTS-46 pin

normie does not implement UTS-46 — it injects it (`Options.IDNA`), so the **caller's
pinned mapping is part of the contract**. The profile version therefore stands in
for "canonicalization output, *including* the IDNA mapping that produced it."

**Bump the profile version (`…/1` → `…/2`) whenever observable output changes** —
a code change to the canonicalizer, **or** a change to the pinned IDNA mapping that
moves any A-label. Record the bump here with the `idna` pin it corresponds to:

| Profile version | idna module / Unicode pin | Date | Note |
|---|---|---|---|
| `gsb-canon/1`, `netstar-canon/1` | `github.com/netstar-labs/idna` v0.1.0 (x/net v0.40.0, **Unicode 15.0.0**) | 2026-07-28 | initial |
| `netstar-key/1` | `github.com/netstar-labs/idna` v0.2.0 (x/net v0.61.0, **Unicode 17.0.0**) | 2026-11-20 | initial |

**The older `/1` rows predate idna v0.2.0.** idna has since moved to Unicode 17.0.0. That move
changes exactly one label that was already valid: U+1E9E (capital sharp s) mapped to `ss` under
Unicode 15 and to U+00DF under 17 (`idna`'s `TestUnicode17Changes`, re-run for this change). The
other two changes affect only inputs that were rejected before, so no stored key moves. The
profile string stands for the pin, so a row stamped `gsb-canon/1` or `netstar-canon/1` was made
against whichever idna the caller injected; record the idna version beside the stamp.
`netstar-key/1` is defined against v0.2.0 from the start.

**The three profiles advance together.** `/1` stands for now. When the pinned version moves,
every profile goes to the same new number in one change, so a single `/N` names a single pin and
the ledger never shows the profiles at different versions. Until that bump the table above shows
two pins, the older profiles at Unicode 15 and `netstar-key/1` at 17.

## Migrating a pin bump (targeted, not wholesale)

When you re-vendor `idna` and it moves output:

1. Bump the profile version above and stamp the new value onto freshly-canonicalized
   rows.
2. Only **non-ASCII** hosts can change — select on `Result.HadNonASCII` (indexed).
   Of those, only hosts containing a codepoint whose derived property actually
   changed between the two Unicode versions (diff the mapping tables → changed
   ranges).
3. Dual-write the affected rows (serve both old and new A-labels) during the
   rollout; drop the old once the query fleet is fully on the new version. A query
   stamped `…/1` must refuse or dual-look-up against a `…/2` index during the window
   — the stamp is what makes the skew detectable instead of a silent miss.

See the drift model in `github.com/netstar-labs/idna` (doc.go) — this is the UTS-46
(lookup-key) discipline. UTS-39 confusable skeletoning is the opposite (never a key,
update freely) and lives elsewhere.
