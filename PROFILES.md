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

The recommended hook is `idna.ToASCIIErr` from `github.com/netstar-labs/idna`
(vendored, pinned) — a nil hook falls back to spec-literal percent-escaping, which
does **not** agree with browser resolution.

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
