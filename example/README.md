# normie examples

| Example | What it shows | Run |
|---|---|---|
| [canon](canon/main.go) | canonicalizing adversarial URLs (backslash confusion, percent-encoding, `inet_aton` IP, defanged) under `ProfileGSB`, with the evidence `Trace` | `go run ./example/canon` |

The examples use a nil `Options.IDNA` hook (ASCII hosts) to keep them
dependency-free. For IDN hosts, wire `idna.ToASCIIErr` from the shared, pinned
`github.com/netstar-labs/idna` — see [../docs/userguide.md](../docs/userguide.md).

For the stdin/stdout CLI, see [../cmd/normie](../cmd/normie) and the
[user guide](../docs/userguide.md):

```sh
printf 'hxxps://www.Example[.]com/a/../b\n' | REFANG=on go run ./cmd/normie -trace
```
