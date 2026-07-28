// Runnable example: canonicalize a few adversarial URLs under ProfileGSB and
// show the evidence trace. Uses a nil IDNA hook (ASCII hosts) — for IDN hosts wire
// idna.ToASCIIErr from github.com/netstar-labs/idna, kept out of this example so
// normie stays dependency-free.
//
//	go run ./example/canon
package main

import (
	"fmt"

	"github.com/netstar-labs/normie"
)

func main() {
	inputs := []string{
		`http://good.com\@evil.com/`,  // backslash authority-confusion: host is good.com
		"http://%65xample.com/a/../b", // percent-decoded + path-resolved
		"http://2130706433/",          // inet_aton integer IP -> 127.0.0.1
		"hxxps://www.Example[.]com/p", // defanged (needs Refang)
	}

	for _, raw := range inputs {
		r := normie.Canon(raw, &normie.Options{Profile: normie.ProfileGSB, Refang: true})
		fmt.Printf("%-32q ->\n", raw)
		if !r.Okay() {
			fmt.Printf("    REJECT  reason=%v\n", r.Reason)
			continue
		}
		fmt.Printf("    host=%q  canonical=%q  profile=%s  ip=%v\n", r.Host, r.Canonical, r.Profile, r.IP)
		fmt.Printf("    trace: %v\n", r.Trace)
	}
}
