// Command normie canonicalizes a list of URLs, one per line, from stdin or a
// file argument. Canonical forms go to stdout; rejects go to stderr with their
// reason, so a pipeline can separate the two without parsing.
//
//	normie urls.txt > canonical.txt 2> rejected.txt
//	cat urls.txt | PROFILE=storage REFANG=on normie
//	normie -expr urls.txt        # emit lookup expressions instead
//	normie -trace urls.txt       # append the transformation trace
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/netstar-labs/normie"
	"github.com/netstar-labs/normie/expr"
)

// Version and Revision are stamped via -ldflags -X.
var Version, Revision = "dev", "unknown"

func main() {
	var (
		showExpr  = flag.Bool("expr", false, "emit lookup expressions, one per line, instead of canonical URLs")
		showHash  = flag.Bool("hash", false, "emit 4-byte hash prefixes as hex instead of canonical URLs")
		showTrace = flag.Bool("trace", false, "append the transformation trace to each line")
		version   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Printf("normie %s %s\n", Version, Revision)
		return
	}

	opts := &normie.Options{
		Profile: normie.ProfileGSB,
		Refang:  envOn("REFANG"),
		Unwrap:  envOn("UNWRAP"),
	}
	if strings.EqualFold(os.Getenv("PROFILE"), "storage") {
		opts.Profile = normie.ProfileStorage
	}

	reader := os.Stdin
	if args := flag.Args(); len(args) > 0 {
		f, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		reader = f
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	sc := bufio.NewScanner(reader)
	// A long line must not silently truncate the scan, which is how a partial
	// feed load goes unnoticed.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		r := normie.Canon(line, opts)
		if !r.Okay() {
			fmt.Fprintf(os.Stderr, "%s\t%s\n", line, r.Reason)
			continue
		}

		switch {
		case *showExpr:
			for _, e := range (expr.GSB{}).Expand(r.Host, r.PathQuery, r.IP) {
				fmt.Fprintln(out, e)
			}
		case *showHash:
			for _, h := range expr.Hashes(expr.GSB{}, r.Host, r.PathQuery, r.IP) {
				fmt.Fprintf(out, "%08x\n", h.Uint32())
			}
		case *showTrace:
			fmt.Fprintf(out, "%s\t%s\n", r.Canonical, r.Trace)
		default:
			fmt.Fprintln(out, r.Canonical)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "read error:", err)
		os.Exit(1)
	}
}

func envOn(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "on", "true", "1", "yes":
		return true
	}
	return false
}
