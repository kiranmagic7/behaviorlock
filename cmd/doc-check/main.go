package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kiranmagic7/behaviorlock/internal/doccheck"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "doc-check: positional arguments are not accepted")
		os.Exit(2)
	}
	issues, err := doccheck.Check(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "doc-check: %s\n", err)
		os.Exit(1)
	}
	for _, issue := range issues {
		fmt.Fprintln(os.Stderr, issue.String())
	}
	if len(issues) != 0 {
		os.Exit(1)
	}
	fmt.Println("documentation links: all relative targets resolved")
}
