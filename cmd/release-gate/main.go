package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kiranmagic7/behaviorlock/internal/releasegate"
)

func main() {
	configPath := flag.String("config", "config/release-proofs.json", "required proof configuration")
	evidencePath := flag.String("evidence", "", "collected GitHub check evidence")
	repository := flag.String("repository", "", "expected owner/repository")
	sourceSHA := flag.String("source-sha", "", "expected protected source commit")
	flag.Parse()
	if flag.NArg() != 0 || *evidencePath == "" || *repository == "" || *sourceSHA == "" {
		fmt.Fprintln(os.Stderr, "release-gate: --evidence, --repository, and --source-sha are required")
		os.Exit(2)
	}
	config, evidence, err := releasegate.Load(*configPath, *evidencePath)
	if err == nil {
		err = releasegate.Verify(config, evidence, *repository, *sourceSHA, time.Now().UTC())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "release-gate: blocked: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("release-gate: all 14 proofs verified for %s@%s\n", *repository, *sourceSHA)
}
