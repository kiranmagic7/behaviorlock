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
	format := flag.String("format", "markdown", "report format: json or markdown")
	flag.Parse()
	if flag.NArg() != 0 || *evidencePath == "" || *repository == "" || *sourceSHA == "" || (*format != "json" && *format != "markdown") {
		fmt.Fprintln(os.Stderr, "release-report: --evidence, --repository, --source-sha, and --format json|markdown are required")
		os.Exit(2)
	}
	config, evidence, err := releasegate.Load(*configPath, *evidencePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "release-report: blocked: %s\n", err)
		os.Exit(1)
	}
	report, err := releasegate.Assess(config, evidence, *repository, *sourceSHA, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "release-report: blocked: %s\n", err)
		os.Exit(1)
	}
	if *format == "json" {
		encoded, encodeErr := releasegate.MarshalReport(report)
		if encodeErr != nil {
			fmt.Fprintf(os.Stderr, "release-report: encode: %s\n", encodeErr)
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(encoded)
	} else {
		fmt.Print(releasegate.RenderMarkdown(report))
	}
	if !report.AllGatesSatisfied {
		os.Exit(1)
	}
}
