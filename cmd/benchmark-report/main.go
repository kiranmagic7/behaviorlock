package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kiranmagic7/behaviorlock/internal/benchmark"
)

func main() {
	manifestPath := flag.String("manifest", "benchmark/manifest.json", "inert benchmark manifest")
	format := flag.String("format", "json", "report format: json or markdown")
	flag.Parse()
	if flag.NArg() != 0 || (*format != "json" && *format != "markdown") {
		fmt.Fprintln(os.Stderr, "benchmark-report: --format must be json or markdown and positional arguments are not accepted")
		os.Exit(2)
	}
	report, err := benchmark.Run(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark-report: blocked: %s\n", err)
		os.Exit(1)
	}
	if *format == "markdown" {
		fmt.Print(benchmark.RenderMarkdown(report))
		return
	}
	encoded, err := benchmark.MarshalJSON(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark-report: encode: %s\n", err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(encoded)
}
