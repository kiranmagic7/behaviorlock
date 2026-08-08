package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kiranmagic7/behaviorlock/internal/capture"
	"github.com/kiranmagic7/behaviorlock/internal/compare"
	"github.com/kiranmagic7/behaviorlock/internal/model"
	"github.com/kiranmagic7/behaviorlock/internal/npm"
	"github.com/kiranmagic7/behaviorlock/internal/trace"
)

const Version = "0.1.0-dev"

func Run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	var exitCode int
	switch arguments[0] {
	case "capture":
		exitCode = runCapture(arguments[1:], stdout, stderr)
	case "profile":
		exitCode = runProfile(arguments[1:], stdout, stderr)
	case "compare":
		exitCode = runCompare(arguments[1:], stdout, stderr)
	case "validate":
		exitCode = runValidate(arguments[1:], stdout, stderr)
	case "doctor":
		exitCode = runDoctor(arguments[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, Version)
		exitCode = 0
	case "help", "--help", "-h":
		printUsage(stdout)
		exitCode = 0
	default:
		fmt.Fprintf(stderr, "behaviorlock: unknown command %q\n", safeText(arguments[0]))
		printUsage(stderr)
		exitCode = 2
	}
	return exitCode
}

func runCapture(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("capture", flag.ContinueOnError)
	flags.SetOutput(stderr)
	packageValue := flags.String("package", "", "exact public npm package version")
	output := flags.String("output", "-", "profile output path or - for stdout")
	timeout := flags.Duration("timeout", 2*time.Minute, "capture wall clock limit")
	experimental := flags.Bool("experimental", false, "acknowledge the experimental capture boundary")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 || !*experimental {
		fmt.Fprintln(stderr, "behaviorlock: capture requires --experimental and accepts no positional arguments")
		return 2
	}
	spec, err := npm.ParseExactSpec(*packageValue)
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: %s\n", safeText(err.Error()))
		return 2
	}
	runner, err := capture.NewDockerRunner()
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: %s\n", safeText(err.Error()))
		return 2
	}
	profile, captureErr := runner.Capture(context.Background(), spec, capture.Config{Timeout: *timeout, ToolVersion: Version})
	if profile.Subject.Name != "" {
		if err := writeProfile(*output, profile); err != nil {
			fmt.Fprintf(stderr, "behaviorlock: write profile: %s\n", safeText(err.Error()))
			return 2
		}
	}
	if captureErr != nil {
		fmt.Fprintf(stderr, "behaviorlock: %s\n", safeText(captureErr.Error()))
		return 2
	}
	if *output != "-" {
		fmt.Fprintf(stdout, "wrote %s with status %s\n", safeText(*output), profile.Result.Status)
	}
	if profile.Result.Status != "complete" {
		return 2
	}
	return 0
}

func runProfile(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("profile", flag.ContinueOnError)
	flags.SetOutput(stderr)
	packageValue := flags.String("package", "", "exact npm package version")
	tracePath := flags.String("trace", "", "raw strace input path")
	output := flags.String("output", "-", "profile output path or - for stdout")
	commandExit := flags.Int("command-exit", 0, "observed lifecycle command exit code")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *tracePath == "" || *commandExit < 0 || *commandExit > 255 {
		fmt.Fprintln(stderr, "behaviorlock: profile requires --package and --trace")
		return 2
	}
	spec, err := npm.ParseExactSpec(*packageValue)
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: %s\n", safeText(err.Error()))
		return 2
	}
	file, err := os.Open(*tracePath)
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: open trace: %s\n", safeText(err.Error()))
		return 2
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, trace.MaxTraceBytes+1))
	if err != nil || len(raw) > trace.MaxTraceBytes {
		fmt.Fprintln(stderr, "behaviorlock: trace could not be read within the size limit")
		return 2
	}
	parsed, err := trace.Parse(bytes.NewReader(raw))
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: parse trace: %s\n", safeText(err.Error()))
		return 2
	}
	if parsed.Stats.RecognizedLines == 0 {
		fmt.Fprintln(stderr, "behaviorlock: external trace contains no recognized events")
		return 2
	}
	profile := model.NewProfile(model.Subject{Ecosystem: "npm", Name: spec.Name, Version: spec.Version, PURL: spec.PURL()}, Version)
	profile.Capture.RunnerImage = "external-trace"
	profile.Capture.RunnerImageID = "unverified"
	profile.Capture.Architecture = "unknown"
	profile.Capture.NodeVersion = "unknown"
	profile.Capture.NPMVersion = "unknown"
	profile.Capture.StraceVersion = "unknown"
	profile.Capture.NetworkMode = "unknown"
	profile.Capture.SandboxProfile = "external-unverified"
	profile.Capture.TraceIntegrity = "external-unverified"
	profile.Capture.Coverage = model.CaptureCoverage{
		Scope: "external-strace", Completeness: "unverified", Lifecycle: []string{},
		Limitations: []string{"The caller supplied this trace; capture conditions and coverage are not attested."},
	}
	sum := sha256.Sum256(raw)
	profile.Capture.RawTraceSHA256 = "sha256:" + hex.EncodeToString(sum[:])
	profile.Behaviors = parsed.Behaviors
	profile.Result = model.Result{Status: "complete", ExitCode: *commandExit}
	if *commandExit != 0 {
		profile.Result.Status = "command_failed"
	}
	profile.Normalize()
	if err := writeProfile(*output, profile); err != nil {
		fmt.Fprintf(stderr, "behaviorlock: write profile: %s\n", safeText(err.Error()))
		return 2
	}
	if *output != "-" {
		fmt.Fprintf(stdout, "wrote %s with %d normalized behaviors\n", safeText(*output), len(profile.Behaviors))
	}
	return 0
}

func runCompare(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baselinePath := flags.String("baseline", "", "baseline profile path")
	candidatePath := flags.String("candidate", "", "candidate profile path")
	output := flags.String("output", "-", "report output path or - for stdout")
	format := flags.String("format", "json", "json, text, or markdown")
	failOn := flags.String("fail-on", "high", "none, low, medium, high, or critical")
	allowExternal := flags.Bool("allow-external", false, "acknowledge that external traces have unverified provenance")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *baselinePath == "" || *candidatePath == "" {
		fmt.Fprintln(stderr, "behaviorlock: compare requires --baseline and --candidate")
		return 2
	}
	if *failOn != "none" && model.SeverityRank(*failOn) == 0 {
		fmt.Fprintf(stderr, "behaviorlock: invalid --fail-on value %q\n", safeText(*failOn))
		return 2
	}
	baseline, err := model.ReadProfile(*baselinePath)
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: baseline: %s\n", safeText(err.Error()))
		return 2
	}
	candidate, err := model.ReadProfile(*candidatePath)
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: candidate: %s\n", safeText(err.Error()))
		return 2
	}
	diff, err := compare.ProfilesWithOptions(baseline, candidate, Version, compare.Options{AllowExternal: *allowExternal})
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: compare: %s\n", safeText(err.Error()))
		return 2
	}
	if err := writeDiff(*output, *format, diff, stdout); err != nil {
		fmt.Fprintf(stderr, "behaviorlock: write report: %s\n", safeText(err.Error()))
		return 2
	}
	if *failOn != "none" && model.SeverityRank(diff.Summary.HighestRisk) >= model.SeverityRank(*failOn) {
		return 1
	}
	return 0
}

func runValidate(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profilePath := flags.String("profile", "", "profile path")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *profilePath == "" {
		fmt.Fprintln(stderr, "behaviorlock: validate requires --profile")
		return 2
	}
	profile, err := model.ReadProfile(*profilePath)
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: invalid profile: %s\n", safeText(err.Error()))
		return 2
	}
	digest, err := profile.StableDigest()
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: digest profile: %s\n", safeText(err.Error()))
		return 2
	}
	fmt.Fprintf(stdout, "structurally valid %s %s %s; authenticity not verified\n", profile.Kind, profile.Subject.PURL, digest)
	return 0
}

func runDoctor(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "behaviorlock: doctor accepts no arguments")
		return 2
	}
	runner, err := capture.NewDockerRunner()
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: %s\n", safeText(err.Error()))
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := runner.Doctor(ctx); err != nil {
		fmt.Fprintf(stderr, "behaviorlock: %s\n", safeText(err.Error()))
		return 2
	}
	fmt.Fprintln(stdout, "docker and the local BehaviorLock runner image are available")
	return 0
}

func writeProfile(path string, profile model.Profile) error {
	profile.Normalize()
	if err := model.ValidateProfile(profile); err != nil {
		return err
	}
	return model.WriteJSON(path, profile)
}

func writeDiff(path, format string, diff model.Diff, stdout io.Writer) error {
	if format == "json" {
		if path == "-" {
			encoder := json.NewEncoder(stdout)
			encoder.SetEscapeHTML(true)
			encoder.SetIndent("", "  ")
			return encoder.Encode(diff)
		}
		return model.WriteJSON(path, diff)
	}
	var content string
	switch format {
	case "text":
		content = renderText(diff)
	case "markdown":
		content = renderMarkdown(diff)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
	if path == "-" {
		_, err := io.WriteString(stdout, content)
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

func renderText(diff model.Diff) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "BehaviorLock observed install lifecycle diff\n")
	fmt.Fprintf(&builder, "Package: %s\n", safeText(diff.Candidate.Name))
	fmt.Fprintf(&builder, "Versions: %s to %s\n", safeText(diff.Baseline.Version), safeText(diff.Candidate.Version))
	fmt.Fprintf(&builder, "Verdict: %s\n", diff.Summary.Verdict)
	fmt.Fprintf(&builder, "Added: %d  Removed: %d  Highest risk: %s\n", diff.Summary.Added, diff.Summary.Removed, diff.Summary.HighestRisk)
	for _, change := range diff.Added {
		fmt.Fprintf(&builder, "[%s] %s %s %s (%s)\n", strings.ToUpper(change.Risk), change.RuleID, safeText(change.Behavior.Type), safeText(change.Behavior.Target), safeText(change.Reason))
	}
	for _, limitation := range diff.Limitations {
		fmt.Fprintf(&builder, "Limitation: %s\n", safeText(limitation))
	}
	return builder.String()
}

func renderMarkdown(diff model.Diff) string {
	var builder strings.Builder
	builder.WriteString("# BehaviorLock observed install lifecycle diff\n\n")
	fmt.Fprintf(&builder, "Package: %s\n\n", markdownCode(diff.Candidate.Name))
	fmt.Fprintf(&builder, "Compared %s with %s. Verdict: **%s**. Highest review level: **%s**.\n\n", markdownCode(diff.Baseline.Version), markdownCode(diff.Candidate.Version), markdown(diff.Summary.Verdict), markdown(diff.Summary.HighestRisk))
	builder.WriteString("| Level | Rule | Behavior | Target | Reason |\n")
	builder.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, change := range diff.Added {
		fmt.Fprintf(&builder, "| %s | %s | %s | %s | %s |\n", markdown(change.Risk), markdownCode(change.RuleID), markdownCode(change.Behavior.Type), markdownCode(change.Behavior.Target), markdown(change.Reason))
	}
	if len(diff.Added) == 0 {
		builder.WriteString("| none | none | none | none | No added observed behavior |\n")
	}
	builder.WriteString("\n## Limitations\n\n")
	for _, limitation := range diff.Limitations {
		fmt.Fprintf(&builder, "* %s\n", markdown(limitation))
	}
	builder.WriteString("\nThis report compares behavior exercised during the selected npm install lifecycle. It does not classify malware or prove that either package version is safe.\n")
	return builder.String()
}

func markdown(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "|", "\\|", "\n", " ", "\r", " ", "\t", " ")
	return replacer.Replace(safeText(value))
}

func markdownCode(value string) string {
	return "<code>" + strings.ReplaceAll(html.EscapeString(safeText(value)), "|", "&#124;") + "</code>"
}

func safeText(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			builder.WriteRune('?')
			continue
		}
		builder.WriteRune(character)
		if builder.Len() >= 4096 {
			builder.WriteString("…")
			break
		}
	}
	return builder.String()
}

func printUsage(writer io.Writer) {
	_, _ = io.WriteString(writer, `BehaviorLock compares observed npm install lifecycle behavior between exact package versions.

Usage:
  behaviorlock doctor
  behaviorlock capture --experimental --package name@1.2.3 --output profile.json
  behaviorlock profile --package name@1.2.3 --trace raw.strace --output profile.json
  behaviorlock compare --baseline old.json --candidate new.json --output report.json
  behaviorlock compare --allow-external --baseline old.json --candidate new.json
  behaviorlock validate --profile profile.json
  behaviorlock version

Exit codes:
  0  completed and policy threshold not reached
  1  observed changes reached the configured review threshold
  2  invalid input, incomplete trace, sandbox failure, or runtime error
`)
}
