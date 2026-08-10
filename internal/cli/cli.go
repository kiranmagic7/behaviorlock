package cli

import (
	"bytes"
	"context"
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
	evidenceOutput := flags.String("evidence-output", "", "raw evidence output path; defaults beside a file profile")
	timeout := flags.Duration("timeout", 2*time.Minute, "capture wall clock limit")
	runnerImage := flags.String("runner", capture.RunnerImage, "runner image tag, digest reference, or local content ID")
	phase := flags.String("phase", "lifecycle", "capture phase: lifecycle or import")
	sinkhole := flags.Bool("sinkhole", false, "use the experimental inert loopback sinkhole instead of offline execution")
	experimental := flags.Bool("experimental", false, "acknowledge the experimental capture boundary")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 || !*experimental {
		fmt.Fprintln(stderr, "behaviorlock: capture requires --experimental and accepts no positional arguments")
		return 2
	}
	evidencePath, err := resolveEvidenceOutput(*output, *evidenceOutput)
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: %s\n", safeText(err.Error()))
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
	profile, rawEvidence, captureErr := runner.CaptureWithEvidence(context.Background(), spec, capture.Config{
		Timeout: *timeout, ToolVersion: Version, RunnerImage: *runnerImage, Phase: *phase, Sinkhole: *sinkhole,
	})
	if profile.Subject.Name != "" {
		if err := writeProfileArtifacts(*output, evidencePath, rawEvidence, profile, stdout); err != nil {
			fmt.Fprintf(stderr, "behaviorlock: write profile: %s\n", safeText(err.Error()))
			return 2
		}
	}
	if captureErr != nil {
		fmt.Fprintf(stderr, "behaviorlock: %s\n", safeText(captureErr.Error()))
		return 2
	}
	if *output != "-" {
		if len(rawEvidence) > 0 {
			fmt.Fprintf(stdout, "wrote %s and retained evidence %s with status %s\n", safeText(*output), safeText(evidencePath), profile.Result.Status)
		} else {
			fmt.Fprintf(stdout, "wrote %s with incomplete status %s; no verified raw evidence was available\n", safeText(*output), profile.Result.Status)
		}
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
	evidenceOutput := flags.String("evidence-output", "", "retained raw evidence output path; defaults beside a file profile")
	commandExit := flags.Int("command-exit", 0, "observed command exit code")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *tracePath == "" || *commandExit < 0 || *commandExit > 255 {
		fmt.Fprintln(stderr, "behaviorlock: profile requires --package and --trace")
		return 2
	}
	evidencePath, err := resolveEvidenceOutput(*output, *evidenceOutput)
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: %s\n", safeText(err.Error()))
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
	profile.Capture.Phase = "external"
	profile.Capture.Coverage = model.CaptureCoverage{
		Scope: "external-strace", Completeness: "unverified", Lifecycle: []string{},
		Limitations: []string{"The caller supplied this trace; capture conditions and coverage are not attested."},
	}
	profile.Behaviors = parsed.Behaviors
	profile.Sequences = model.BuildObservationSequences(parsed.Behaviors)
	model.AttachEvidence(&profile, raw, "external-unverified", "external-strace")
	profile.Result = model.Result{Status: "complete", ExitCode: *commandExit}
	if *commandExit != 0 {
		profile.Result.Status = "command_failed"
	}
	profile.Normalize()
	if err := writeProfileArtifacts(*output, evidencePath, raw, profile, stdout); err != nil {
		fmt.Fprintf(stderr, "behaviorlock: write profile: %s\n", safeText(err.Error()))
		return 2
	}
	if *output != "-" {
		fmt.Fprintf(stdout, "wrote %s with %d normalized behaviors and retained unverified evidence %s\n", safeText(*output), len(profile.Behaviors), safeText(evidencePath))
	}
	return 0
}

func runCompare(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baselinePath := flags.String("baseline", "", "baseline profile path")
	candidatePath := flags.String("candidate", "", "candidate profile path")
	baselineEvidence := flags.String("baseline-evidence", "", "baseline raw evidence path; defaults beside the profile")
	candidateEvidence := flags.String("candidate-evidence", "", "candidate raw evidence path; defaults beside the profile")
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
	if *failOn != "none" && model.ReviewLevelRank(*failOn) == 0 {
		fmt.Fprintf(stderr, "behaviorlock: invalid --fail-on value %q\n", safeText(*failOn))
		return 2
	}
	baseline, err := readProfileWithEvidence(*baselinePath, *baselineEvidence)
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: baseline: %s\n", safeText(err.Error()))
		return 2
	}
	candidate, err := readProfileWithEvidence(*candidatePath, *candidateEvidence)
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
	if *failOn != "none" && model.ReviewLevelRank(diff.Summary.HighestReviewLevel) >= model.ReviewLevelRank(*failOn) {
		return 1
	}
	return 0
}

func runValidate(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profilePath := flags.String("profile", "", "profile path")
	evidencePath := flags.String("evidence", "", "raw evidence path; defaults beside the profile")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *profilePath == "" {
		fmt.Fprintln(stderr, "behaviorlock: validate requires --profile")
		return 2
	}
	profile, err := readProfileWithEvidence(*profilePath, *evidencePath)
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: invalid profile: %s\n", safeText(err.Error()))
		return 2
	}
	digest, err := profile.StableDigest()
	if err != nil {
		fmt.Fprintf(stderr, "behaviorlock: digest profile: %s\n", safeText(err.Error()))
		return 2
	}
	fmt.Fprintf(stdout, "structurally valid %s %s %s; raw evidence verified; signer authenticity not verified\n", profile.Kind, profile.Subject.PURL, digest)
	return 0
}

func runDoctor(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	runnerImage := flags.String("runner", capture.RunnerImage, "runner image tag, digest reference, or local content ID")
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
	if err := runner.Doctor(ctx, *runnerImage); err != nil {
		fmt.Fprintf(stderr, "behaviorlock: %s\n", safeText(err.Error()))
		return 2
	}
	fmt.Fprintf(stdout, "docker and runner image %s are available\n", safeText(*runnerImage))
	return 0
}

func writeProfileArtifacts(path, evidencePath string, raw []byte, profile model.Profile, stdout io.Writer) error {
	profile.Normalize()
	if err := model.ValidateProfile(profile); err != nil {
		return err
	}
	if profile.Capture.EvidenceArtifact != nil {
		if err := model.VerifyEvidence(profile, raw); err != nil {
			return err
		}
		if err := model.WriteEvidence(evidencePath, raw); err != nil {
			return err
		}
	} else if len(raw) != 0 {
		return fmt.Errorf("profile does not declare the supplied raw evidence")
	}
	if path == "-" {
		return model.EncodeJSON(stdout, profile)
	}
	return model.WriteJSON(path, profile)
}

func resolveEvidenceOutput(profilePath, requested string) (string, error) {
	if requested == "-" {
		return "", fmt.Errorf("raw evidence cannot share stdout with a profile")
	}
	if requested == "" {
		if profilePath == "" || profilePath == "-" {
			return "", fmt.Errorf("stdout profile output requires an explicit --evidence-output file")
		}
		requested = profilePath + ".evidence.strace"
	}
	if requested == profilePath {
		return "", fmt.Errorf("profile and raw evidence outputs must be different files")
	}
	return requested, nil
}

func readProfileWithEvidence(profilePath, requestedEvidencePath string) (model.Profile, error) {
	profile, err := model.ReadProfile(profilePath)
	if err != nil {
		return model.Profile{}, err
	}
	evidencePath := requestedEvidencePath
	if evidencePath == "" {
		evidencePath = profilePath + ".evidence.strace"
	}
	// #nosec G304 -- reading a caller-selected evidence path is the explicit local CLI contract.
	file, err := os.Open(evidencePath)
	if err != nil {
		return model.Profile{}, fmt.Errorf("open raw evidence %s: %w", evidencePath, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, trace.MaxTraceBytes+1))
	if err != nil {
		return model.Profile{}, fmt.Errorf("read raw evidence: %w", err)
	}
	if len(raw) > trace.MaxTraceBytes {
		return model.Profile{}, fmt.Errorf("raw evidence exceeds %d bytes", trace.MaxTraceBytes)
	}
	if err := model.VerifyEvidence(profile, raw); err != nil {
		return model.Profile{}, fmt.Errorf("verify raw evidence: %w", err)
	}
	return profile, nil
}

func writeDiff(path, format string, diff model.Diff, stdout io.Writer) error {
	if format == "json" {
		if path == "-" {
			return model.EncodeJSON(stdout, diff)
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
	fmt.Fprintf(&builder, "BehaviorLock observed %s phase diff\n", safeText(diff.Phase))
	fmt.Fprintf(&builder, "Package: %s\n", safeText(diff.Candidate.Name))
	fmt.Fprintf(&builder, "Versions: %s to %s\n", safeText(diff.Baseline.Version), safeText(diff.Candidate.Version))
	fmt.Fprintf(&builder, "Review required: %t\n", diff.Summary.ReviewRequired)
	fmt.Fprintf(&builder, "Added: %d  Removed: %d  Highest review level: %s\n", diff.Summary.Added, diff.Summary.Removed, diff.Summary.HighestReviewLevel)
	for _, change := range diff.Added {
		technique := techniqueLabel(change.Techniques)
		if technique != "" {
			technique = " technique=\"" + technique + "\""
		}
		fmt.Fprintf(&builder, "[%s] %s %s %s (%s) evidence=%s%s\n", strings.ToUpper(change.ReviewLevel), change.RuleID, safeText(change.Behavior.Type), safeText(change.Behavior.Target), safeText(change.Reason), evidenceLabel(change.Behavior), technique)
	}
	for _, behavior := range diff.Removed {
		fmt.Fprintf(&builder, "[REMOVED] %s %s evidence=%s\n", safeText(behavior.Type), safeText(behavior.Target), evidenceLabel(behavior))
	}
	for _, sequence := range diff.AddedSequences {
		fmt.Fprintf(&builder, "[ADDED SEQUENCE] %s: %s\n", safeText(sequence.ID), safeText(strings.Join(sequence.BehaviorIDs, " -> ")))
	}
	for _, sequence := range diff.RemovedSequences {
		fmt.Fprintf(&builder, "[REMOVED SEQUENCE] %s: %s\n", safeText(sequence.ID), safeText(strings.Join(sequence.BehaviorIDs, " -> ")))
	}
	for _, limitation := range diff.Limitations {
		fmt.Fprintf(&builder, "Limitation: %s\n", safeText(limitation))
	}
	return builder.String()
}

func renderMarkdown(diff model.Diff) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# BehaviorLock observed %s phase diff\n\n", markdown(diff.Phase))
	fmt.Fprintf(&builder, "Package: %s\n\n", markdownCode(diff.Candidate.Name))
	fmt.Fprintf(&builder, "Compared %s with %s. Review required: **%t**. Highest review level: **%s**.\n\n", markdownCode(diff.Baseline.Version), markdownCode(diff.Candidate.Version), diff.Summary.ReviewRequired, markdown(diff.Summary.HighestReviewLevel))
	builder.WriteString("| Level | Rule | Behavior | Target | Evidence | Technique context | Reason |\n")
	builder.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, change := range diff.Added {
		fmt.Fprintf(&builder, "| %s | %s | %s | %s | %s | %s | %s |\n", markdown(change.ReviewLevel), markdownCode(change.RuleID), markdownCode(change.Behavior.Type), markdownCode(change.Behavior.Target), markdownCode(evidenceLabel(change.Behavior)), markdown(techniqueLabel(change.Techniques)), markdown(change.Reason))
	}
	if len(diff.Added) == 0 {
		builder.WriteString("| none | none | none | none | none | none | No added observed behavior |\n")
	}
	if len(diff.AddedSequences) > 0 {
		builder.WriteString("\n## Added observed sequences\n\n")
		for _, sequence := range diff.AddedSequences {
			fmt.Fprintf(&builder, "* %s: %s\n", markdownCode(sequence.ID), markdownCode(strings.Join(sequence.BehaviorIDs, " -> ")))
		}
	}
	if len(diff.Removed) > 0 {
		builder.WriteString("\n## Removed observed behavior\n\n")
		builder.WriteString("| Behavior | Target | Evidence |\n")
		builder.WriteString("| --- | --- | --- |\n")
		for _, behavior := range diff.Removed {
			fmt.Fprintf(&builder, "| %s | %s | %s |\n", markdownCode(behavior.Type), markdownCode(behavior.Target), markdownCode(evidenceLabel(behavior)))
		}
	}
	if len(diff.RemovedSequences) > 0 {
		builder.WriteString("\n## Removed observed sequences\n\n")
		for _, sequence := range diff.RemovedSequences {
			fmt.Fprintf(&builder, "* %s: %s\n", markdownCode(sequence.ID), markdownCode(strings.Join(sequence.BehaviorIDs, " -> ")))
		}
	}
	builder.WriteString("\n## Limitations\n\n")
	for _, limitation := range diff.Limitations {
		fmt.Fprintf(&builder, "* %s\n", markdown(limitation))
	}
	fmt.Fprintf(&builder, "\nThis report compares behavior exercised during the selected npm %s phase. It does not classify malware or prove that either package version is safe.\n", markdown(diff.Phase))
	return builder.String()
}

func techniqueLabel(techniques []model.TechniqueRef) string {
	if len(techniques) == 0 {
		return ""
	}
	labels := make([]string, 0, len(techniques))
	for _, technique := range techniques {
		labels = append(labels, fmt.Sprintf("%s %s %s", technique.Relationship, technique.Framework, technique.ID))
	}
	return strings.Join(labels, "; ")
}

func evidenceLabel(behavior model.Behavior) string {
	if len(behavior.Evidence) == 0 {
		return "none"
	}
	ref := behavior.Evidence[0]
	digest := strings.TrimPrefix(ref.ArtifactSHA256, "sha256:")
	if len(digest) > 12 {
		digest = digest[:12]
	}
	label := fmt.Sprintf("sha256:%s:L%d", digest, ref.Line)
	if len(behavior.Evidence) > 1 {
		label += fmt.Sprintf(" (+%d refs)", len(behavior.Evidence)-1)
	}
	return label
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
	_, _ = io.WriteString(writer, `BehaviorLock compares observed npm behavior during compatible bounded phases between exact package versions.

Usage:
  behaviorlock doctor
  behaviorlock capture --experimental --package name@1.2.3 --phase lifecycle --output profile.json [--evidence-output raw.strace]
  behaviorlock capture --experimental --package name@1.2.3 --phase import --output import.json [--sinkhole]
  behaviorlock profile --package name@1.2.3 --trace raw.strace --output profile.json [--evidence-output retained.strace]
  behaviorlock compare --baseline old.json --candidate new.json --output report.json [--baseline-evidence old.strace --candidate-evidence new.strace]
  behaviorlock compare --allow-external --baseline old.json --candidate new.json
  behaviorlock validate --profile profile.json [--evidence raw.strace]
  behaviorlock version

Exit codes:
  0  completed and policy threshold not reached
  1  observed changes reached the configured review threshold
  2  invalid input, incomplete trace, sandbox failure, or runtime error
`)
}
