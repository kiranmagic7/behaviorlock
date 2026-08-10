package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kiranmagic7/behaviorlock/internal/reviewci"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "behaviorlock review-ci: %s\n", err)
		os.Exit(2)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("expected extract, bundle, or verify")
	}
	switch arguments[0] {
	case "extract":
		return runExtract(arguments[1:])
	case "bundle":
		return runBundle(arguments[1:])
	case "verify":
		return runVerify(arguments[1:])
	default:
		return fmt.Errorf("unsupported command %q", arguments[0])
	}
}

func runExtract(arguments []string) error {
	flags := flag.NewFlagSet("extract", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	eventPath := flags.String("event", "", "pull_request event JSON")
	outputPath := flags.String("output", "", "review plan path")
	githubOutput := flags.String("github-output", "", "GitHub output file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *eventPath == "" || *outputPath == "" {
		return errors.New("extract requires --event and --output")
	}
	raw, err := readFile(*eventPath, 4<<20)
	if err != nil {
		return err
	}
	reference, err := reviewci.ParsePullRequestEvent(raw)
	if err != nil {
		return err
	}
	client, err := githubClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	baseline, err := optionalManifest(ctx, client, reference.BaseRepository, reference.BaseSHA)
	if err != nil {
		return err
	}
	candidate, err := optionalManifest(ctx, client, reference.HeadRepository, reference.HeadSHA)
	if err != nil {
		return err
	}
	plan, err := reviewci.BuildPlan(reference, baseline, candidate)
	if err != nil {
		return err
	}
	if err := reviewci.WritePlan(*outputPath, plan); err != nil {
		return err
	}
	return appendOutputs(*githubOutput, map[string]string{
		"baseline-package":  plan.BaselinePackage,
		"candidate-package": plan.CandidatePackage,
		"plan-path":         *outputPath,
		"skipped":           strconv.FormatBool(plan.Skipped),
	})
}

func runBundle(arguments []string) error {
	flags := flag.NewFlagSet("bundle", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "flat artifact directory")
	threshold := flags.String("threshold", "high", "review threshold")
	githubOutput := flags.String("github-output", "", "GitHub output file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *directory == "" {
		return errors.New("bundle requires --directory")
	}
	runID, err := reviewci.ParseRunID(os.Getenv("GITHUB_RUN_ID"))
	if err != nil {
		return err
	}
	runAttempt, err := strconv.Atoi(os.Getenv("GITHUB_RUN_ATTEMPT"))
	if err != nil || runAttempt < 1 {
		return errors.New("workflow run attempt is invalid")
	}
	manifest, err := reviewci.BuildArtifact(*directory, reviewci.RunIdentity{
		Repository: os.Getenv("GITHUB_REPOSITORY"), RunID: runID, RunAttempt: runAttempt, SourceRunSHA: os.Getenv("GITHUB_SHA"),
	}, *threshold)
	if err != nil {
		return err
	}
	values := map[string]string{
		"threshold-reached":       strconv.FormatBool(manifest.Result.ThresholdReached),
		"highest-review-level":    manifest.Result.HighestReviewLevel,
		"added-count":             strconv.Itoa(manifest.Result.AddedCount),
		"skipped":                 strconv.FormatBool(manifest.Result.Skipped),
		"baseline-profile-path":   outputPath(*directory, manifest.Result.BaselineProfilePath),
		"baseline-evidence-path":  outputPath(*directory, manifest.Result.BaselineEvidencePath),
		"candidate-profile-path":  outputPath(*directory, manifest.Result.CandidateProfilePath),
		"candidate-evidence-path": outputPath(*directory, manifest.Result.CandidateEvidencePath),
		"diff-path":               outputPath(*directory, manifest.Result.DiffPath),
	}
	return appendOutputs(*githubOutput, values)
}

func runVerify(arguments []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	eventPath := flags.String("event", "", "workflow_run event JSON")
	directory := flags.String("directory", "", "downloaded flat artifact directory")
	commentPath := flags.String("comment", "", "sanitized comment output")
	githubOutput := flags.String("github-output", "", "GitHub output file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *eventPath == "" || *directory == "" || *commentPath == "" {
		return errors.New("verify requires --event, --directory, and --comment")
	}
	raw, err := readFile(*eventPath, 4<<20)
	if err != nil {
		return err
	}
	source, err := reviewci.ParseWorkflowRunEvent(raw)
	if err != nil {
		return err
	}
	client, err := githubClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	manifest, comment, err := reviewci.VerifyArtifact(ctx, *directory, source, client)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*commentPath, []byte(comment), 0o600); err != nil {
		return err
	}
	return appendOutputs(*githubOutput, map[string]string{
		"pull-request-number": strconv.Itoa(manifest.Plan.Number),
		"comment-path":        *commentPath,
	})
}

func githubClient() (*reviewci.GitHubClient, error) {
	return reviewci.NewGitHubClient(os.Getenv("GITHUB_API_URL"), os.Getenv("GITHUB_TOKEN"), &http.Client{Timeout: 30 * time.Second})
}

func optionalManifest(ctx context.Context, client *reviewci.GitHubClient, repository, revision string) ([]byte, error) {
	raw, err := client.FetchManifest(ctx, repository, revision)
	if errors.Is(err, reviewci.ErrNotFound) {
		return nil, nil
	}
	return raw, err
}

func appendOutputs(path string, values map[string]string) error {
	if path == "" {
		return nil
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- GitHub supplies the explicit output file.
	if err != nil {
		return err
	}
	defer file.Close()
	keys := []string{
		"added-count", "baseline-evidence-path", "baseline-package", "baseline-profile-path", "candidate-evidence-path",
		"candidate-package", "candidate-profile-path", "comment-path", "diff-path", "highest-review-level", "plan-path",
		"pull-request-number", "skipped", "threshold-reached",
	}
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("output %s contains a forbidden control character", key)
		}
		if _, err := fmt.Fprintf(file, "%s=%s\n", key, value); err != nil {
			return err
		}
	}
	return nil
}

func readFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- event path is an explicit workflow input.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("input file exceeded its bound")
	}
	return raw, nil
}

func outputPath(directory, name string) string {
	if name == "" {
		return ""
	}
	return filepath.Join(directory, name)
}
