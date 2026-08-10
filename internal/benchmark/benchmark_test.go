package benchmark

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repositoryManifest(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "benchmark", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunMatchesEveryDeclaredCorpusExpectation(t *testing.T) {
	t.Parallel()
	report, err := Run(repositoryManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Observed.ExpectationsMatched || report.Observed.CasesEvaluated != 4 || report.Observed.CasesMatched != 4 {
		t.Fatalf("unexpected observed report: %#v", report.Observed)
	}
	if len(report.ProjectedHistoricalCoverage) != 1 || report.ProjectedHistoricalCoverage[0].Status != "projection-only" {
		t.Fatalf("historical projection was not kept separate: %#v", report.ProjectedHistoricalCoverage)
	}
}

func TestRunCaseFailsClosedWhenExpectationDrifts(t *testing.T) {
	t.Parallel()
	manifestPath := repositoryManifest(t)
	manifest, _, err := Load(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	drifted := manifest.Cases[0]
	drifted.Expected.RuleIDs = []string{"BL900"}
	_, err = runCase(filepath.Dir(manifestPath), drifted)
	if err == nil || !strings.Contains(err.Error(), "rule identifiers changed") {
		t.Fatalf("expectation drift was not rejected: %v", err)
	}
}

func TestLoadRejectsUnknownFieldsAndMultipleValues(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(repositoryManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown": func(value []byte) []byte {
			return []byte(strings.Replace(string(value), `"schemaVersion": 1,`, `"schemaVersion": 1, "unexpected": true,`, 1))
		},
		"multiple": func(value []byte) []byte { return append(value, []byte("\n{}\n")...) },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, mutate(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := Load(path); err == nil {
				t.Fatal("malformed manifest unexpectedly loaded")
			}
		})
	}
}

func TestConfinedTracePathRejectsEscapeAndSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	corpus := filepath.Join(root, "corpus")
	if err := os.Mkdir(corpus, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.strace")
	if err := os.WriteFile(outside, []byte("execve(\"/bin/true\", [\"true\"], 0x0) = 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := confinedTracePath(root, "../outside.strace"); err == nil {
		t.Fatal("path escape unexpectedly accepted")
	}
	symlink := filepath.Join(corpus, "linked.strace")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := confinedTracePath(root, "corpus/linked.strace"); err == nil {
		t.Fatal("symlink fixture unexpectedly accepted")
	}
}

func TestMarkdownKeepsProjectionDisclaimer(t *testing.T) {
	t.Parallel()
	report, err := Run(repositoryManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	markdown := RenderMarkdown(report)
	if !strings.Contains(markdown, "not executed and are not demonstrated detections") || !strings.Contains(markdown, "projection only") {
		t.Fatalf("projection disclaimer missing:\n%s", markdown)
	}
}
