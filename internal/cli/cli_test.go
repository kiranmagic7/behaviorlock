package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kiranmagic7/behaviorlock/internal/model"
)

func TestUnknownCommandFails(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"unknown"}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit = %d", exit)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCaptureRequiresExplicitExperimentalAcknowledgement(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"capture", "--package", "example@1.0.0"}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit = %d", exit)
	}
	if !strings.Contains(stderr.String(), "requires --experimental") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestProfileAndValidateRawTrace(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	tracePath := filepath.Join(directory, "trace")
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(tracePath, []byte("execve(\"/usr/bin/node\", [\"node\"], 0x0) = 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"profile", "--package", "example@1.0.0", "--trace", tracePath, "--output", profilePath}, &stdout, &stderr); exit != 0 {
		t.Fatalf("profile exit=%d stderr=%s", exit, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"validate", "--profile", profilePath}, &stdout, &stderr); exit != 0 {
		t.Fatalf("validate exit=%d stderr=%s", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pkg:npm/example@1.0.0") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestProfileRejectsEmptyExternalTrace(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	tracePath := filepath.Join(directory, "trace")
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(tracePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"profile", "--package", "example@1.0.0", "--trace", tracePath, "--output", profilePath}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit = %d", exit)
	}
	if !strings.Contains(stderr.String(), "no recognized events") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestProfileStdoutRequiresSeparateEvidenceOutput(t *testing.T) {
	t.Parallel()
	tracePath := filepath.Join(t.TempDir(), "trace")
	if err := os.WriteFile(tracePath, []byte("execve(\"/usr/bin/node\", [\"node\"], 0x0) = 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"profile", "--package", "example@1.0.0", "--trace", tracePath}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit = %d", exit)
	}
	if !strings.Contains(stderr.String(), "requires an explicit --evidence-output") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestValidateRejectsTamperedEvidence(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	tracePath := filepath.Join(directory, "trace")
	profilePath := filepath.Join(directory, "profile.json")
	evidencePath := profilePath + ".evidence.strace"
	if err := os.WriteFile(tracePath, []byte("execve(\"/usr/bin/node\", [\"node\"], 0x0) = 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"profile", "--package", "example@1.0.0", "--trace", tracePath, "--output", profilePath}, &stdout, &stderr); exit != 0 {
		t.Fatalf("profile exit=%d stderr=%s", exit, stderr.String())
	}
	if err := os.WriteFile(evidencePath, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"validate", "--profile", profilePath}, &stdout, &stderr); exit != 2 {
		t.Fatalf("validate exit=%d stderr=%s", exit, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not match") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestHumanReportsCarryEvidenceReferencesWithoutVerdicts(t *testing.T) {
	t.Parallel()
	behavior := model.Behavior{
		Type: "network.connect", Operation: "connect", Target: "AF_INET:198.51.100.1:443",
		Outcome: "blocked", Count: 1, ID: "event:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Evidence: []model.EvidenceRef{{
			ArtifactSHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Line:           7,
			LineSHA256:     "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		}},
		SourceCall: "connect",
	}
	diff := model.Diff{
		Baseline:  model.Subject{Name: "example", Version: "1.0.0"},
		Candidate: model.Subject{Name: "example", Version: "1.1.0"},
		Added:     []model.Change{{ReviewLevel: "high", RuleID: "BL200", Reason: "new network attempt", Behavior: behavior}},
		Summary:   model.DiffSummary{Added: 1, ReviewRequired: true, HighestReviewLevel: "high"},
	}
	for name, rendered := range map[string]string{"text": renderText(diff), "markdown": renderMarkdown(diff)} {
		if !strings.Contains(rendered, "sha256:bbbbbbbbbbbb:L7") {
			t.Fatalf("%s report omitted evidence reference: %q", name, rendered)
		}
		if strings.Contains(strings.ToLower(rendered), "verdict") {
			t.Fatalf("%s report still contains verdict language: %q", name, rendered)
		}
	}
}
