package releasegate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func validFixture(now time.Time) (Config, Evidence) {
	config := Config{SchemaVersion: 1, MaxAgeHours: 24}
	evidence := Evidence{
		SchemaVersion: 1, Repository: "kiranmagic7/behaviorlock", SourceSHA: testSHA, GeneratedAt: now.Add(-time.Minute),
	}
	for gate := 1; gate <= 14; gate++ {
		id := fmt.Sprintf("gate-%02d", gate)
		check := id + "-proof"
		config.Proofs = append(config.Proofs, RequiredProof{ID: id, Check: check, Description: "required proof"})
		evidence.Proofs = append(evidence.Proofs, ObservedProof{
			ID: id, Check: check, Status: "completed", Conclusion: "success", SourceSHA: testSHA,
			CompletedAt: now.Add(-time.Minute), DetailsURL: "https://github.com/kiranmagic7/behaviorlock/actions/runs/123/jobs/456",
		})
	}
	return config, evidence
}

func TestVerifyAcceptsFreshExactProofSet(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	config, evidence := validFixture(now)
	if err := Verify(config, evidence, evidence.Repository, testSHA, now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFailsClosedForMissingSkippedFailedOrStaleProof(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*Evidence){
		"missing": func(value *Evidence) { value.Proofs = value.Proofs[1:] },
		"skipped": func(value *Evidence) { value.Proofs[0].Conclusion = "skipped" },
		"failed":  func(value *Evidence) { value.Proofs[0].Conclusion = "failure" },
		"stale":   func(value *Evidence) { value.Proofs[0].CompletedAt = now.Add(-25 * time.Hour) },
		"wrong sha": func(value *Evidence) {
			value.Proofs[0].SourceSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		"untrusted URL": func(value *Evidence) { value.Proofs[0].DetailsURL = "https://attacker.invalid/actions/runs/123" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			config, evidence := validFixture(now)
			mutate(&evidence)
			if err := Verify(config, evidence, evidence.Repository, testSHA, now); err == nil {
				t.Fatal("invalid proof set unexpectedly passed")
			}
		})
	}
}

func TestVerifyRejectsUnexpectedOrDuplicateProofs(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	config, evidence := validFixture(now)
	evidence.Proofs = append(evidence.Proofs, evidence.Proofs[0])
	if err := Verify(config, evidence, evidence.Repository, testSHA, now); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate proof was not rejected: %v", err)
	}
}

func TestAssessEnumeratesEveryUnsatisfiedGate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	config, evidence := validFixture(now)
	evidence.Proofs[0].Conclusion = "skipped"
	evidence.Proofs[1].Conclusion = "failure"
	evidence.Proofs = evidence.Proofs[:13]
	report, err := Assess(config, evidence, evidence.Repository, testSHA, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.AllGatesSatisfied || report.GatesSatisfied != 11 || len(report.Gates) != 14 {
		t.Fatalf("unexpected gate summary: %#v", report)
	}
	if report.Gates[0].Reason == "" || report.Gates[1].Reason == "" || report.Gates[13].Reason != "is missing" {
		t.Fatalf("blocked reasons were not preserved: %#v", report.Gates)
	}
	markdown := RenderMarkdown(report)
	if !strings.Contains(markdown, "11 of 14") || !strings.Contains(markdown, "cannot authorize a tag") {
		t.Fatalf("release report omitted its status or authority boundary:\n%s", markdown)
	}
}

func TestAssessRejectsStaleManifestWithoutHidingGateEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	config, evidence := validFixture(now)
	evidence.GeneratedAt = now.Add(-25 * time.Hour)
	report, err := Assess(config, evidence, evidence.Repository, testSHA, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.AllGatesSatisfied || len(report.Issues) != 1 || !strings.Contains(report.Issues[0], "stale") {
		t.Fatalf("stale manifest did not block the report: %#v", report)
	}
}

func TestAssessListsUnexpectedAndDuplicateEvidenceAsIssues(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	config, evidence := validFixture(now)
	evidence.Proofs = append(evidence.Proofs, evidence.Proofs[0], ObservedProof{ID: "gate-99"})
	report, err := Assess(config, evidence, evidence.Repository, testSHA, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.AllGatesSatisfied || len(report.Issues) != 2 {
		t.Fatalf("malformed evidence issues were not retained: %#v", report.Issues)
	}
}

func TestDecodeStrictRejectsSymlinksAndOversizedInputs(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "linked.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var decoded map[string]any
	if err := decodeStrict(link, &decoded); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink input was not rejected: %v", err)
	}

	oversized := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversized, make([]byte, maxInputBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict(oversized, &decoded); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized input was not rejected: %v", err)
	}
}
