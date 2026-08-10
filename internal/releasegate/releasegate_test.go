package releasegate

import (
	"fmt"
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
