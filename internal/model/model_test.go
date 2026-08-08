package model

import (
	"os"
	"path/filepath"
	"testing"
)

func testProfile() Profile {
	profile := NewProfile(Subject{
		Ecosystem:            "npm",
		Name:                 "example",
		Version:              "1.2.3",
		PURL:                 "pkg:npm/example@1.2.3",
		RegistryIntegrity:    "sha512-test",
		DependencyLockSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, "test")
	profile.Capture.RunnerImage = "behaviorlock-runner:test"
	profile.Capture.RunnerImageID = "sha256:runner"
	profile.Capture.Architecture = "amd64"
	profile.Capture.NodeVersion = "v22.1.0"
	profile.Capture.NPMVersion = "10.8.0"
	profile.Capture.StraceVersion = "6.1"
	profile.Capture.RawTraceSHA256 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	profile.Result = Result{Status: "complete", ExitCode: 0}
	profile.Behaviors = []Behavior{{Type: "process.exec", Operation: "exec", Target: "/bin/true", Outcome: "success", Count: 1, SourceCall: "execve"}}
	profile.Normalize()
	return profile
}

func TestNormalizeAggregatesAndSortsBehaviors(t *testing.T) {
	t.Parallel()
	profile := testProfile()
	first := Behavior{Type: "process.exec", Operation: "exec", Target: "/bin/z", Outcome: "success", Count: 1, Evidence: "trace:L2", SourceCall: "execve"}
	second := Behavior{Type: "filesystem.read", Operation: "read", Target: "/etc/hosts", Outcome: "success", Count: 1, Evidence: "trace:L1", SourceCall: "openat"}
	profile.Behaviors = []Behavior{first, second, first}
	profile.Normalize()
	if len(profile.Behaviors) != 2 {
		t.Fatalf("behavior count = %d", len(profile.Behaviors))
	}
	if profile.Behaviors[0].Type != "filesystem.read" || profile.Behaviors[1].Count != 2 {
		t.Fatalf("unexpected normalized behaviors: %#v", profile.Behaviors)
	}
}

func TestStableDigestIgnoresOnlyDuration(t *testing.T) {
	t.Parallel()
	left := testProfile()
	right := testProfile()
	left.Capture.DurationMillis = 12
	right.Capture.DurationMillis = 999
	left.Capture.RawTraceSHA256 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	right.Capture.RawTraceSHA256 = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	left.Behaviors[0].Count = 1
	right.Behaviors[0].Count = 99
	leftDigest, err := left.StableDigest()
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := right.StableDigest()
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatal("duration changed the stable digest")
	}
	if right.Behaviors[0].Count != 99 {
		t.Fatal("stable digest mutated the source profile")
	}
	right.Subject.Version = "1.2.4"
	changedDigest, err := right.StableDigest()
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == leftDigest {
		t.Fatal("subject change did not change the stable digest")
	}
}

func TestReadWriteProfileRoundTripAndPermissions(t *testing.T) {
	t.Parallel()
	profile := testProfile()
	filePath := filepath.Join(t.TempDir(), "profile.json")
	if err := WriteJSON(filePath, profile); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("profile permissions = %o", got)
	}
	decoded, err := ReadProfile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Subject.PURL != profile.Subject.PURL || decoded.Result.Status != "complete" {
		t.Fatalf("round trip changed profile: %#v", decoded)
	}
}

func TestReadProfileRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	filePath := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(filePath, []byte(`{"schemaVersion":"1.0.0","kind":"npm.install.profile","unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProfile(filePath); err == nil {
		t.Fatal("unknown profile field unexpectedly succeeded")
	}
}

func TestReadProfileRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	profile := testProfile()
	filePath := filepath.Join(t.TempDir(), "profile.json")
	if err := WriteJSON(filePath, profile); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{}\n"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProfile(filePath); err == nil {
		t.Fatal("trailing JSON unexpectedly succeeded")
	}
}

func TestValidateProfileRejectsControlCharacters(t *testing.T) {
	t.Parallel()
	profile := testProfile()
	profile.Behaviors[0].Target = "safe\nworkflow-command"
	profile.Behaviors[0].Evidence = StableEvidence(profile.Behaviors[0])
	if err := ValidateProfile(profile); err == nil {
		t.Fatal("control characters unexpectedly validated")
	}
}

func TestValidateProfileRejectsContradictoryCompletion(t *testing.T) {
	t.Parallel()
	profile := testProfile()
	profile.Result.TimedOut = true
	if err := ValidateProfile(profile); err == nil {
		t.Fatal("timed out complete profile unexpectedly validated")
	}
}

func TestSeverityRanksAreOrdered(t *testing.T) {
	t.Parallel()
	levels := []string{"none", "low", "medium", "high", "critical"}
	for index := 1; index < len(levels); index++ {
		if SeverityRank(levels[index]) <= SeverityRank(levels[index-1]) {
			t.Fatalf("severity order is invalid at %q", levels[index])
		}
	}
}
