package model

import (
	"os"
	"path/filepath"
	"testing"
)

const testRegistryIntegrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

var testRawEvidence = []byte("execve(\"/bin/true\", [\"true\"], 0x0) = 0\n")

func testProfile() Profile {
	profile := NewProfile(Subject{
		Ecosystem:            "npm",
		Name:                 "example",
		Version:              "1.2.3",
		PURL:                 "pkg:npm/example@1.2.3",
		RegistryIntegrity:    testRegistryIntegrity,
		DependencyLockSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, "test")
	profile.Capture.RunnerImage = "behaviorlock-runner:test"
	profile.Capture.RunnerImageID = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	profile.Capture.Architecture = "amd64"
	profile.Capture.NodeVersion = "v22.1.0"
	profile.Capture.NPMVersion = "10.8.0"
	profile.Capture.StraceVersion = "6.1"
	profile.Capture.Acquisition = &AcquisitionInfo{
		NetworkMode: "registry-proxy-unix", PolicyVersion: "npm-registry-connect-v1",
		AllowedAuthority: "registry.npmjs.org:443", ProxyRunnerImageID: profile.Capture.RunnerImageID,
	}
	profile.Result = Result{Status: "complete", ExitCode: 0}
	profile.Behaviors = []Behavior{{
		Type: "process.exec", Operation: "exec", Target: "/bin/true", Outcome: "success", Count: 1,
		Evidence: []EvidenceRef{NewEvidenceRef(1, testRawEvidence)}, SourceCall: "execve",
	}}
	AttachEvidence(&profile, testRawEvidence, "retained", "behaviorlock-trace-v1-payload")
	profile.Normalize()
	return profile
}

func TestNormalizeAggregatesAndSortsBehaviors(t *testing.T) {
	t.Parallel()
	profile := testProfile()
	first := Behavior{Type: "process.exec", Operation: "exec", Target: "/bin/z", Outcome: "success", Count: 1, Evidence: []EvidenceRef{NewEvidenceRef(2, []byte("exec-z"))}, SourceCall: "execve"}
	second := Behavior{Type: "filesystem.read", Operation: "read", Target: "/etc/hosts", Outcome: "success", Count: 1, Evidence: []EvidenceRef{NewEvidenceRef(1, []byte("read-hosts"))}, SourceCall: "openat"}
	profile.Behaviors = []Behavior{first, second, first}
	profile.Normalize()
	if len(profile.Behaviors) != 2 {
		t.Fatalf("behavior count = %d", len(profile.Behaviors))
	}
	if profile.Behaviors[0].Type != "filesystem.read" || profile.Behaviors[1].Count != 2 {
		t.Fatalf("unexpected normalized behaviors: %#v", profile.Behaviors)
	}
}

func TestStableDigestIgnoresCaptureNoiseAndEvidenceCoordinates(t *testing.T) {
	t.Parallel()
	left := testProfile()
	right := testProfile()
	left.Capture.DurationMillis = 12
	right.Capture.DurationMillis = 999
	AttachEvidence(&right, []byte("different raw trace bytes\n"), "retained", "behaviorlock-trace-v1-payload")
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
		t.Fatal("capture noise or evidence coordinates changed the stable digest")
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

func TestStableDigestIncludesAcquisitionPolicyFingerprint(t *testing.T) {
	t.Parallel()
	left := testProfile()
	right := testProfile()
	right.Capture.Acquisition.PolicyVersion = "npm-registry-connect-v2"
	leftDigest, err := left.StableDigest()
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := right.StableDigest()
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest == rightDigest {
		t.Fatal("acquisition policy change did not change the stable digest")
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
	if err := os.WriteFile(filePath, []byte(`{"schemaVersion":"2.0.0","kind":"npm.install.profile","unexpected":true}`), 0o600); err != nil {
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
	profile.Behaviors[0].ID = StableBehaviorID(profile.Behaviors[0])
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

func TestValidateProfileRejectsMalformedAcquisitionEvidence(t *testing.T) {
	t.Parallel()
	profile := testProfile()
	profile.Subject.RegistryIntegrity = "sha512-not-a-real-digest"
	if err := ValidateProfile(profile); err == nil {
		t.Fatal("malformed registry integrity unexpectedly validated")
	}
	profile = testProfile()
	profile.Capture.RunnerImageID = "behaviorlock-runner:mutable"
	if err := ValidateProfile(profile); err == nil {
		t.Fatal("mutable runner image reference unexpectedly validated as an ID")
	}
	profile = testProfile()
	profile.Capture.Acquisition = nil
	if err := ValidateProfile(profile); err == nil {
		t.Fatal("captured profile without an acquisition egress fingerprint unexpectedly validated")
	}
}

func TestValidateProfileRejectsUnsafeCoverage(t *testing.T) {
	t.Parallel()
	profile := testProfile()
	profile.Capture.Coverage.Limitations = []string{"unsafe\nworkflow command"}
	if err := ValidateProfile(profile); err == nil {
		t.Fatal("unsafe coverage limitation unexpectedly validated")
	}
	profile = testProfile()
	profile.Capture.Coverage.Completeness = "complete"
	if err := ValidateProfile(profile); err == nil {
		t.Fatal("unsupported coverage completeness unexpectedly validated")
	}
}

func TestReviewLevelRanksAreOrdered(t *testing.T) {
	t.Parallel()
	levels := []string{"none", "low", "medium", "high", "critical"}
	for index := 1; index < len(levels); index++ {
		if ReviewLevelRank(levels[index]) <= ReviewLevelRank(levels[index-1]) {
			t.Fatalf("review level order is invalid at %q", levels[index])
		}
	}
}

func TestVerifyEvidenceRejectsTampering(t *testing.T) {
	t.Parallel()
	profile := testProfile()
	if err := VerifyEvidence(profile, testRawEvidence); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidence(profile, []byte("execve(\"/bin/false\", [\"false\"], 0x0) = 0\n")); err == nil {
		t.Fatal("tampered raw evidence unexpectedly verified")
	}
}

func TestReadProfileRejectsHistoricalSchema(t *testing.T) {
	t.Parallel()
	filePath := filepath.Join(t.TempDir(), "profile-v1.json")
	if err := os.WriteFile(filePath, []byte(`{"schemaVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProfile(filePath); err == nil {
		t.Fatal("historical profile unexpectedly read as current")
	}
}
