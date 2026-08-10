package compare

import (
	"strings"
	"testing"

	"github.com/kiranmagic7/behaviorlock/internal/model"
)

const testRegistryIntegrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

func completeProfile(version string, behaviors ...model.Behavior) model.Profile {
	profile := model.NewProfile(model.Subject{
		Ecosystem: "npm", Name: "example", Version: version, PURL: "pkg:npm/example@" + version,
		RegistryIntegrity: testRegistryIntegrity, DependencyLockSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, "test")
	profile.Capture.RunnerImage = "behaviorlock-runner:test"
	profile.Capture.RunnerImageID = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	profile.Capture.Architecture = "amd64"
	profile.Capture.NodeVersion = "v22.1.0"
	profile.Capture.NPMVersion = "10.8.0"
	profile.Capture.StraceVersion = "6.1"
	profile.Capture.Acquisition = &model.AcquisitionInfo{
		NetworkMode: "registry-proxy-unix", PolicyVersion: "npm-registry-connect-v1",
		AllowedAuthority: "registry.npmjs.org:443", ProxyRunnerImageID: profile.Capture.RunnerImageID,
	}
	profile.Result = model.Result{Status: "complete", ExitCode: 0}
	harness := model.Behavior{Type: "process.exec", Operation: "exec", Target: "/usr/bin/npm", Outcome: "success", Count: 1, SourceCall: "execve"}
	profile.Behaviors = append([]model.Behavior{harness}, behaviors...)
	raw := []byte("evidence-1\nevidence-2\nevidence-3\nevidence-4\n")
	lines := [][]byte{[]byte("evidence-1\n"), []byte("evidence-2\n"), []byte("evidence-3\n"), []byte("evidence-4\n")}
	for index := range profile.Behaviors {
		profile.Behaviors[index].Evidence = []model.EvidenceRef{model.NewEvidenceRef(index+1, lines[index])}
	}
	model.AttachEvidence(&profile, raw, "retained", "behaviorlock-trace-v1-payload")
	profile.Normalize()
	return profile
}

func TestProfilesFlagsNewSensitiveRead(t *testing.T) {
	t.Parallel()
	baseline := completeProfile("1.0.0")
	candidate := completeProfile("1.1.0", model.Behavior{
		Type: "filesystem.read", Operation: "read", Target: "$HOME/.ssh/id_rsa",
		Outcome: "blocked", Errno: "EACCES", Sensitive: true, Count: 1, SourceCall: "openat",
	})
	diff, err := Profiles(baseline, candidate, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Summary.ReviewRequired || diff.Summary.HighestReviewLevel != "critical" || len(diff.Added) != 1 {
		t.Fatalf("unexpected diff summary: %#v", diff.Summary)
	}
}

func TestProfilesRejectsIncompleteTrace(t *testing.T) {
	t.Parallel()
	baseline := completeProfile("1.0.0")
	candidate := completeProfile("1.1.0")
	candidate.Result.Status = "trace_incomplete"
	if _, err := Profiles(baseline, candidate, "test"); err == nil {
		t.Fatal("expected incomplete candidate to fail")
	}
}

func TestProfilesAreDeterministic(t *testing.T) {
	t.Parallel()
	a := model.Behavior{Type: "filesystem.read", Operation: "read", Target: "/etc/hosts", Outcome: "success", Count: 1, SourceCall: "openat"}
	b := model.Behavior{Type: "process.exec", Operation: "exec", Target: "/usr/bin/node", Outcome: "success", Count: 1, SourceCall: "execve"}
	left, err := Profiles(completeProfile("1.0.0"), completeProfile("1.1.0", a, b), "test")
	if err != nil {
		t.Fatal(err)
	}
	right, err := Profiles(completeProfile("1.0.0"), completeProfile("1.1.0", b, a), "test")
	if err != nil {
		t.Fatal(err)
	}
	if left.CandidateDigest != right.CandidateDigest || left.Added[0].RuleID != right.Added[0].RuleID {
		t.Fatalf("comparison was not deterministic: %#v vs %#v", left, right)
	}
}

func TestProfilesRequireExplicitExternalAcknowledgement(t *testing.T) {
	t.Parallel()
	baseline := completeProfile("1.0.0")
	candidate := completeProfile("1.1.0")
	for _, profile := range []*model.Profile{&baseline, &candidate} {
		profile.Capture.TraceIntegrity = "external-unverified"
		profile.Capture.NetworkMode = "unknown"
		profile.Capture.SandboxProfile = "external-unverified"
		profile.Capture.Coverage.Scope = "external-strace"
		profile.Capture.Coverage.Completeness = "unverified"
		profile.Capture.Coverage.Lifecycle = []string{}
		profile.Capture.Acquisition = nil
		profile.Capture.EvidenceArtifact.Retention = "external-unverified"
		profile.Capture.EvidenceArtifact.Envelope = "external-strace"
		profile.Subject.RegistryIntegrity = ""
		profile.Subject.DependencyLockSHA256 = ""
	}
	if _, err := Profiles(baseline, candidate, "test"); err == nil {
		t.Fatal("external profiles unexpectedly compared without acknowledgement")
	}
	if _, err := ProfilesWithOptions(baseline, candidate, "test", Options{AllowExternal: true}); err != nil {
		t.Fatal(err)
	}
}

func TestProfilesRejectDifferentRunnerReferencesForSameContentID(t *testing.T) {
	t.Parallel()
	baseline := completeProfile("1.0.0")
	candidate := completeProfile("1.1.0")
	candidate.Capture.RunnerImage = "ghcr.io/kiranmagic7/behaviorlock-runner:v0.1.0"
	if _, err := Profiles(baseline, candidate, "test"); err == nil || !strings.Contains(err.Error(), "runner image reference") {
		t.Fatalf("different runner references were not rejected: %v", err)
	}
}
