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

func TestProfilesFlagsNewEnvironmentFingerprintRead(t *testing.T) {
	t.Parallel()
	baseline := completeProfile("1.0.0")
	candidate := completeProfile("1.1.0", model.Behavior{
		Type: "filesystem.read", Operation: "inspect", Target: "/proc/self/status",
		Outcome: "success", Count: 1, SourceCall: "openat",
	})
	diff, err := Profiles(baseline, candidate, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Summary.ReviewRequired || diff.Summary.HighestReviewLevel != "medium" || len(diff.Added) != 1 {
		t.Fatalf("unexpected diff summary: %#v", diff.Summary)
	}
	change := diff.Added[0]
	if change.RuleID != "BL600" || change.ReviewLevel != "medium" {
		t.Fatalf("unexpected environment fingerprint classification: %#v", change)
	}
	if len(change.Techniques) != 1 || change.Techniques[0].Relationship != "consistent with" || change.Techniques[0].ID != "T1497.001" {
		t.Fatalf("optional technique context became missing or classificatory: %#v", change.Techniques)
	}
}

func TestClassifyEnvironmentFingerprintPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		target  string
		outcome string
	}{
		{name: "docker marker", target: "/.dockerenv", outcome: "success"},
		{name: "container marker", target: "/run/.containerenv", outcome: "failed"},
		{name: "init cgroup", target: "/proc/$PID/cgroup", outcome: "success"},
		{name: "tracer status", target: "/proc/self/status", outcome: "success"},
		{name: "mount layout", target: "/proc/self/mountinfo", outcome: "blocked"},
		{name: "cpu characteristics", target: "/proc/cpuinfo", outcome: "success"},
		{name: "memory characteristics", target: "/proc/meminfo", outcome: "success"},
		{name: "system uptime", target: "/proc/uptime", outcome: "success"},
		{name: "dmi root", target: "/sys/class/dmi", outcome: "success"},
		{name: "dmi child", target: "/sys/class/dmi/id/product_name", outcome: "success"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			risk, ruleID, reason := classify(model.Behavior{
				Type: "filesystem.read", Operation: "inspect", Target: test.target,
				Outcome: test.outcome, Count: 1, SourceCall: "openat",
			})
			if risk != "medium" || ruleID != "BL600" || reason != "new access to a path commonly used to detect containers or tracing" {
				t.Fatalf("classification = %q %q %q", risk, ruleID, reason)
			}
		})
	}
}

func TestClassifyEnvironmentFingerprintPathsRequiresBoundaries(t *testing.T) {
	t.Parallel()
	lookalikes := []string{
		"/.dockerenv.bak",
		"/.dockerenv/child",
		"/run/.containerenv-old",
		"/proc/$PID/cgroup-copy",
		"/proc/self/status-old",
		"/proc/self/mountinfo.backup",
		"/proc/cpuinfo-copy",
		"/proc/meminfo/extra",
		"/proc/uptime2",
		"/sys/class/dmi-fake/id",
		"$WORK/sys/class/dmi/id/product_name",
	}
	for _, target := range lookalikes {
		target := target
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			risk, ruleID, _ := classify(model.Behavior{
				Type: "filesystem.read", Operation: "inspect", Target: target,
				Outcome: "success", Count: 1, SourceCall: "openat",
			})
			if risk != "low" || ruleID != "BL500" {
				t.Fatalf("lookalike %q classified as %q %q", target, risk, ruleID)
			}
		})
	}
}

func TestClassifySensitiveReadPrecedesEnvironmentFingerprintRule(t *testing.T) {
	t.Parallel()
	risk, ruleID, _ := classify(model.Behavior{
		Type: "filesystem.read", Operation: "read", Target: "/proc/self/status",
		Outcome: "success", Sensitive: true, Count: 1, SourceCall: "openat",
	})
	if risk != "critical" || ruleID != "BL100" {
		t.Fatalf("sensitive environment read classified as %q %q", risk, ruleID)
	}
}

func TestClassifyOrdinaryReadUsesBL500(t *testing.T) {
	t.Parallel()
	risk, ruleID, reason := classify(model.Behavior{
		Type: "filesystem.read", Operation: "read", Target: "/etc/hosts",
		Outcome: "success", Count: 1, SourceCall: "openat",
	})
	if risk != "low" || ruleID != "BL500" || reason != "new filesystem read or metadata inspection" {
		t.Fatalf("ordinary read classification = %q %q %q", risk, ruleID, reason)
	}
}

func TestClassifyExpandedObservationRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		behavior model.Behavior
		level    string
		ruleID   string
	}{
		{behavior: model.Behavior{Type: "network.send"}, level: "high", ruleID: "BL201"},
		{behavior: model.Behavior{Type: "network.dns"}, level: "high", ruleID: "BL202"},
		{behavior: model.Behavior{Type: "network.listen"}, level: "high", ruleID: "BL203"},
		{behavior: model.Behavior{Type: "network.accept"}, level: "medium", ruleID: "BL204"},
		{behavior: model.Behavior{Type: "network.socket"}, level: "low", ruleID: "BL205"},
		{behavior: model.Behavior{Type: "process.create"}, level: "medium", ruleID: "BL302"},
		{behavior: model.Behavior{Type: "process.memfd"}, level: "high", ruleID: "BL303"},
		{behavior: model.Behavior{Type: "process.fileless_exec"}, level: "high", ruleID: "BL303"},
		{behavior: model.Behavior{Type: "process.ptrace"}, level: "medium", ruleID: "BL304"},
		{behavior: model.Behavior{Type: "filesystem.truncate"}, level: "high", ruleID: "BL403"},
		{behavior: model.Behavior{Type: "filesystem.descriptor_write"}, level: "high", ruleID: "BL403"},
		{behavior: model.Behavior{Type: "filesystem.enumerate"}, level: "low", ruleID: "BL501"},
		{behavior: model.Behavior{Type: "environment.timing"}, level: "low", ruleID: "BL601"},
	}
	for _, test := range tests {
		level, ruleID, _ := classify(test.behavior)
		if level != test.level || ruleID != test.ruleID {
			t.Errorf("%s classified as %s %s, want %s %s", test.behavior.Type, level, ruleID, test.level, test.ruleID)
		}
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
		profile.Capture.Phase = "external"
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

func TestProfilesRejectDifferentObservationPolicies(t *testing.T) {
	t.Parallel()
	baseline := completeProfile("1.0.0")
	candidate := completeProfile("1.1.0")
	candidate.Capture.ObservationPolicy = "strace-observation-v3"
	if _, err := Profiles(baseline, candidate, "test"); err == nil || !strings.Contains(err.Error(), "observation policy") {
		t.Fatalf("different observation policies were not rejected: %v", err)
	}
}

func TestProfilesRejectLifecycleAndImportPhaseComparison(t *testing.T) {
	t.Parallel()
	baseline := completeProfile("1.0.0")
	candidate := completeProfile("1.1.0")
	candidate.Capture.Phase = "import"
	candidate.Capture.Coverage = model.CaptureCoverage{
		Scope: "registry-import-entrypoint", Lifecycle: []string{}, Completeness: "partial",
		Limitations: []string{"Only the resolved import entry point is observed."},
	}
	candidate.Capture.Import = &model.ImportInfo{
		Entrypoint: "$WORK/node_modules/example/index.js", ModuleKind: "commonjs",
		ResolverVersion: "node-resolve-v1", Support: "supported",
	}
	if _, err := Profiles(baseline, candidate, "test"); err == nil || !strings.Contains(err.Error(), "capture phase") {
		t.Fatalf("lifecycle and import profiles were not rejected explicitly: %v", err)
	}
}

func TestProfilesRequireReviewForObservedSequenceChangeWithoutInventingLevel(t *testing.T) {
	t.Parallel()
	anchor := model.Behavior{Type: "filesystem.create", Operation: "create", Target: "$WORK/stage", Outcome: "success", Count: 1, SourceCall: "openat"}
	baseline := completeProfile("1.0.0", anchor)
	candidate := completeProfile("1.1.0", anchor)
	baselineSequence := model.ObservationSequence{
		Scope: "process-lineage-observed-order", BehaviorIDs: []string{baseline.Behaviors[0].ID, baseline.Behaviors[1].ID},
	}
	baselineSequence.ID = model.StableSequenceID(baselineSequence)
	candidateSequence := model.ObservationSequence{
		Scope: "process-lineage-observed-order", BehaviorIDs: []string{candidate.Behaviors[1].ID, candidate.Behaviors[0].ID},
	}
	candidateSequence.ID = model.StableSequenceID(candidateSequence)
	baseline.Sequences = []model.ObservationSequence{baselineSequence}
	candidate.Sequences = []model.ObservationSequence{candidateSequence}

	diff, err := Profiles(baseline, candidate, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Summary.ReviewRequired || diff.Summary.HighestReviewLevel != "none" || len(diff.Added) != 0 || len(diff.AddedSequences) != 1 {
		t.Fatalf("sequence-only change was not represented honestly: %#v", diff)
	}
}
