package schemas

import (
	"encoding/json"
	"testing"

	"github.com/kiranmagic7/behaviorlock/internal/compare"
	"github.com/kiranmagic7/behaviorlock/internal/model"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const testRegistryIntegrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

func schemaProfile(version string, behaviors ...model.Behavior) model.Profile {
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

func compileSchema(t *testing.T, fileName string) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(fileName)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func asJSONValue(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestProfileSchemaAcceptsGeneratedProfile(t *testing.T) {
	t.Parallel()
	profile := schemaProfile("1.0.0")
	if err := compileSchema(t, "profile-v2.schema.json").Validate(asJSONValue(t, profile)); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentSchemasAcceptExpandedBehaviorWithRuntimeAttribution(t *testing.T) {
	t.Parallel()
	behavior := model.Behavior{
		Type: "network.dns", Operation: "query", Target: "AF_INET:8.8.8.8:53",
		Outcome: "blocked", Errno: "ENETUNREACH", Count: 1, SourceCall: "sendto",
		Runtime: []model.RuntimeContext{{Process: "401", Parent: "400", Descriptor: "3", Attribution: "direct"}},
	}
	baseline := schemaProfile("1.0.0")
	candidate := schemaProfile("1.1.0", behavior)
	if err := compileSchema(t, "profile-v2.schema.json").Validate(asJSONValue(t, candidate)); err != nil {
		t.Fatal(err)
	}
	diff, err := compare.Profiles(baseline, candidate, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := compileSchema(t, "diff-v2.schema.json").Validate(asJSONValue(t, diff)); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentProfileSchemaRejectsNumericRuntimeIdentifiers(t *testing.T) {
	t.Parallel()
	profile := schemaProfile("1.0.0", model.Behavior{
		Type: "network.socket", Operation: "socket", Target: "AF_INET:SOCK_DGRAM:IPPROTO_IP",
		Outcome: "success", Count: 1, SourceCall: "socket",
		Runtime: []model.RuntimeContext{{Process: "401", Descriptor: "3", Attribution: "direct"}},
	})
	value := asJSONValue(t, profile).(map[string]any)
	behaviors := value["behaviors"].([]any)
	runtime := behaviors[0].(map[string]any)["runtime"].([]any)
	runtime[0].(map[string]any)["process"] = float64(401)
	if err := compileSchema(t, "profile-v2.schema.json").Validate(value); err == nil {
		t.Fatal("schema accepted a numeric runtime process identifier")
	}
}

func TestProfileSchemaRejectsContradictoryCompletion(t *testing.T) {
	t.Parallel()
	profile := schemaProfile("1.0.0")
	profile.Result.TimedOut = true
	if err := compileSchema(t, "profile-v2.schema.json").Validate(asJSONValue(t, profile)); err == nil {
		t.Fatal("schema accepted complete profile with timedOut true")
	}
}

func TestProfileSchemaAcceptsExternalUnverifiedProfile(t *testing.T) {
	t.Parallel()
	profile := schemaProfile("1.0.0")
	profile.Subject.RegistryIntegrity = ""
	profile.Subject.DependencyLockSHA256 = ""
	profile.Capture.TraceIntegrity = "external-unverified"
	profile.Capture.NetworkMode = "unknown"
	profile.Capture.SandboxProfile = "external-unverified"
	profile.Capture.Coverage.Scope = "external-strace"
	profile.Capture.Coverage.Completeness = "unverified"
	profile.Capture.Coverage.Lifecycle = []string{}
	profile.Capture.Acquisition = nil
	profile.Capture.EvidenceArtifact.Retention = "external-unverified"
	profile.Capture.EvidenceArtifact.Envelope = "external-strace"
	if err := compileSchema(t, "profile-v2.schema.json").Validate(asJSONValue(t, profile)); err != nil {
		t.Fatal(err)
	}
}

func TestProfileSchemaRejectsEmptyCapturedLifecycle(t *testing.T) {
	t.Parallel()
	profile := schemaProfile("1.0.0")
	profile.Capture.Coverage.Lifecycle = []string{}
	if err := compileSchema(t, "profile-v2.schema.json").Validate(asJSONValue(t, profile)); err == nil {
		t.Fatal("schema accepted captured profile with empty lifecycle coverage")
	}
}

func TestProfileSchemaRequiresCapturedAcquisitionFingerprint(t *testing.T) {
	t.Parallel()
	profile := schemaProfile("1.0.0")
	profile.Capture.Acquisition = nil
	if err := compileSchema(t, "profile-v2.schema.json").Validate(asJSONValue(t, profile)); err == nil {
		t.Fatal("schema accepted a captured profile without acquisition controls")
	}
}

func TestDiffSchemaAcceptsGeneratedDiff(t *testing.T) {
	t.Parallel()
	baseline := schemaProfile("1.0.0")
	candidate := schemaProfile("1.1.0", model.Behavior{
		Type: "network.connect", Operation: "connect", Target: "AF_INET:198.51.100.1:443",
		Outcome: "blocked", Errno: "ENETUNREACH", Count: 1, SourceCall: "connect",
	})
	diff, err := compare.Profiles(baseline, candidate, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := compileSchema(t, "diff-v2.schema.json").Validate(asJSONValue(t, diff)); err != nil {
		t.Fatal(err)
	}
}

func TestDiffSchemaAcceptsEnvironmentFingerprintAndOrdinaryReadRules(t *testing.T) {
	t.Parallel()
	baseline := schemaProfile("1.0.0")
	candidate := schemaProfile("1.1.0",
		model.Behavior{
			Type: "filesystem.read", Operation: "inspect", Target: "/proc/self/status",
			Outcome: "success", Count: 1, SourceCall: "openat",
		},
		model.Behavior{
			Type: "filesystem.read", Operation: "read", Target: "/etc/hosts",
			Outcome: "success", Count: 1, SourceCall: "openat",
		},
	)
	diff, err := compare.Profiles(baseline, candidate, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Added) != 2 || diff.Added[0].RuleID != "BL600" || diff.Added[1].RuleID != "BL500" {
		t.Fatalf("unexpected rules: %#v", diff.Added)
	}
	if err := compileSchema(t, "diff-v2.schema.json").Validate(asJSONValue(t, diff)); err != nil {
		t.Fatal(err)
	}
}

func TestDiffSchemaRejectsNumericRuleID(t *testing.T) {
	t.Parallel()
	baseline := schemaProfile("1.0.0")
	candidate := schemaProfile("1.1.0", model.Behavior{
		Type: "network.connect", Operation: "connect", Target: "AF_INET:198.51.100.1:443",
		Outcome: "blocked", Errno: "ENETUNREACH", Count: 1, SourceCall: "connect",
	})
	diff, err := compare.Profiles(baseline, candidate, "test")
	if err != nil {
		t.Fatal(err)
	}
	value := asJSONValue(t, diff).(map[string]any)
	value["added"].([]any)[0].(map[string]any)["ruleId"] = float64(100)
	if err := compileSchema(t, "diff-v2.schema.json").Validate(value); err == nil {
		t.Fatal("schema accepted numeric ruleId")
	}
}

func TestHistoricalSchemasRemainAvailable(t *testing.T) {
	t.Parallel()
	compileSchema(t, "profile-v1.schema.json")
	compileSchema(t, "diff-v1.schema.json")
}
