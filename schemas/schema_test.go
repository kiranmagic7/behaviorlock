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
	profile.Capture.RawTraceSHA256 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	profile.Result = model.Result{Status: "complete", ExitCode: 0}
	harness := model.Behavior{Type: "process.exec", Operation: "exec", Target: "/usr/bin/npm", Outcome: "success", Count: 1, SourceCall: "execve"}
	profile.Behaviors = append([]model.Behavior{harness}, behaviors...)
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
	if err := compileSchema(t, "profile-v1.schema.json").Validate(asJSONValue(t, profile)); err != nil {
		t.Fatal(err)
	}
}

func TestProfileSchemaRejectsContradictoryCompletion(t *testing.T) {
	t.Parallel()
	profile := schemaProfile("1.0.0")
	profile.Result.TimedOut = true
	if err := compileSchema(t, "profile-v1.schema.json").Validate(asJSONValue(t, profile)); err == nil {
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
	if err := compileSchema(t, "profile-v1.schema.json").Validate(asJSONValue(t, profile)); err != nil {
		t.Fatal(err)
	}
}

func TestProfileSchemaRejectsEmptyCapturedLifecycle(t *testing.T) {
	t.Parallel()
	profile := schemaProfile("1.0.0")
	profile.Capture.Coverage.Lifecycle = []string{}
	if err := compileSchema(t, "profile-v1.schema.json").Validate(asJSONValue(t, profile)); err == nil {
		t.Fatal("schema accepted captured profile with empty lifecycle coverage")
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
	if err := compileSchema(t, "diff-v1.schema.json").Validate(asJSONValue(t, diff)); err != nil {
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
	if err := compileSchema(t, "diff-v1.schema.json").Validate(value); err == nil {
		t.Fatal("schema accepted numeric ruleId")
	}
}
