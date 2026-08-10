package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kiranmagic7/behaviorlock/internal/model"
	"github.com/kiranmagic7/behaviorlock/internal/npm"
)

const (
	testRunnerImageID     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testPreparedImageID   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testRegistryIntegrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	testPrepareOutput     = "BEHAVIORLOCK_PREP_V1 {\"integrity\":\"" + testRegistryIntegrity + "\",\"dependencyLockSha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"acquisitionPolicyVersion\":\"npm-registry-connect-v1\",\"allowedAuthority\":\"registry.npmjs.org:443\",\"importEntrypoint\":\"$WORK/node_modules/example/index.js\",\"importModuleKind\":\"commonjs\",\"importResolverVersion\":\"node-resolve-v1\",\"importSupport\":\"supported\",\"importReason\":\"\"}\n"
	testProxyOutput       = "BEHAVIORLOCK_PROXY_READY_V1 npm-registry-connect-v1 registry.npmjs.org:443\nBEHAVIORLOCK_PROXY_V1 {\"decision\":\"allow\",\"reason\":\"npm-registry-connect-v1\",\"authority\":\"registry.npmjs.org:443\"}\n"
)

func TestTraceArgumentsKeepPackageSpecAfterImage(t *testing.T) {
	t.Parallel()
	packageSpec := "safe-package@1.2.3"
	canaries := deterministicCanaries(t)
	arguments := buildTraceArgs("behaviorlock-trace-abc", testPreparedImageID, packageSpec, "lifecycle", "none", canaries)
	if arguments[len(arguments)-1] != "lifecycle" || arguments[len(arguments)-2] != packageSpec || arguments[len(arguments)-3] != "trace" {
		t.Fatalf("unexpected trailing arguments: %q", arguments[len(arguments)-4:])
	}
	for _, forbidden := range []string{"--privileged", "seccomp=unconfined", "--pid", "host", "/var/run/docker.sock"} {
		if slices.Contains(arguments, forbidden) {
			t.Fatalf("trace arguments contain forbidden value %q", forbidden)
		}
	}
	joined := strings.Join(arguments, " ")
	for _, required := range []string{"--network none", "--read-only", "--user 0:0", "--cap-drop ALL", "--cap-add SETUID", "--cap-add SETGID", "--cap-add SYS_PTRACE", "no-new-privileges:true", "--pids-limit 128", "fsize=67108864:67108864", "/trace:rw,nosuid,nodev,noexec"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("trace arguments missing %q: %s", required, joined)
		}
	}
	assertProxyEnvironmentScrubbed(t, arguments)
	if !strings.Contains(joined, "--env BEHAVIORLOCK_CANARY_SSH=") || !strings.Contains(joined, "--env AWS_SECRET_ACCESS_KEY=") {
		t.Fatalf("trace arguments are missing generated canaries: %q", arguments)
	}
	if !strings.Contains(joined, "--env BEHAVIORLOCK_SINKHOLE_ENABLED=0") {
		t.Fatalf("offline trace arguments do not make sinkhole state explicit: %q", arguments)
	}
}

func TestTraceArgumentsEnableOnlyGeneratedSinkholeNamespace(t *testing.T) {
	t.Parallel()
	canaries := deterministicCanaries(t)
	arguments := buildTraceArgs("behaviorlock-trace-abc", testPreparedImageID, "safe-package@1.2.3", "import", "container:behaviorlock-sinkhole-abc", canaries)
	joined := strings.Join(arguments, " ")
	if !strings.Contains(joined, "--network container:behaviorlock-sinkhole-abc") || !strings.Contains(joined, "--env BEHAVIORLOCK_SINKHOLE_ENABLED=1") {
		t.Fatalf("sinkhole namespace was not enabled explicitly: %q", arguments)
	}

	invalid := strings.Join(buildTraceArgs("behaviorlock-trace-abc", testPreparedImageID, "safe-package@1.2.3", "import", "container:attacker", canaries), " ")
	if !strings.Contains(invalid, "--network none") || !strings.Contains(invalid, "--env BEHAVIORLOCK_SINKHOLE_ENABLED=0") {
		t.Fatalf("untrusted network namespace was not rejected: %q", invalid)
	}
}

func deterministicCanaries(t *testing.T) []canarySpec {
	t.Helper()
	raw := make([]byte, 16*len(canaryTemplates))
	for index := range raw {
		raw[index] = byte(index)
	}
	canaries, err := newCanarySet(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return canaries
}

func TestPrepareArgumentsNeverMountHostPaths(t *testing.T) {
	t.Parallel()
	arguments := buildPrepareArgs("behaviorlock-prep-abc", "behaviorlock-acq-socket-abc", testRunnerImageID, "safe-package@1.2.3")
	for _, argument := range arguments {
		if argument == "-v" || argument == "--volume" || strings.Contains(argument, "docker.sock") {
			t.Fatalf("prepare arguments expose a host mount: %q", arguments)
		}
	}
	joined := strings.Join(arguments, " ")
	if !strings.Contains(joined, "--user 65532:65532") {
		t.Fatalf("preparation must run as the nonroot package user: %q", arguments)
	}
	if !strings.Contains(joined, "--network none") || !strings.Contains(joined, "source=behaviorlock-acq-socket-abc,target=/proxy,readonly") {
		t.Fatalf("preparation does not use network none and the read-only proxy socket: %q", arguments)
	}
	if arguments[len(arguments)-3] != testRunnerImageID {
		t.Fatalf("preparation did not use the resolved runner image ID: %q", arguments)
	}
	assertAcquisitionProxyEnvironment(t, arguments)
}

func TestProxyArgumentsAreBoundedWithMinimalSupervisorCapabilities(t *testing.T) {
	t.Parallel()
	arguments := buildProxyArgs("behaviorlock-proxy-abc", "behaviorlock-acq-egress-abc", "behaviorlock-acq-socket-abc", testRunnerImageID)
	joined := strings.Join(arguments, " ")
	for _, required := range []string{
		"--detach", "--network behaviorlock-acq-egress-abc",
		"--read-only", "--user 0:0", "--cap-drop ALL", "--cap-add CHOWN", "--cap-add SETUID", "--cap-add SETGID", "no-new-privileges:true",
		"--pids-limit 64", "--memory 128m", "--cpus 0.5",
		"source=behaviorlock-acq-socket-abc,target=/proxy,volume-nocopy",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("proxy arguments missing %q: %q", required, arguments)
		}
	}
	for _, forbidden := range []string{"--privileged", "--network host", "/var/run/docker.sock", "NET_ADMIN", "NET_RAW", "SYS_ADMIN"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("proxy arguments contain forbidden value %q: %q", forbidden, arguments)
		}
	}
	assertProxyEnvironmentScrubbed(t, arguments)
}

func assertProxyEnvironmentScrubbed(t *testing.T, arguments []string) {
	t.Helper()
	joined := strings.Join(arguments, " ")
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
		if !strings.Contains(joined, "--env "+name+"=") {
			t.Fatalf("docker arguments did not clear %s: %q", name, arguments)
		}
	}
}

func assertAcquisitionProxyEnvironment(t *testing.T, arguments []string) {
	t.Helper()
	joined := strings.Join(arguments, " ")
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "npm_config_proxy", "npm_config_https_proxy"} {
		if !strings.Contains(joined, "--env "+name+"="+acquisitionProxyAddress) {
			t.Fatalf("preparation did not pin %s to the internal proxy: %q", name, arguments)
		}
	}
	for _, name := range []string{"ALL_PROXY", "NO_PROXY", "all_proxy", "no_proxy"} {
		if !strings.Contains(joined, "--env "+name+"=") {
			t.Fatalf("preparation did not clear %s: %q", name, arguments)
		}
	}
}

func TestBoundedBufferReportsTruncation(t *testing.T) {
	t.Parallel()
	buffer := newBoundedBuffer(4)
	if written, _ := buffer.Write([]byte("abcdef")); written != 6 {
		t.Fatalf("Write reported %d bytes", written)
	}
	if got := string(buffer.Bytes()); got != "abcd" || !buffer.Truncated() {
		t.Fatalf("bounded buffer = %q truncated=%t", got, buffer.Truncated())
	}
}

func TestClassifyTraceFailureKeepsBoundaryOutcomesDistinct(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		contextErr error
		result     commandResult
		runErr     error
		state      *containerState
		status     string
		timedOut   bool
		truncated  bool
	}{
		{name: "timeout", contextErr: context.DeadlineExceeded, status: "timed_out", timedOut: true},
		{name: "cancellation", contextErr: context.Canceled, status: "trace_incomplete"},
		{name: "authoritative oom", result: commandResult{ExitCode: 137}, state: &containerState{OOMKilled: true, ExitCode: 137}, status: "resource_exhausted"},
		{name: "signal style but not oom", result: commandResult{ExitCode: 137}, state: &containerState{ExitCode: 137}, status: "trace_incomplete"},
		{name: "client success but container signal", result: commandResult{ExitCode: 0}, state: &containerState{ExitCode: 137}, status: "trace_incomplete"},
		{name: "output truncation", result: commandResult{Truncated: true}, status: "trace_incomplete", truncated: true},
		{name: "docker execution error", result: commandResult{Stderr: []byte("trusted supervisor diagnostic\nsecond line")}, runErr: errors.New("docker unavailable"), status: "trace_incomplete"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := classifyTraceFailure(test.contextErr, test.result, test.runErr, test.state)
			if err == nil || result.Status != test.status || result.TimedOut != test.timedOut || result.Truncated != test.truncated {
				t.Fatalf("classification = %#v err=%v", result, err)
			}
			if strings.ContainsAny(result.Message, "\r\n\t") {
				t.Fatalf("profile result contains operator diagnostics: %q", result.Message)
			}
			if test.name == "docker execution error" && !strings.Contains(err.Error(), "trusted supervisor diagnostic") {
				t.Fatalf("operator error omitted bounded diagnostics: %v", err)
			}
		})
	}
	if result, err := classifyTraceFailure(nil, commandResult{}, nil, nil); err != nil || result.Status != "" {
		t.Fatalf("successful trace was classified as failure: %#v err=%v", result, err)
	}
}

func TestInspectContainerStateRequiresValidDockerState(t *testing.T) {
	t.Parallel()
	runner := &DockerRunner{dockerPath: "docker"}
	runner.run = func(_ context.Context, arguments []string, _, _ int64) (commandResult, error) {
		if strings.Join(arguments, " ") != "inspect --format {{json .State}} behaviorlock-trace-test" {
			t.Fatalf("unexpected inspect arguments: %q", arguments)
		}
		return commandResult{Stdout: []byte(`{"OOMKilled":true,"ExitCode":137,"Error":""}`)}, nil
	}
	state, err := runner.inspectContainerState("behaviorlock-trace-test")
	if err != nil || !state.OOMKilled || state.ExitCode != 137 {
		t.Fatalf("state = %#v err=%v", state, err)
	}
}

func TestParsePrepareMetadata(t *testing.T) {
	t.Parallel()
	metadata, err := parsePrepareMetadata([]byte("noise\n" + testPrepareOutput))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Integrity != testRegistryIntegrity {
		t.Fatalf("integrity = %q", metadata.Integrity)
	}
}

func TestParsePrepareMetadataRejectsUnknownAndTrailingJSON(t *testing.T) {
	t.Parallel()
	valid := strings.TrimSpace(strings.TrimPrefix(testPrepareOutput, "BEHAVIORLOCK_PREP_V1 "))
	tests := map[string]string{
		"unknown field":  strings.Replace(valid, `"importReason":""}`, `"importReason":"","unexpected":"value"}`, 1),
		"trailing value": valid + ` {}`,
	}
	for name, payload := range tests {
		name, payload := name, payload
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parsePrepareMetadata([]byte("BEHAVIORLOCK_PREP_V1 " + payload + "\n")); err == nil {
				t.Fatal("untrusted preparation metadata unexpectedly passed strict decoding")
			}
		})
	}
}

func TestAcquisitionProxyAuditRejectsAnyDeniedRequest(t *testing.T) {
	t.Parallel()
	runner := &DockerRunner{dockerPath: "docker"}
	runner.run = func(_ context.Context, arguments []string, _, _ int64) (commandResult, error) {
		if arguments[0] != "logs" {
			t.Fatalf("unexpected docker arguments: %q", arguments)
		}
		return commandResult{Stdout: []byte("BEHAVIORLOCK_PROXY_V1 {\"decision\":\"deny\",\"reason\":\"authority_not_allowed\",\"authority\":\"attacker.invalid:443\"}\n")}, nil
	}
	if err := runner.verifyAcquisitionProxyAudit(context.Background(), "behaviorlock-proxy-test"); err == nil {
		t.Fatal("denied acquisition request unexpectedly passed the audit")
	}
}

func TestCaptureCompletesOnlyWithValidEnvelope(t *testing.T) {
	t.Parallel()
	runner := &DockerRunner{dockerPath: "docker"}
	observedCanary := ""
	runner.run = func(_ context.Context, arguments []string, _, _ int64) (commandResult, error) {
		switch arguments[0] {
		case "version":
			return commandResult{Stdout: []byte("26.1.0\n")}, nil
		case "image":
			if arguments[1] == "inspect" {
				return commandResult{Stdout: []byte(`{"Id":"` + testRunnerImageID + `","Architecture":"amd64"}`)}, nil
			}
			return commandResult{}, nil
		case "create":
			if arguments[len(arguments)-3] != testRunnerImageID {
				t.Fatalf("prepare used mutable runner reference: %q", arguments)
			}
			return commandResult{}, nil
		case "network":
			if arguments[1] == "create" {
				return commandResult{Stdout: []byte("network-id\n")}, nil
			}
			return commandResult{}, nil
		case "volume":
			if arguments[1] == "create" {
				return commandResult{Stdout: []byte("volume-name\n")}, nil
			}
			return commandResult{}, nil
		case "logs":
			return commandResult{Stdout: []byte(testProxyOutput)}, nil
		case "rm":
			return commandResult{}, nil
		case "commit":
			return commandResult{Stdout: []byte(testPreparedImageID + "\n")}, nil
		case "start":
			return commandResult{Stdout: []byte(testPrepareOutput)}, nil
		case "inspect":
			return commandResult{Stdout: []byte(`{"OOMKilled":false,"ExitCode":0,"Error":""}`)}, nil
		case "run":
			if arguments[len(arguments)-1] == "proxy" {
				return commandResult{Stdout: []byte("proxy-container-id\n")}, nil
			}
			if arguments[len(arguments)-1] == "version" {
				if arguments[len(arguments)-2] != testRunnerImageID {
					t.Fatalf("version probe used mutable runner reference: %q", arguments)
				}
				return commandResult{Stdout: []byte("{\"node\":\"v22.1.0\",\"npm\":\"10.8.0\",\"strace\":\"6.1\"}\n")}, nil
			}
			if arguments[len(arguments)-4] != testPreparedImageID {
				t.Fatalf("trace used mutable preparation image reference: %q", arguments)
			}
			for _, argument := range arguments {
				if strings.HasPrefix(argument, "GITHUB_TOKEN=") {
					observedCanary = strings.TrimPrefix(argument, "GITHUB_TOKEN=")
				}
			}
			if observedCanary == "" {
				t.Fatal("trace arguments omitted the generated GitHub canary")
			}
			return commandResult{Stdout: []byte("BEHAVIORLOCK_TRACE_V1\nopenat(AT_FDCWD, \"/opt/behaviorlock/sentinel-start\", O_RDONLY) = 3\nexecve(\"/bin/echo\", [\"echo\", \"" + observedCanary + "\"], 0x0) = 0\nopenat(AT_FDCWD, \"/opt/behaviorlock/sentinel-end\", O_RDONLY) = 3\nBEHAVIORLOCK_TRACE_END exit=0\n")}, nil
		default:
			t.Fatalf("unexpected docker arguments: %q", arguments)
			return commandResult{}, nil
		}
	}
	spec, err := npm.ParseExactSpec("example@1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	profile, rawEvidence, err := runner.CaptureWithEvidence(context.Background(), spec, Config{Timeout: time.Minute, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Result.Status != "complete" || len(profile.Behaviors) != 3 {
		t.Fatalf("unexpected profile: %#v", profile)
	}
	if profile.Subject.RegistryIntegrity != testRegistryIntegrity || profile.Capture.RunnerImageID != testRunnerImageID {
		t.Fatalf("capture evidence is incomplete: %#v", profile)
	}
	if len(rawEvidence) == 0 || profile.Capture.EvidenceArtifact == nil {
		t.Fatal("capture did not retain raw evidence metadata and bytes")
	}
	if err := model.VerifyEvidence(profile, rawEvidence); err != nil {
		t.Fatalf("retained capture evidence did not verify: %v", err)
	}
	if err := model.ValidateProfile(profile); err != nil {
		t.Fatalf("captured profile did not validate: %v", err)
	}
	if profile.Capture.Acquisition == nil || profile.Capture.Acquisition.NetworkMode != "registry-proxy-unix" {
		t.Fatalf("capture omitted acquisition fingerprint: %#v", profile.Capture.Acquisition)
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), observedCanary) {
		t.Fatal("normalized profile retained a generated canary value")
	}
	var matched bool
	for _, behavior := range profile.Behaviors {
		if slices.Contains(behavior.CanaryIDs, "canary:github-token") && slices.Contains(behavior.Arguments, "$CANARY[github-token]") {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("capture did not replace visible canary movement with its stable identifier: %#v", profile.Behaviors)
	}
}

func TestCaptureRejectsMissingTraceFooter(t *testing.T) {
	t.Parallel()
	runner := &DockerRunner{dockerPath: "docker"}
	runner.run = func(_ context.Context, arguments []string, _, _ int64) (commandResult, error) {
		switch arguments[0] {
		case "version":
			return commandResult{Stdout: []byte("26.1.0\n")}, nil
		case "image":
			return commandResult{Stdout: []byte(`{"Id":"` + testRunnerImageID + `","Architecture":"amd64"}`)}, nil
		case "create", "rm":
			return commandResult{}, nil
		case "network":
			if arguments[1] == "create" {
				return commandResult{Stdout: []byte("network-id\n")}, nil
			}
			return commandResult{}, nil
		case "volume":
			if arguments[1] == "create" {
				return commandResult{Stdout: []byte("volume-name\n")}, nil
			}
			return commandResult{}, nil
		case "logs":
			return commandResult{Stdout: []byte(testProxyOutput)}, nil
		case "commit":
			return commandResult{Stdout: []byte(testPreparedImageID + "\n")}, nil
		case "start":
			return commandResult{Stdout: []byte(testPrepareOutput)}, nil
		case "inspect":
			return commandResult{Stdout: []byte(`{"OOMKilled":false,"ExitCode":0,"Error":""}`)}, nil
		case "run":
			if arguments[len(arguments)-1] == "proxy" {
				return commandResult{Stdout: []byte("proxy-container-id\n")}, nil
			}
			if arguments[len(arguments)-1] == "version" {
				return commandResult{Stdout: []byte("{\"node\":\"v22.1.0\",\"npm\":\"10.8.0\",\"strace\":\"6.1\"}\n")}, nil
			}
			return commandResult{Stdout: []byte("BEHAVIORLOCK_TRACE_V1\nexecve(\"/bin/true\", [\"true\"], 0x0) = 0\n")}, nil
		default:
			return commandResult{}, nil
		}
	}
	spec, err := npm.ParseExactSpec("example@1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := runner.Capture(context.Background(), spec, Config{Timeout: time.Minute, ToolVersion: "test"})
	if err == nil {
		t.Fatal("capture without a completion footer unexpectedly succeeded")
	}
	if profile.Result.Status != "trace_incomplete" {
		t.Fatalf("status = %q", profile.Result.Status)
	}
}

func TestCaptureRejectsInvalidTimeoutBeforeDocker(t *testing.T) {
	t.Parallel()
	runner := &DockerRunner{dockerPath: "docker"}
	runner.run = func(_ context.Context, _ []string, _, _ int64) (commandResult, error) {
		t.Fatal("docker must not run for an invalid timeout")
		return commandResult{}, nil
	}
	spec, err := npm.ParseExactSpec("example@1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Capture(context.Background(), spec, Config{Timeout: time.Second}); err == nil {
		t.Fatal("invalid timeout unexpectedly succeeded")
	}
}

func TestRunnerImageReferenceValidation(t *testing.T) {
	t.Parallel()
	valid := []string{
		"behaviorlock-runner:dev",
		"ghcr.io/kiranmagic7/behaviorlock-runner:v0.1.0",
		"ghcr.io/kiranmagic7/behaviorlock-runner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	for _, value := range valid {
		if got, err := normalizeRunnerImage(value); err != nil || got != value {
			t.Errorf("valid reference %q rejected: got=%q err=%v", value, got, err)
		}
	}
	invalid := []string{
		"behaviorlock-runner",
		"behaviorlock-runner:latest",
		"-v",
		"https://registry.invalid/image:v1",
		"registry.invalid/Upper/image:v1",
		"behaviorlock-runner:dev\n--privileged",
		"ghcr.io/kiranmagic7/behaviorlock-runner@sha256:short",
	}
	for _, value := range invalid {
		if _, err := normalizeRunnerImage(value); err == nil {
			t.Errorf("invalid reference %q accepted", value)
		}
	}
}

func TestCaptureRejectsInvalidRunnerBeforeDocker(t *testing.T) {
	t.Parallel()
	runner := &DockerRunner{dockerPath: "docker"}
	runner.run = func(_ context.Context, _ []string, _, _ int64) (commandResult, error) {
		t.Fatal("docker must not run for an invalid runner reference")
		return commandResult{}, nil
	}
	spec, err := npm.ParseExactSpec("example@1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Capture(context.Background(), spec, Config{
		Timeout: time.Minute, ToolVersion: "test", RunnerImage: "--privileged",
	}); err == nil || !strings.Contains(err.Error(), "runner image") {
		t.Fatalf("invalid runner reference was not rejected: %v", err)
	}
}

func TestCaptureRejectsCommitWithoutContentID(t *testing.T) {
	t.Parallel()
	runner := &DockerRunner{dockerPath: "docker"}
	runner.run = func(_ context.Context, arguments []string, _, _ int64) (commandResult, error) {
		switch arguments[0] {
		case "version":
			return commandResult{Stdout: []byte("26.1.0\n")}, nil
		case "image":
			return commandResult{Stdout: []byte(`{"Id":"` + testRunnerImageID + `","Architecture":"amd64"}`)}, nil
		case "create", "rm":
			return commandResult{}, nil
		case "network":
			if arguments[1] == "create" {
				return commandResult{Stdout: []byte("network-id\n")}, nil
			}
			return commandResult{}, nil
		case "volume":
			if arguments[1] == "create" {
				return commandResult{Stdout: []byte("volume-name\n")}, nil
			}
			return commandResult{}, nil
		case "logs":
			return commandResult{Stdout: []byte(testProxyOutput)}, nil
		case "start":
			return commandResult{Stdout: []byte(testPrepareOutput)}, nil
		case "commit":
			return commandResult{Stdout: []byte("behaviorlock-analysis:mutable\n")}, nil
		case "run":
			if arguments[len(arguments)-1] == "proxy" {
				return commandResult{Stdout: []byte("proxy-container-id\n")}, nil
			}
			return commandResult{Stdout: []byte("{\"node\":\"v22.1.0\",\"npm\":\"10.8.0\",\"strace\":\"6.1\"}\n")}, nil
		default:
			return commandResult{}, nil
		}
	}
	spec, err := npm.ParseExactSpec("example@1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Capture(context.Background(), spec, Config{Timeout: time.Minute, ToolVersion: "test"}); err == nil || !strings.Contains(err.Error(), "content ID") {
		t.Fatalf("invalid commit result was not rejected: %v", err)
	}
}
