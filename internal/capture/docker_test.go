package capture

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kiranmagic7/behaviorlock/internal/npm"
)

const (
	testRunnerImageID     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testPreparedImageID   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testRegistryIntegrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

func TestTraceArgumentsKeepPackageSpecAfterImage(t *testing.T) {
	t.Parallel()
	packageSpec := "safe-package@1.2.3"
	arguments := buildTraceArgs("behaviorlock-trace-abc", testPreparedImageID, packageSpec)
	if arguments[len(arguments)-1] != packageSpec || arguments[len(arguments)-2] != "trace" {
		t.Fatalf("unexpected trailing arguments: %q", arguments[len(arguments)-3:])
	}
	for _, forbidden := range []string{"--privileged", "seccomp=unconfined", "--pid", "host", "/var/run/docker.sock"} {
		if slices.Contains(arguments, forbidden) {
			t.Fatalf("trace arguments contain forbidden value %q", forbidden)
		}
	}
	joined := strings.Join(arguments, " ")
	for _, required := range []string{"--network none", "--read-only", "--user 0:0", "--cap-drop ALL", "--cap-add SETUID", "--cap-add SETGID", "--cap-add SYS_PTRACE", "no-new-privileges:true", "--pids-limit 128", "/trace:rw,nosuid,nodev,noexec"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("trace arguments missing %q: %s", required, joined)
		}
	}
	assertProxyEnvironmentScrubbed(t, arguments)
}

func TestPrepareArgumentsNeverMountHostPaths(t *testing.T) {
	t.Parallel()
	arguments := buildPrepareArgs("behaviorlock-prep-abc", testRunnerImageID, "safe-package@1.2.3")
	for _, argument := range arguments {
		if argument == "-v" || argument == "--volume" || strings.Contains(argument, "docker.sock") {
			t.Fatalf("prepare arguments expose a host mount: %q", arguments)
		}
	}
	if !strings.Contains(strings.Join(arguments, " "), "--user 65532:65532") {
		t.Fatalf("preparation must run as the nonroot package user: %q", arguments)
	}
	if arguments[len(arguments)-3] != testRunnerImageID {
		t.Fatalf("preparation did not use the resolved runner image ID: %q", arguments)
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

func TestParsePrepareMetadata(t *testing.T) {
	t.Parallel()
	metadata, err := parsePrepareMetadata([]byte("noise\nBEHAVIORLOCK_PREP_V1 {\"integrity\":\"" + testRegistryIntegrity + "\",\"dependencyLockSha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Integrity != testRegistryIntegrity {
		t.Fatalf("integrity = %q", metadata.Integrity)
	}
}

func TestCaptureCompletesOnlyWithValidEnvelope(t *testing.T) {
	t.Parallel()
	runner := &DockerRunner{dockerPath: "docker"}
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
		case "rm":
			return commandResult{}, nil
		case "commit":
			return commandResult{Stdout: []byte(testPreparedImageID + "\n")}, nil
		case "start":
			return commandResult{Stdout: []byte("BEHAVIORLOCK_PREP_V1 {\"integrity\":\"" + testRegistryIntegrity + "\",\"dependencyLockSha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n")}, nil
		case "run":
			if arguments[len(arguments)-1] == "version" {
				if arguments[len(arguments)-2] != testRunnerImageID {
					t.Fatalf("version probe used mutable runner reference: %q", arguments)
				}
				return commandResult{Stdout: []byte("{\"node\":\"v22.1.0\",\"npm\":\"10.8.0\",\"strace\":\"6.1\"}\n")}, nil
			}
			if arguments[len(arguments)-3] != testPreparedImageID {
				t.Fatalf("trace used mutable preparation image reference: %q", arguments)
			}
			return commandResult{Stdout: []byte("BEHAVIORLOCK_TRACE_V1\nopenat(AT_FDCWD, \"/opt/behaviorlock/sentinel-start\", O_RDONLY) = 3\nexecve(\"/bin/true\", [\"true\"], 0x0) = 0\nopenat(AT_FDCWD, \"/opt/behaviorlock/sentinel-end\", O_RDONLY) = 3\nBEHAVIORLOCK_TRACE_END exit=0\n")}, nil
		default:
			t.Fatalf("unexpected docker arguments: %q", arguments)
			return commandResult{}, nil
		}
	}
	spec, err := npm.ParseExactSpec("example@1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := runner.Capture(context.Background(), spec, Config{Timeout: time.Minute, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Result.Status != "complete" || len(profile.Behaviors) != 3 {
		t.Fatalf("unexpected profile: %#v", profile)
	}
	if profile.Subject.RegistryIntegrity != testRegistryIntegrity || profile.Capture.RunnerImageID != testRunnerImageID {
		t.Fatalf("capture evidence is incomplete: %#v", profile)
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
		case "commit":
			return commandResult{Stdout: []byte(testPreparedImageID + "\n")}, nil
		case "start":
			return commandResult{Stdout: []byte("BEHAVIORLOCK_PREP_V1 {\"integrity\":\"" + testRegistryIntegrity + "\",\"dependencyLockSha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n")}, nil
		case "run":
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
		case "start":
			return commandResult{Stdout: []byte("BEHAVIORLOCK_PREP_V1 {\"integrity\":\"" + testRegistryIntegrity + "\",\"dependencyLockSha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n")}, nil
		case "commit":
			return commandResult{Stdout: []byte("behaviorlock-analysis:mutable\n")}, nil
		case "run":
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
