package capture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kiranmagic7/behaviorlock/internal/model"
	"github.com/kiranmagic7/behaviorlock/internal/npm"
	"github.com/kiranmagic7/behaviorlock/internal/trace"
)

const (
	RunnerImage       = "behaviorlock-runner:dev"
	SandboxProfile    = "behaviorlock-linux-npm-v1"
	maxPreparationLog = 4 << 20
	maxTraceStream    = trace.MaxTraceBytes + (1 << 20)
)

type Config struct {
	Timeout     time.Duration
	ToolVersion string
}

type PrepareMetadata struct {
	Integrity            string `json:"integrity"`
	DependencyLockSHA256 string `json:"dependencyLockSha256"`
}

type RunnerMetadata struct {
	Node   string `json:"node"`
	NPM    string `json:"npm"`
	Strace string `json:"strace"`
}

type imageInspect struct {
	ID           string `json:"Id"`
	Architecture string `json:"Architecture"`
}

type DockerRunner struct {
	dockerPath string
	run        func(context.Context, []string, int64, int64) (commandResult, error)
}

type commandResult struct {
	Stdout    []byte
	Stderr    []byte
	Truncated bool
	ExitCode  int
}

func NewDockerRunner() (*DockerRunner, error) {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return nil, errors.New("docker is required for experimental capture; install Docker or use profile --trace")
	}
	runner := &DockerRunner{dockerPath: dockerPath}
	runner.run = runner.runCommand
	return runner, nil
}

func (runner *DockerRunner) Doctor(ctx context.Context) error {
	result, err := runner.run(ctx, []string{"version", "--format", "{{.Server.Version}}"}, 64<<10, 64<<10)
	if err != nil {
		return fmt.Errorf("docker daemon is unavailable: %w", err)
	}
	if result.ExitCode != 0 || strings.TrimSpace(string(result.Stdout)) == "" {
		return fmt.Errorf("docker daemon check failed: %s", safeDiagnostic(result.Stderr))
	}
	if _, _, err := runner.imageDetails(ctx, RunnerImage); err != nil {
		return fmt.Errorf("runner image %s is missing; run `make runner` from the repository", RunnerImage)
	}
	return nil
}

func (runner *DockerRunner) Capture(ctx context.Context, spec npm.Spec, config Config) (model.Profile, error) {
	if config.Timeout < 10*time.Second || config.Timeout > 10*time.Minute {
		return model.Profile{}, errors.New("capture timeout must be between 10 seconds and 10 minutes")
	}
	captureContext, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	profile := model.NewProfile(model.Subject{
		Ecosystem: "npm", Name: spec.Name, Version: spec.Version, PURL: spec.PURL(),
	}, config.ToolVersion)
	profile.Capture.RunnerImage = RunnerImage
	profile.Capture.SandboxProfile = SandboxProfile
	profile.Capture.TraceIntegrity = "isolated-root-tracer"
	profile.Capture.Experimental = true
	if err := runner.Doctor(captureContext); err != nil {
		return timedOutProfile(profile, captureContext, err)
	}
	runID, err := randomID()
	if err != nil {
		return profile, err
	}
	prepContainer := "behaviorlock-prep-" + runID
	traceContainer := "behaviorlock-trace-" + runID
	temporaryImage := "behaviorlock-analysis:" + runID
	defer runner.cleanup(prepContainer, traceContainer, temporaryImage)

	runnerImageID, architecture, err := runner.imageDetails(captureContext, RunnerImage)
	if err != nil {
		return timedOutProfile(profile, captureContext, err)
	}
	runnerMetadata, err := runner.runnerMetadata(captureContext, runnerImageID)
	if err != nil {
		return timedOutProfile(profile, captureContext, err)
	}
	profile.Capture.RunnerImageID = runnerImageID
	profile.Capture.Architecture = architecture
	profile.Capture.NodeVersion = runnerMetadata.Node
	profile.Capture.NPMVersion = runnerMetadata.NPM
	profile.Capture.StraceVersion = runnerMetadata.Strace

	prepareArgs := buildPrepareArgs(prepContainer, runnerImageID, spec.String())
	created, err := runner.run(captureContext, prepareArgs, 64<<10, maxPreparationLog)
	if err != nil || created.ExitCode != 0 {
		return timedOutProfile(profile, captureContext, fmt.Errorf("create preparation container: %s", safeDiagnostic(created.Stderr)))
	}
	prepared, err := runner.run(captureContext, []string{"start", "--attach", prepContainer}, maxPreparationLog, maxPreparationLog)
	if err != nil || prepared.ExitCode != 0 || prepared.Truncated {
		return timedOutProfile(profile, captureContext, fmt.Errorf("prepare package without lifecycle scripts: %s", safeDiagnostic(prepared.Stderr)))
	}
	metadata, err := parsePrepareMetadata(prepared.Stdout)
	if err != nil {
		return profile, err
	}
	profile.Subject.RegistryIntegrity = metadata.Integrity
	profile.Subject.DependencyLockSHA256 = metadata.DependencyLockSHA256
	committed, err := runner.run(captureContext, []string{"commit", "--pause=true", prepContainer, temporaryImage}, 64<<10, 64<<10)
	if err != nil || committed.ExitCode != 0 {
		return timedOutProfile(profile, captureContext, fmt.Errorf("commit disposable preparation image: %s", safeDiagnostic(committed.Stderr)))
	}
	preparedImageID := strings.TrimSpace(string(committed.Stdout))
	if !validSHA256(preparedImageID) {
		return profile, errors.New("committed preparation image did not resolve to a content ID")
	}
	_, _ = runner.run(captureContext, []string{"rm", "--force", prepContainer}, 64<<10, 64<<10)

	started := time.Now()
	traced, runErr := runner.run(captureContext, buildTraceArgs(traceContainer, preparedImageID, spec.String()), maxTraceStream, 1<<20)
	duration := time.Since(started)
	profile.Capture.DurationMillis = duration.Milliseconds()

	if errors.Is(captureContext.Err(), context.DeadlineExceeded) {
		profile.Result = model.Result{Status: "timed_out", ExitCode: 2, TimedOut: true, Message: "capture exceeded its wall clock limit"}
		return profile, errors.New("capture timed out and was marked incomplete")
	}
	if runErr != nil || traced.ExitCode != 0 {
		profile.Result = model.Result{Status: "trace_incomplete", ExitCode: 2, Message: safeDiagnostic(traced.Stderr)}
		return profile, fmt.Errorf("trace container failed before a verified completion marker")
	}
	if traced.Truncated {
		profile.Result = model.Result{Status: "trace_incomplete", ExitCode: 2, Truncated: true, Message: "trace output exceeded the capture limit"}
		return profile, errors.New("trace output was truncated and cannot produce a verdict")
	}
	parsed, raw, commandExit, err := trace.ParseEnvelope(traced.Stdout)
	if err != nil {
		profile.Result = model.Result{Status: "trace_incomplete", ExitCode: 2, Message: err.Error()}
		return profile, fmt.Errorf("parse trace envelope: %w", err)
	}
	sum := sha256.Sum256(raw)
	profile.Capture.RawTraceSHA256 = "sha256:" + hex.EncodeToString(sum[:])
	profile.Behaviors = parsed.Behaviors
	profile.Result = model.Result{Status: "complete", ExitCode: commandExit}
	if commandExit != 0 {
		profile.Result.Status = "command_failed"
		profile.Result.Message = "the selected lifecycle command returned a nonzero exit code"
	}
	profile.Normalize()
	return profile, nil
}

func buildPrepareArgs(containerName, runnerImageID, packageSpec string) []string {
	arguments := []string{
		"create",
		"--name", containerName,
		"--network", "bridge",
		"--user", "65532:65532",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--pids-limit", "128",
		"--memory", "768m",
		"--memory-swap", "768m",
		"--cpus", "1",
		"--ulimit", "nofile=1024:1024",
		"--ulimit", "nproc=128:128",
		"--ulimit", "core=0:0",
		"--shm-size", "16m",
		"--ipc", "none",
		"--env", "HOME=/home/scanner",
		"--env", "npm_config_cache=/seed/.npm-cache",
		"--env", "npm_config_userconfig=/dev/null",
		"--env", "npm_config_audit=false",
		"--env", "npm_config_fund=false",
		"--env", "npm_config_update_notifier=false",
	}
	arguments = appendScrubbedProxyEnvironment(arguments)
	return append(arguments, runnerImageID, "prepare", packageSpec)
}

func buildTraceArgs(containerName, image, packageSpec string) []string {
	arguments := []string{
		"run", "--name", containerName,
		"--network", "none",
		"--read-only",
		"--user", "0:0",
		"--cap-drop", "ALL",
		"--cap-add", "SETUID",
		"--cap-add", "SETGID",
		"--cap-add", "SYS_PTRACE",
		"--security-opt", "no-new-privileges:true",
		"--pids-limit", "128",
		"--memory", "512m",
		"--memory-swap", "512m",
		"--cpus", "1",
		"--ulimit", "nofile=1024:1024",
		"--ulimit", "nproc=128:128",
		"--ulimit", "core=0:0",
		"--shm-size", "16m",
		"--ipc", "none",
		"--tmpfs", "/work:rw,exec,nosuid,nodev,size=384m,uid=65532,gid=65532,mode=0700",
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=96m,uid=0,gid=0,mode=1777",
		"--tmpfs", "/home/scanner:rw,nosuid,nodev,size=8m,uid=65532,gid=65532,mode=0700",
		"--tmpfs", "/trace:rw,nosuid,nodev,noexec,size=128m,uid=0,gid=0,mode=0700",
		"--env", "HOME=/home/scanner",
		"--env", "npm_config_cache=/work/.npm-cache",
		"--env", "npm_config_userconfig=/dev/null",
		"--env", "npm_config_audit=false",
		"--env", "npm_config_fund=false",
		"--env", "npm_config_update_notifier=false",
	}
	arguments = appendScrubbedProxyEnvironment(arguments)
	return append(arguments, image, "trace", packageSpec)
}

func appendScrubbedProxyEnvironment(arguments []string) []string {
	for _, name := range []string{
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "all_proxy", "no_proxy",
	} {
		arguments = append(arguments, "--env", name+"=")
	}
	return arguments
}

func (runner *DockerRunner) imageDetails(ctx context.Context, image string) (string, string, error) {
	result, err := runner.run(ctx, []string{"image", "inspect", image, "--format", "{{json .}}"}, 64<<10, 64<<10)
	if err != nil || result.ExitCode != 0 {
		return "", "", fmt.Errorf("inspect runner image: %s", safeDiagnostic(result.Stderr))
	}
	var inspected imageInspect
	if err := json.Unmarshal(result.Stdout, &inspected); err != nil {
		return "", "", fmt.Errorf("decode runner image metadata: %w", err)
	}
	if !validSHA256(inspected.ID) {
		return "", "", errors.New("runner image did not resolve to a content ID")
	}
	if inspected.Architecture == "" || len(inspected.Architecture) > 64 {
		return "", "", errors.New("runner image architecture is missing")
	}
	return inspected.ID, inspected.Architecture, nil
}

func (runner *DockerRunner) runnerMetadata(ctx context.Context, runnerImageID string) (RunnerMetadata, error) {
	arguments := []string{
		"run", "--rm", "--network", "none", "--read-only", "--user", "65532:65532",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
	}
	arguments = appendScrubbedProxyEnvironment(arguments)
	arguments = append(arguments, runnerImageID, "version")
	result, err := runner.run(ctx, arguments, 64<<10, 64<<10)
	if err != nil || result.ExitCode != 0 {
		return RunnerMetadata{}, fmt.Errorf("read runner versions: %s", safeDiagnostic(result.Stderr))
	}
	var metadata RunnerMetadata
	if err := json.Unmarshal(result.Stdout, &metadata); err != nil {
		return RunnerMetadata{}, fmt.Errorf("decode runner versions: %w", err)
	}
	if metadata.Node == "" || metadata.NPM == "" || metadata.Strace == "" {
		return RunnerMetadata{}, errors.New("runner version metadata is incomplete")
	}
	return metadata, nil
}

func (runner *DockerRunner) cleanup(containers ...string) {
	cleanupContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for index, value := range containers {
		if value == "" {
			continue
		}
		if index < 2 {
			_, _ = runner.run(cleanupContext, []string{"rm", "--force", value}, 64<<10, 64<<10)
			continue
		}
		_, _ = runner.run(cleanupContext, []string{"image", "rm", "--force", value}, 64<<10, 64<<10)
	}
}

func (runner *DockerRunner) runCommand(ctx context.Context, arguments []string, stdoutLimit, stderrLimit int64) (commandResult, error) {
	// #nosec G204 -- docker is resolved without a shell; every argument vector is built internally after strict package-spec validation.
	command := exec.CommandContext(ctx, runner.dockerPath, arguments...)
	stdout := newBoundedBuffer(stdoutLimit)
	stderr := newBoundedBuffer(stderrLimit)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	result := commandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Truncated: stdout.Truncated() || stderr.Truncated()}
	if command.ProcessState != nil {
		result.ExitCode = command.ProcessState.ExitCode()
	} else {
		result.ExitCode = 2
	}
	var exitError *exec.ExitError
	if err != nil && !errors.As(err, &exitError) {
		return result, err
	}
	return result, nil
}

func parsePrepareMetadata(output []byte) (PrepareMetadata, error) {
	const prefix = "BEHAVIORLOCK_PREP_V1 "
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		var metadata PrepareMetadata
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, prefix)), &metadata); err != nil {
			return PrepareMetadata{}, fmt.Errorf("decode preparation metadata: %w", err)
		}
		if !model.ValidRegistryIntegrity(metadata.Integrity) {
			return PrepareMetadata{}, errors.New("npm registry integrity metadata is missing or unsupported")
		}
		if !validSHA256(metadata.DependencyLockSHA256) {
			return PrepareMetadata{}, errors.New("dependency lock digest is missing or invalid")
		}
		return metadata, nil
	}
	return PrepareMetadata{}, errors.New("preparation metadata marker is missing")
}

func timedOutProfile(profile model.Profile, ctx context.Context, cause error) (model.Profile, error) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		profile.Result = model.Result{Status: "timed_out", ExitCode: 2, TimedOut: true, Message: "capture exceeded its wall clock limit"}
		return profile, errors.New("capture timed out and was marked incomplete")
	}
	return profile, cause
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func randomID() (string, error) {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate run identifier: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func safeDiagnostic(value []byte) string {
	value = bytes.TrimSpace(value)
	if len(value) > 1024 {
		value = value[len(value)-1024:]
	}
	var builder strings.Builder
	for _, character := range string(value) {
		if character < 0x20 && character != '\n' && character != '\t' {
			builder.WriteString("?")
			continue
		}
		if character == '\r' {
			builder.WriteString("\\r")
			continue
		}
		builder.WriteRune(character)
	}
	return strings.TrimSpace(builder.String())
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	remaining int64
	truncated bool
}

func newBoundedBuffer(limit int64) *boundedBuffer {
	return &boundedBuffer{remaining: limit}
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	if buffer.remaining <= 0 {
		buffer.truncated = true
		return originalLength, nil
	}
	if int64(len(value)) > buffer.remaining {
		value = value[:buffer.remaining]
		buffer.truncated = true
	}
	_, _ = buffer.buffer.Write(value)
	buffer.remaining -= int64(len(value))
	return originalLength, nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	return append([]byte(nil), buffer.buffer.Bytes()...)
}

func (buffer *boundedBuffer) Truncated() bool {
	return buffer.truncated
}

var _ io.Writer = (*boundedBuffer)(nil)

func ExitCodeString(code int) string {
	return strconv.Itoa(code)
}
