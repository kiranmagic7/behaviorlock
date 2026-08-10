package capture

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kiranmagic7/behaviorlock/internal/model"
	"github.com/kiranmagic7/behaviorlock/internal/npm"
	"github.com/kiranmagic7/behaviorlock/internal/trace"
)

const (
	RunnerImage             = "behaviorlock-runner:dev"
	SandboxProfile          = "behaviorlock-linux-npm-v1"
	AcquisitionPolicy       = "npm-registry-connect-v1"
	AcquisitionAuthority    = "registry.npmjs.org:443"
	acquisitionProxyAddress = "http://127.0.0.1:8080"
	maxPreparationLog       = 4 << 20
	maxTraceStream          = trace.MaxTraceBytes + (1 << 20)
)

type Config struct {
	Timeout     time.Duration
	ToolVersion string
	RunnerImage string
	Phase       string
	Sinkhole    bool
}

type PrepareMetadata struct {
	Integrity                string `json:"integrity"`
	DependencyLockSHA256     string `json:"dependencyLockSha256"`
	AcquisitionPolicyVersion string `json:"acquisitionPolicyVersion"`
	AllowedAuthority         string `json:"allowedAuthority"`
	ImportEntrypoint         string `json:"importEntrypoint"`
	ImportModuleKind         string `json:"importModuleKind"`
	ImportResolverVersion    string `json:"importResolverVersion"`
	ImportSupport            string `json:"importSupport"`
	ImportReason             string `json:"importReason"`
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

type containerState struct {
	OOMKilled bool   `json:"OOMKilled"`
	ExitCode  int    `json:"ExitCode"`
	Error     string `json:"Error"`
}

type cleanupTargets struct {
	containers []string
	images     []string
	volumes    []string
	networks   []string
}

type proxyAudit struct {
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
	Authority string `json:"authority"`
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

func (runner *DockerRunner) Doctor(ctx context.Context, runnerImage string) error {
	runnerImage, err := normalizeRunnerImage(runnerImage)
	if err != nil {
		return err
	}
	if err := runner.checkDocker(ctx); err != nil {
		return err
	}
	if _, _, err := runner.imageDetails(ctx, runnerImage); err != nil {
		return fmt.Errorf("runner image %s is missing or invalid; build it or provide --runner: %w", runnerImage, err)
	}
	return nil
}

func (runner *DockerRunner) checkDocker(ctx context.Context) error {
	result, err := runner.run(ctx, []string{"version", "--format", "{{.Server.Version}}"}, 64<<10, 64<<10)
	if err != nil {
		return fmt.Errorf("docker daemon is unavailable: %w", err)
	}
	if result.ExitCode != 0 || strings.TrimSpace(string(result.Stdout)) == "" {
		return fmt.Errorf("docker daemon check failed: %s", safeDiagnostic(result.Stderr))
	}
	return nil
}

func (runner *DockerRunner) Capture(ctx context.Context, spec npm.Spec, config Config) (model.Profile, error) {
	profile, _, err := runner.CaptureWithEvidence(ctx, spec, config)
	return profile, err
}

func (runner *DockerRunner) CaptureWithEvidence(ctx context.Context, spec npm.Spec, config Config) (model.Profile, []byte, error) {
	if config.Timeout < 10*time.Second || config.Timeout > 10*time.Minute {
		return model.Profile{}, nil, errors.New("capture timeout must be between 10 seconds and 10 minutes")
	}
	if config.Phase == "" {
		config.Phase = "lifecycle"
	}
	if config.Phase != "lifecycle" && config.Phase != "import" {
		return model.Profile{}, nil, errors.New("capture phase must be lifecycle or import")
	}
	runnerImage, err := normalizeRunnerImage(config.RunnerImage)
	if err != nil {
		return model.Profile{}, nil, err
	}
	captureContext, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	profile := model.NewProfile(model.Subject{
		Ecosystem: "npm", Name: spec.Name, Version: spec.Version, PURL: spec.PURL(),
	}, config.ToolVersion)
	profile.Capture.RunnerImage = runnerImage
	profile.Capture.SandboxProfile = SandboxProfile
	profile.Capture.TraceIntegrity = "isolated-root-tracer"
	profile.Capture.Phase = config.Phase
	if config.Phase == "import" {
		profile.Capture.Coverage = model.CaptureCoverage{
			Scope: "registry-import-entrypoint", Lifecycle: []string{}, Completeness: "partial",
			Limitations: []string{
				"Only behavior exercised while loading the resolved package entry point is observed.",
				"strace changes timing and can be detected by package code.",
				"Environment variable reads are not observable unless a value becomes visible in an observed argument or path.",
			},
		}
	}
	profile.Capture.Experimental = true
	if err := runner.checkDocker(captureContext); err != nil {
		return withoutEvidence(timedOutProfile(profile, captureContext, err))
	}
	runID, err := randomID()
	if err != nil {
		return profile, nil, err
	}
	canaries, err := newCanarySet(rand.Reader)
	if err != nil {
		return profile, nil, err
	}
	profile.Capture.Canaries = canaryDescriptors(canaries)
	prepContainer := "behaviorlock-prep-" + runID
	traceContainer := "behaviorlock-trace-" + runID
	proxyContainer := "behaviorlock-proxy-" + runID
	sinkholeContainer := "behaviorlock-sinkhole-" + runID
	temporaryImage := "behaviorlock-analysis:" + runID
	egressNetwork := "behaviorlock-acq-egress-" + runID
	proxyVolume := "behaviorlock-acq-socket-" + runID
	defer runner.cleanup(cleanupTargets{
		containers: []string{prepContainer, traceContainer, proxyContainer, sinkholeContainer},
		images:     []string{temporaryImage},
		volumes:    []string{proxyVolume},
		networks:   []string{egressNetwork},
	})

	runnerImageID, architecture, err := runner.imageDetails(captureContext, runnerImage)
	if err != nil {
		return withoutEvidence(timedOutProfile(profile, captureContext, err))
	}
	runnerMetadata, err := runner.runnerMetadata(captureContext, runnerImageID)
	if err != nil {
		return withoutEvidence(timedOutProfile(profile, captureContext, err))
	}
	profile.Capture.RunnerImageID = runnerImageID
	profile.Capture.Architecture = architecture
	profile.Capture.NodeVersion = runnerMetadata.Node
	profile.Capture.NPMVersion = runnerMetadata.NPM
	profile.Capture.StraceVersion = runnerMetadata.Strace
	if err := runner.startAcquisitionProxy(captureContext, proxyContainer, egressNetwork, proxyVolume, runnerImageID); err != nil {
		return withoutEvidence(timedOutProfile(profile, captureContext, err))
	}
	profile.Capture.Acquisition = &model.AcquisitionInfo{
		NetworkMode:        "registry-proxy-unix",
		PolicyVersion:      AcquisitionPolicy,
		AllowedAuthority:   AcquisitionAuthority,
		ProxyRunnerImageID: runnerImageID,
	}

	prepareArgs := buildPrepareArgs(prepContainer, proxyVolume, runnerImageID, spec.String())
	created, err := runner.run(captureContext, prepareArgs, 64<<10, maxPreparationLog)
	if err != nil || created.ExitCode != 0 {
		return withoutEvidence(timedOutProfile(profile, captureContext, fmt.Errorf("create preparation container: %s", safeDiagnostic(created.Stderr))))
	}
	prepared, err := runner.run(captureContext, []string{"start", "--attach", prepContainer}, maxPreparationLog, maxPreparationLog)
	if err != nil || prepared.ExitCode != 0 || prepared.Truncated {
		return withoutEvidence(timedOutProfile(profile, captureContext, fmt.Errorf("prepare package without lifecycle scripts: %s", safeDiagnostic(prepared.Stderr))))
	}
	if err := runner.verifyAcquisitionProxyAudit(captureContext, proxyContainer); err != nil {
		return profile, nil, err
	}
	metadata, err := parsePrepareMetadata(prepared.Stdout)
	if err != nil {
		return profile, nil, err
	}
	if metadata.ImportSupport == "supported" && !strings.HasPrefix(metadata.ImportEntrypoint, "$WORK/node_modules/"+spec.Name+"/") {
		return profile, nil, errors.New("resolved import entry point is outside the selected package")
	}
	profile.Subject.RegistryIntegrity = metadata.Integrity
	profile.Subject.DependencyLockSHA256 = metadata.DependencyLockSHA256
	if config.Phase == "import" {
		profile.Capture.Import = &model.ImportInfo{
			Entrypoint: metadata.ImportEntrypoint, ModuleKind: metadata.ImportModuleKind,
			ResolverVersion: metadata.ImportResolverVersion, Support: metadata.ImportSupport, Reason: metadata.ImportReason,
		}
		if metadata.ImportSupport != "supported" {
			profile.Result = model.Result{Status: "unsupported", ExitCode: 2, Message: "the installed package entry point is unsupported for import observation"}
			profile.Normalize()
			return profile, nil, errors.New("package entry point is unsupported for import observation")
		}
	}
	committed, err := runner.run(captureContext, []string{"commit", "--pause=true", prepContainer, temporaryImage}, 64<<10, 64<<10)
	if err != nil || committed.ExitCode != 0 {
		return withoutEvidence(timedOutProfile(profile, captureContext, fmt.Errorf("commit disposable preparation image: %s", safeDiagnostic(committed.Stderr))))
	}
	preparedImageID := strings.TrimSpace(string(committed.Stdout))
	if !validSHA256(preparedImageID) {
		return profile, nil, errors.New("committed preparation image did not resolve to a content ID")
	}
	if err := runner.retireAcquisition(captureContext, prepContainer, proxyContainer, proxyVolume, egressNetwork); err != nil {
		return profile, nil, err
	}
	traceNetwork := "none"
	if config.Sinkhole {
		if err := runner.startSinkhole(captureContext, sinkholeContainer, runnerImageID, canaries); err != nil {
			return withoutEvidence(timedOutProfile(profile, captureContext, err))
		}
		traceNetwork = "container:" + sinkholeContainer
		profile.Capture.NetworkMode = "sinkhole-loopback-v1"
		profile.Capture.Sinkhole = &model.SinkholeInfo{Mode: "loopback-no-route", ResponderVersion: sinkholePolicy, CanaryIDs: []string{}}
	}

	started := time.Now()
	traced, runErr := runner.run(captureContext, buildTraceArgs(traceContainer, preparedImageID, spec.String(), profile.Capture.Phase, traceNetwork, canaries), maxTraceStream, 1<<20)
	duration := time.Since(started)
	profile.Capture.DurationMillis = duration.Milliseconds()

	var inspectedState *containerState
	if captureContext.Err() == nil {
		if state, inspectErr := runner.inspectContainerState(traceContainer); inspectErr == nil {
			inspectedState = &state
		}
	}
	var sinkholeErr error
	if config.Sinkhole {
		info, auditErr := runner.readSinkholeAudit(sinkholeContainer, canaries)
		if auditErr != nil {
			sinkholeErr = auditErr
		} else {
			profile.Capture.Sinkhole = &info
		}
	}
	if result, failure := classifyTraceFailure(captureContext.Err(), traced, runErr, inspectedState); failure != nil {
		profile.Result = result
		return profile, nil, failure
	}
	if sinkholeErr != nil {
		profile.Result = model.Result{Status: "trace_incomplete", ExitCode: 2, Message: "sinkhole audit could not be verified"}
		return profile, nil, sinkholeErr
	}
	parsed, raw, commandExit, err := trace.ParseEnvelope(traced.Stdout)
	if err != nil {
		profile.Result = model.Result{Status: "trace_incomplete", ExitCode: 2, Message: err.Error()}
		return profile, nil, fmt.Errorf("parse trace envelope: %w", err)
	}
	applyCanaryObservations(parsed.Behaviors, canaries)
	profile.Behaviors = parsed.Behaviors
	profile.Sequences = model.BuildObservationSequences(parsed.Behaviors)
	model.AttachEvidence(&profile, raw, "retained", "behaviorlock-trace-v1-payload")
	profile.Result = model.Result{Status: "complete", ExitCode: commandExit}
	if commandExit != 0 {
		profile.Result.Status = "command_failed"
		profile.Result.Message = "the selected observation command returned a nonzero exit code"
	}
	profile.Normalize()
	return profile, raw, nil
}

func classifyTraceFailure(contextErr error, traced commandResult, runErr error, state *containerState) (model.Result, error) {
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return model.Result{Status: "timed_out", ExitCode: 2, TimedOut: true, Message: "capture exceeded its wall clock limit"},
			errors.New("capture timed out and was marked incomplete")
	}
	if errors.Is(contextErr, context.Canceled) {
		return model.Result{Status: "trace_incomplete", ExitCode: 2, Message: "capture was cancelled before completion"},
			errors.New("capture was cancelled and marked incomplete")
	}
	if state != nil && state.OOMKilled {
		return model.Result{Status: "resource_exhausted", ExitCode: 2, Message: "trace container exceeded its memory limit"},
			errors.New("trace container was OOM-killed and marked resource exhausted")
	}
	if traced.Truncated {
		return model.Result{Status: "trace_incomplete", ExitCode: 2, Truncated: true, Message: "trace output exceeded the capture limit"},
			errors.New("trace output was truncated and cannot produce a complete profile")
	}
	if runErr != nil || traced.ExitCode != 0 || (state != nil && state.ExitCode != 0) {
		exitCode := traced.ExitCode
		message := safeDiagnostic(traced.Stderr)
		if state != nil {
			if state.ExitCode != 0 {
				exitCode = state.ExitCode
			}
			if message == "" {
				message = safeDiagnostic([]byte(state.Error))
			}
		}
		if exitCode >= 128 {
			message = fmt.Sprintf("trace supervisor ended with signal-style exit code %d", exitCode)
		}
		if message == "" {
			message = "trace container exited before a verified completion marker"
		}
		return model.Result{Status: "trace_incomplete", ExitCode: 2, Message: message},
			errors.New("trace container failed before a verified completion marker")
	}
	return model.Result{}, nil
}

func withoutEvidence(profile model.Profile, err error) (model.Profile, []byte, error) {
	return profile, nil, err
}

func buildPrepareArgs(containerName, proxyVolume, runnerImageID, packageSpec string) []string {
	arguments := []string{
		"create",
		"--name", containerName,
		"--network", "none",
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
		"--mount", "type=volume,source=" + proxyVolume + ",target=/proxy,readonly,volume-nocopy",
		"--env", "HOME=/home/scanner",
		"--env", "npm_config_cache=/seed/.npm-cache",
		"--env", "npm_config_userconfig=/dev/null",
		"--env", "npm_config_audit=false",
		"--env", "npm_config_fund=false",
		"--env", "npm_config_update_notifier=false",
		"--env", "npm_config_registry=https://registry.npmjs.org/",
		"--env", "npm_config_strict_ssl=true",
	}
	arguments = appendAcquisitionProxyEnvironment(arguments)
	return append(arguments, runnerImageID, "prepare", packageSpec)
}

func buildProxyArgs(containerName, networkName, proxyVolume, runnerImageID string) []string {
	arguments := []string{
		"run", "--detach",
		"--name", containerName,
		"--network", networkName,
		"--read-only",
		"--user", "0:0",
		"--cap-drop", "ALL",
		"--cap-add", "CHOWN",
		"--cap-add", "SETUID",
		"--cap-add", "SETGID",
		"--security-opt", "no-new-privileges:true",
		"--pids-limit", "64",
		"--memory", "128m",
		"--memory-swap", "128m",
		"--cpus", "0.5",
		"--ulimit", "nofile=256:256",
		"--ulimit", "nproc=64:64",
		"--ulimit", "core=0:0",
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=8m,uid=65532,gid=65532,mode=0700",
		"--mount", "type=volume,source=" + proxyVolume + ",target=/proxy,volume-nocopy",
	}
	arguments = appendScrubbedProxyEnvironment(arguments)
	return append(arguments, runnerImageID, "proxy")
}

func buildTraceArgs(containerName, image, packageSpec, phase, networkMode string, canaries []canarySpec) []string {
	if networkMode != "none" && !strings.HasPrefix(networkMode, "container:behaviorlock-sinkhole-") {
		networkMode = "none"
	}
	arguments := []string{
		"run", "--name", containerName,
		"--network", networkMode,
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
		"--ulimit", "fsize=67108864:67108864",
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
	sinkholeEnabled := "0"
	if strings.HasPrefix(networkMode, "container:behaviorlock-sinkhole-") {
		sinkholeEnabled = "1"
	}
	arguments = append(arguments, "--env", "BEHAVIORLOCK_SINKHOLE_ENABLED="+sinkholeEnabled)
	arguments = appendCanaryEnvironment(arguments, canaries)
	return append(arguments, image, "trace", packageSpec, phase)
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

func appendAcquisitionProxyEnvironment(arguments []string) []string {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		arguments = append(arguments, "--env", name+"="+acquisitionProxyAddress)
	}
	for _, name := range []string{"ALL_PROXY", "NO_PROXY", "all_proxy", "no_proxy"} {
		arguments = append(arguments, "--env", name+"=")
	}
	arguments = append(arguments,
		"--env", "npm_config_proxy="+acquisitionProxyAddress,
		"--env", "npm_config_https_proxy="+acquisitionProxyAddress,
	)
	return arguments
}

func (runner *DockerRunner) startAcquisitionProxy(ctx context.Context, containerName, egressNetwork, proxyVolume, runnerImageID string) error {
	createdNetwork, err := runner.run(ctx, []string{"network", "create", "--driver", "bridge", egressNetwork}, 64<<10, 64<<10)
	if err != nil || createdNetwork.ExitCode != 0 || strings.TrimSpace(string(createdNetwork.Stdout)) == "" {
		return fmt.Errorf("create acquisition egress network: %s", safeDiagnostic(createdNetwork.Stderr))
	}
	createdVolume, err := runner.run(ctx, []string{"volume", "create", "--driver", "local", proxyVolume}, 64<<10, 64<<10)
	if err != nil || createdVolume.ExitCode != 0 || strings.TrimSpace(string(createdVolume.Stdout)) == "" {
		return fmt.Errorf("create acquisition socket volume: %s", safeDiagnostic(createdVolume.Stderr))
	}
	started, err := runner.run(ctx, buildProxyArgs(containerName, egressNetwork, proxyVolume, runnerImageID), 64<<10, 64<<10)
	if err != nil || started.ExitCode != 0 || strings.TrimSpace(string(started.Stdout)) == "" {
		return fmt.Errorf("start acquisition proxy: %s", safeDiagnostic(started.Stderr))
	}
	readyContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		logs, logErr := runner.run(readyContext, []string{"logs", containerName}, 64<<10, 64<<10)
		if logErr == nil && logs.ExitCode == 0 && strings.Contains(string(logs.Stdout), "BEHAVIORLOCK_PROXY_READY_V1 "+AcquisitionPolicy+" "+AcquisitionAuthority) {
			return nil
		}
		select {
		case <-readyContext.Done():
			return fmt.Errorf("acquisition proxy did not become ready: %s", safeDiagnostic(logs.Stderr))
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (runner *DockerRunner) verifyAcquisitionProxyAudit(ctx context.Context, containerName string) error {
	logs, err := runner.run(ctx, []string{"logs", containerName}, maxPreparationLog, 64<<10)
	if err != nil || logs.ExitCode != 0 || logs.Truncated || len(bytes.TrimSpace(logs.Stderr)) != 0 {
		return fmt.Errorf("read acquisition proxy audit: %s", safeDiagnostic(logs.Stderr))
	}
	allowed := false
	for _, line := range strings.Split(string(logs.Stdout), "\n") {
		const prefix = "BEHAVIORLOCK_PROXY_V1 "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		var event proxyAudit
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, prefix)), &event); err != nil {
			return fmt.Errorf("decode acquisition proxy audit: %w", err)
		}
		if event.Decision == "deny" {
			return fmt.Errorf("acquisition proxy denied a nonregistry or unsafe request: %s", safeDiagnostic([]byte(event.Reason)))
		}
		if event.Decision == "allow" && event.Reason == AcquisitionPolicy && event.Authority == AcquisitionAuthority {
			allowed = true
		}
	}
	if !allowed {
		return errors.New("acquisition proxy did not record an allowed registry tunnel")
	}
	return nil
}

func (runner *DockerRunner) retireAcquisition(ctx context.Context, preparationContainer, proxyContainer, proxyVolume, egressNetwork string) error {
	for _, target := range []struct {
		label     string
		arguments []string
	}{
		{label: "preparation container", arguments: []string{"rm", "--force", preparationContainer}},
		{label: "proxy container", arguments: []string{"rm", "--force", proxyContainer}},
	} {
		result, err := runner.run(ctx, target.arguments, 64<<10, 64<<10)
		if err != nil || result.ExitCode != 0 {
			return fmt.Errorf("remove acquisition %s: %s", target.label, safeDiagnostic(result.Stderr))
		}
	}
	for _, target := range []struct {
		label     string
		arguments []string
	}{
		{label: "socket volume", arguments: []string{"volume", "rm", "--force", proxyVolume}},
		{label: "egress network", arguments: []string{"network", "rm", egressNetwork}},
	} {
		result, err := runner.run(ctx, target.arguments, 64<<10, 64<<10)
		if err != nil || result.ExitCode != 0 {
			return fmt.Errorf("remove acquisition %s: %s", target.label, safeDiagnostic(result.Stderr))
		}
	}
	return nil
}

func (runner *DockerRunner) inspectContainerState(containerName string) (containerState, error) {
	inspectContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.run(inspectContext, []string{"inspect", "--format", "{{json .State}}", containerName}, 64<<10, 64<<10)
	if err != nil || result.ExitCode != 0 || result.Truncated {
		return containerState{}, fmt.Errorf("inspect trace container state: %s", safeDiagnostic(result.Stderr))
	}
	var state containerState
	if err := json.Unmarshal(result.Stdout, &state); err != nil {
		return containerState{}, fmt.Errorf("decode trace container state: %w", err)
	}
	if state.ExitCode < 0 || state.ExitCode > 255 || len(state.Error) > 4096 {
		return containerState{}, errors.New("trace container state is invalid")
	}
	return state, nil
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

func (runner *DockerRunner) cleanup(targets cleanupTargets) {
	cleanupContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, value := range targets.containers {
		if value == "" {
			continue
		}
		_, _ = runner.run(cleanupContext, []string{"rm", "--force", value}, 64<<10, 64<<10)
	}
	for _, value := range targets.images {
		if value == "" {
			continue
		}
		_, _ = runner.run(cleanupContext, []string{"image", "rm", "--force", value}, 64<<10, 64<<10)
	}
	for _, value := range targets.volumes {
		if value == "" {
			continue
		}
		_, _ = runner.run(cleanupContext, []string{"volume", "rm", "--force", value}, 64<<10, 64<<10)
	}
	for _, value := range targets.networks {
		if value == "" {
			continue
		}
		_, _ = runner.run(cleanupContext, []string{"network", "rm", value}, 64<<10, 64<<10)
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
		decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, prefix)))
		decoder.DisallowUnknownFields()
		var metadata PrepareMetadata
		if err := decoder.Decode(&metadata); err != nil {
			return PrepareMetadata{}, fmt.Errorf("decode preparation metadata: %w", err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			if err == nil {
				return PrepareMetadata{}, errors.New("decode preparation metadata: trailing JSON value")
			}
			return PrepareMetadata{}, fmt.Errorf("decode preparation metadata trailing data: %w", err)
		}
		if !model.ValidRegistryIntegrity(metadata.Integrity) {
			return PrepareMetadata{}, errors.New("npm registry integrity metadata is missing or unsupported")
		}
		if !validSHA256(metadata.DependencyLockSHA256) {
			return PrepareMetadata{}, errors.New("dependency lock digest is missing or invalid")
		}
		if metadata.AcquisitionPolicyVersion != AcquisitionPolicy || metadata.AllowedAuthority != AcquisitionAuthority {
			return PrepareMetadata{}, errors.New("preparation acquisition policy marker is missing or invalid")
		}
		if metadata.ImportResolverVersion != "node-resolve-v1" {
			return PrepareMetadata{}, errors.New("preparation import resolver marker is missing or invalid")
		}
		if metadata.ImportSupport == "supported" {
			if !validPrepareText(metadata.ImportEntrypoint, 4096) || !strings.HasPrefix(metadata.ImportEntrypoint, "$WORK/node_modules/") ||
				strings.Contains(metadata.ImportEntrypoint, "/../") || (metadata.ImportModuleKind != "commonjs" && metadata.ImportModuleKind != "esm") || metadata.ImportReason != "" {
				return PrepareMetadata{}, errors.New("preparation import plan is inconsistent")
			}
		} else if metadata.ImportSupport != "unsupported" || metadata.ImportModuleKind != "unsupported" ||
			(metadata.ImportReason != "entrypoint-unresolved" && metadata.ImportReason != "unsupported-extension") {
			return PrepareMetadata{}, errors.New("preparation unsupported import plan is invalid")
		}
		return metadata, nil
	}
	return PrepareMetadata{}, errors.New("preparation metadata marker is missing")
}

func validPrepareText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
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

var runnerReferencePattern = regexp.MustCompile(`^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)*(?:[a-z0-9]+(?:[._-][a-z0-9]+)*)(?:(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})|(?:@sha256:[0-9a-f]{64}))$`)

func normalizeRunnerImage(value string) (string, error) {
	if value == "" {
		value = RunnerImage
	}
	if len(value) > 256 || strings.TrimSpace(value) != value || strings.HasPrefix(value, "-") ||
		strings.Contains(value, "://") || !runnerReferencePattern.MatchString(value) {
		return "", errors.New("runner image must be an explicit Docker tag, sha256 content ID, or @sha256 digest reference")
	}
	lastSlash := strings.LastIndexByte(value, '/')
	lastColon := strings.LastIndexByte(value, ':')
	if !strings.Contains(value, "@sha256:") && lastColon <= lastSlash {
		return "", errors.New("runner image must include an explicit non-latest tag or sha256 digest")
	}
	if strings.HasSuffix(value, ":latest") {
		return "", errors.New("runner image tag latest is not allowed")
	}
	return value, nil
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
