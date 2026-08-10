package capture

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kiranmagic7/behaviorlock/internal/model"
)

const sinkholePolicy = "inert-sinkhole-v1"

type sinkholeAudit struct {
	Kind      string   `json:"kind"`
	CanaryIDs []string `json:"canaryIds"`
}

func encodeSinkholeCanaries(canaries []canarySpec) (string, error) {
	entries := make([]struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}, 0, len(canaries))
	for _, canary := range canaries {
		entries = append(entries, struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		}{ID: canary.Descriptor.ID, Value: canary.Value})
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return "", fmt.Errorf("encode sinkhole canaries: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func buildSinkholeArgs(containerName, runnerImageID string, canaries []canarySpec) ([]string, error) {
	encoded, err := encodeSinkholeCanaries(canaries)
	if err != nil {
		return nil, err
	}
	arguments := []string{
		"run", "--detach",
		"--name", containerName,
		"--network", "none",
		"--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
		"--read-only",
		"--user", "0:0",
		"--cap-drop", "ALL",
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
		"--env", "BEHAVIORLOCK_SINKHOLE_CANARIES=" + encoded,
	}
	arguments = appendScrubbedProxyEnvironment(arguments)
	return append(arguments, runnerImageID, "sinkhole"), nil
}

func (runner *DockerRunner) startSinkhole(ctx context.Context, containerName, runnerImageID string, canaries []canarySpec) error {
	arguments, err := buildSinkholeArgs(containerName, runnerImageID, canaries)
	if err != nil {
		return err
	}
	started, err := runner.run(ctx, arguments, 64<<10, 64<<10)
	if err != nil || started.ExitCode != 0 || strings.TrimSpace(string(started.Stdout)) == "" {
		return fmt.Errorf("start inert sinkhole: %s", safeDiagnostic(started.Stderr))
	}
	for attempt := 0; attempt < 100; attempt++ {
		logs, logErr := runner.run(ctx, []string{"logs", containerName}, 1<<20, 64<<10)
		if logErr == nil && logs.ExitCode == 0 && len(bytes.TrimSpace(logs.Stderr)) != 0 {
			return fmt.Errorf("sinkhole emitted startup diagnostics: %s", safeDiagnostic(logs.Stderr))
		}
		if logErr == nil && logs.ExitCode == 0 && strings.Contains(string(logs.Stdout), "BEHAVIORLOCK_SINKHOLE_READY_V1 "+sinkholePolicy) {
			return nil
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	logs, logErr := runner.run(ctx, []string{"logs", containerName}, 1<<20, 64<<10)
	if logErr != nil {
		return fmt.Errorf("inert sinkhole did not become ready; read startup diagnostics: %w", logErr)
	}
	if diagnostic := safeDiagnostic(logs.Stderr); diagnostic != "" {
		return fmt.Errorf("inert sinkhole did not become ready: %s", diagnostic)
	}
	if logs.ExitCode != 0 {
		return fmt.Errorf("inert sinkhole did not become ready; docker logs exited %d", logs.ExitCode)
	}
	return errors.New("inert sinkhole did not become ready without diagnostics")
}

func (runner *DockerRunner) readSinkholeAudit(containerName string, canaries []canarySpec) (model.SinkholeInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	logs, err := runner.run(ctx, []string{"logs", containerName}, 1<<20, 64<<10)
	if err != nil || logs.ExitCode != 0 || logs.Truncated {
		return model.SinkholeInfo{}, fmt.Errorf("read bounded sinkhole audit: %s", safeDiagnostic(logs.Stderr))
	}
	if len(bytes.TrimSpace(logs.Stderr)) != 0 {
		return model.SinkholeInfo{}, fmt.Errorf("sinkhole emitted diagnostics: %s", safeDiagnostic(logs.Stderr))
	}
	known := make(map[string]struct{}, len(canaries))
	for _, canary := range canaries {
		known[canary.Descriptor.ID] = struct{}{}
	}
	info := model.SinkholeInfo{Mode: "loopback-no-route", ResponderVersion: sinkholePolicy, CanaryIDs: []string{}}
	ready := false
	const prefix = "BEHAVIORLOCK_SINKHOLE_V1 "
	for _, line := range strings.Split(string(logs.Stdout), "\n") {
		if line == "BEHAVIORLOCK_SINKHOLE_READY_V1 "+sinkholePolicy {
			ready = true
			continue
		}
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, prefix)))
		decoder.DisallowUnknownFields()
		var event sinkholeAudit
		if err := decoder.Decode(&event); err != nil {
			return model.SinkholeInfo{}, fmt.Errorf("decode sinkhole audit: %w", err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return model.SinkholeInfo{}, errors.New("decode sinkhole audit: trailing JSON value")
		}
		switch event.Kind {
		case "dns":
			info.DNSRequests++
		case "http":
			info.HTTPRequests++
			info.TCPConnections++
		case "tcp":
			info.TCPConnections++
		default:
			return model.SinkholeInfo{}, errors.New("sinkhole audit kind is invalid")
		}
		if info.DNSRequests > 10_000 || info.HTTPRequests > 10_000 || info.TCPConnections > 10_000 {
			return model.SinkholeInfo{}, errors.New("sinkhole audit exceeds its event bound")
		}
		for _, canaryID := range event.CanaryIDs {
			if _, exists := known[canaryID]; !exists {
				return model.SinkholeInfo{}, errors.New("sinkhole audit references an unknown canary")
			}
			info.CanaryIDs = append(info.CanaryIDs, canaryID)
		}
	}
	if !ready {
		return model.SinkholeInfo{}, errors.New("sinkhole readiness evidence is missing")
	}
	return info, nil
}
