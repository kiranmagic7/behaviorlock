package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnknownCommandFails(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"unknown"}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit = %d", exit)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCaptureRequiresExplicitExperimentalAcknowledgement(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"capture", "--package", "example@1.0.0"}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit = %d", exit)
	}
	if !strings.Contains(stderr.String(), "requires --experimental") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestProfileAndValidateRawTrace(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	tracePath := filepath.Join(directory, "trace")
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(tracePath, []byte("execve(\"/usr/bin/node\", [\"node\"], 0x0) = 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"profile", "--package", "example@1.0.0", "--trace", tracePath, "--output", profilePath}, &stdout, &stderr); exit != 0 {
		t.Fatalf("profile exit=%d stderr=%s", exit, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"validate", "--profile", profilePath}, &stdout, &stderr); exit != 0 {
		t.Fatalf("validate exit=%d stderr=%s", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pkg:npm/example@1.0.0") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestProfileRejectsEmptyExternalTrace(t *testing.T) {
	t.Parallel()
	tracePath := filepath.Join(t.TempDir(), "trace")
	if err := os.WriteFile(tracePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exit := Run([]string{"profile", "--package", "example@1.0.0", "--trace", tracePath}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit = %d", exit)
	}
	if !strings.Contains(stderr.String(), "no recognized events") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
