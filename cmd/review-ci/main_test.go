package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendOutputsRejectsWorkflowCommandLineInjection(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "github-output")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := appendOutputs(path, map[string]string{"baseline-package": "example@1.0.0\nname=attacker"}); err == nil {
		t.Fatal("newline output injection unexpectedly passed")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 0 {
		t.Fatalf("rejected output still wrote workflow data: %q", raw)
	}
}

func TestRunRejectsUnknownReviewCommand(t *testing.T) {
	t.Parallel()
	if err := run([]string{"execute-artifact"}); err == nil {
		t.Fatal("unknown review command unexpectedly passed")
	}
}
