package reviewci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDependencyReviewWorkflowsPreservePrivilegeSplit(t *testing.T) {
	t.Parallel()
	capture := readRepositoryFile(t, ".github/workflows/dependency-review-capture.yml")
	comment := readRepositoryFile(t, ".github/workflows/dependency-review-comment.yml")
	action := readRepositoryFile(t, ".github/actions/dependency-review/action.yml")
	combined := capture + "\n" + comment + "\n" + action
	for _, forbidden := range []string{
		"pull_request_target", "self-hosted", "id-token: write", "secrets: inherit", "--privileged", "/var/run/docker.sock",
		"checkout@main", "checkout@master", "verdict",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("dependency review automation contains forbidden token %q", forbidden)
		}
	}
	for _, required := range []string{
		"pull_request:", "permissions:\n  contents: read", "ref: ${{ github.event.pull_request.base.sha }}",
		"persist-credentials: false", "uses: ./.github/actions/dependency-review",
	} {
		if !strings.Contains(capture, required) {
			t.Fatalf("capture workflow is missing %q", required)
		}
	}
	for _, forbidden := range []string{"docker ", "npm ", "--experimental", "uses: ./.github/actions/"} {
		if strings.Contains(comment, forbidden) {
			t.Fatalf("privileged comment workflow can execute capture content through %q", forbidden)
		}
	}
	for _, required := range []string{
		"workflow_run:", "actions: read", "contents: read", "pull-requests: write",
		"ref: ${{ github.event.repository.default_branch }}", "go run ./cmd/review-ci verify",
		"github.event.workflow_run.id", "github-actions[bot]",
	} {
		if !strings.Contains(comment, required) {
			t.Fatalf("comment workflow is missing %q", required)
		}
	}
	for _, required := range []string{
		"threshold-reached:", "highest-review-level:", "added-count:", "skipped:",
		"baseline-profile-path:", "baseline-evidence-path:", "candidate-profile-path:",
		"candidate-evidence-path:", "diff-path:", "--fail-on none",
	} {
		if !strings.Contains(action, required) {
			t.Fatalf("local action is missing output or control %q", required)
		}
	}
}

func TestDependencyReviewRemoteActionsAreCommitPinned(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		".github/workflows/dependency-review-capture.yml",
		".github/workflows/dependency-review-comment.yml",
	} {
		content := readRepositoryFile(t, path)
		for _, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "uses: ") || strings.HasPrefix(trimmed, "uses: ./") {
				continue
			}
			if !regexp.MustCompile(`^uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}(?:\s+#.*)?$`).MatchString(trimmed) {
				t.Fatalf("%s contains an unpinned action: %s", path, trimmed)
			}
		}
	}
}

func readRepositoryFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", path))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
