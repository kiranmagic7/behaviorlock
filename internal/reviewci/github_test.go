package reviewci

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGitHubClientFetchesOnlyBoundedStructuredData(t *testing.T) {
	t.Parallel()
	manifest := []byte(`{"dependencies":{"example":"1.0.0"}}`)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" || request.Method != http.MethodGet {
			t.Fatalf("unexpected GitHub request authentication or method")
		}
		switch request.URL.Path {
		case "/repos/owner/project/contents/package.json":
			if request.URL.Query().Get("ref") != strings.Repeat("a", 40) {
				t.Fatalf("unexpected manifest ref: %q", request.URL.RawQuery)
			}
			fmt.Fprintf(response, `{"type":"file","encoding":"base64","size":%d,"content":"%s"}`,
				len(manifest), base64.StdEncoding.EncodeToString(manifest))
		case "/repos/owner/project/pulls/42":
			fmt.Fprintf(response, `{"number":42,"base":{"sha":"%s","repo":{"full_name":"owner/project"}},"head":{"sha":"%s","repo":{"full_name":"fork/project"}}}`,
				strings.Repeat("a", 40), strings.Repeat("b", 40))
		case "/repos/owner/project/actions/runs/123/artifacts":
			if request.URL.Query().Get("per_page") != "100" {
				t.Fatal("artifact query is not bounded")
			}
			fmt.Fprintf(response, `{"artifacts":[{"id":9,"name":"behaviorlock-review-123","size_in_bytes":4096,"expired":false,"digest":"sha256:%s","workflow_run":{"id":123}}]}`,
				strings.Repeat("c", 64))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client, err := NewGitHubClient(server.URL, "test-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	gotManifest, err := client.FetchManifest(ctx, "owner/project", strings.Repeat("a", 40))
	if err != nil || string(gotManifest) != string(manifest) {
		t.Fatalf("manifest=%s err=%v", gotManifest, err)
	}
	reference, err := client.FetchPullRequest(ctx, "owner/project", 42)
	if err != nil || reference.HeadRepository != "fork/project" || reference.Number != 42 {
		t.Fatalf("reference=%#v err=%v", reference, err)
	}
	artifact, err := client.FetchArtifact(ctx, "owner/project", 123, "behaviorlock-review-123")
	if err != nil || artifact.ID != 9 || artifact.Size != 4096 {
		t.Fatalf("artifact=%#v err=%v", artifact, err)
	}
}

func TestGitHubClientRejectsMissingAndMalformedResources(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("case") {
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client, err := NewGitHubClient(server.URL, "token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchManifest(context.Background(), "owner/project", strings.Repeat("a", 40)); err != ErrNotFound {
		t.Fatalf("missing manifest error = %v", err)
	}
	for _, invalid := range []string{"http://api.github.com", "https://user@example.com", "not-a-url"} {
		if _, err := NewGitHubClient(invalid, "token", nil); err == nil {
			t.Fatalf("invalid GitHub API URL %q unexpectedly passed", invalid)
		}
	}
}

func TestGitHubClientDoesNotForwardTokenAcrossRedirects(t *testing.T) {
	t.Parallel()
	var reached atomic.Bool
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		reached.Store(true)
		response.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, receiver.URL, http.StatusFound)
	}))
	defer redirector.Close()
	client, err := NewGitHubClient(redirector.URL, "sensitive-token", redirector.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchManifest(context.Background(), "owner/project", strings.Repeat("a", 40)); err == nil {
		t.Fatal("redirecting GitHub API response unexpectedly passed")
	}
	if reached.Load() {
		t.Fatal("GitHub API redirect reached another origin")
	}
}

func TestParseWorkflowRunEventValidatesSourceIdentity(t *testing.T) {
	t.Parallel()
	valid := fmt.Sprintf(`{"action":"completed","repository":{"full_name":"owner/project"},"workflow_run":{"id":123,"run_attempt":2,"name":%q,"path":%q,"event":"pull_request","status":"completed","conclusion":"success","head_sha":"%s","repository":{"full_name":"owner/project"},"pull_requests":[{"number":42}]}}`,
		WorkflowName, WorkflowPath, strings.Repeat("d", 40))
	parsed, err := ParseWorkflowRunEvent([]byte(valid))
	if err != nil || parsed.RunID != 123 || parsed.PullRequest != 42 || parsed.RunAttempt != 2 {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	for _, replacement := range [][2]string{
		{`"conclusion":"success"`, `"conclusion":"failure"`},
		{`"event":"pull_request"`, `"event":"pull_request_target"`},
		{`"path":"` + WorkflowPath + `"`, `"path":".github/workflows/attacker.yml"`},
		{`"pull_requests":[{"number":42}]`, `"pull_requests":[]`},
	} {
		if _, err := ParseWorkflowRunEvent([]byte(strings.Replace(valid, replacement[0], replacement[1], 1))); err == nil {
			t.Fatalf("invalid workflow source unexpectedly passed: %s", replacement[1])
		}
	}
}
