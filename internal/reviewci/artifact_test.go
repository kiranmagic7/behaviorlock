package reviewci

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kiranmagic7/behaviorlock/internal/compare"
	"github.com/kiranmagic7/behaviorlock/internal/model"
)

const testIntegrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

var artifactEvidence = []byte("exec-one\nwrite-two\nread-three\nspare-four\n")

func TestBuildAndVerifyArtifactRecomputesEveryTrustedOutput(t *testing.T) {
	directory := t.TempDir()
	plan := writeReviewFixture(t, directory)
	identity := RunIdentity{Repository: plan.Repository, RunID: 123, RunAttempt: 2, SourceRunSHA: strings.Repeat("c", 40)}
	manifest, err := BuildArtifact(directory, identity, "high")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Result.Skipped || manifest.Result.AddedCount != 1 || manifest.Result.HighestReviewLevel == "none" || len(manifest.Files) != 6 {
		t.Fatalf("unexpected artifact manifest: %#v", manifest)
	}
	server := reviewAPIServer(t, plan, identity)
	defer server.Close()
	client, err := NewGitHubClient(server.URL, "token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	verified, comment, err := VerifyArtifact(context.Background(), directory, WorkflowRunRef{
		Repository: plan.Repository, RunID: identity.RunID, RunAttempt: identity.RunAttempt,
		SourceRunSHA: identity.SourceRunSHA, PullRequest: plan.Number,
	}, client)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Result.AddedCount != 1 || !strings.HasPrefix(comment, CommentMarker) ||
		strings.Contains(comment, "<script>") || !strings.Contains(comment, "not a package safety verdict") {
		t.Fatalf("unsafe or incomplete comment:\n%s", comment)
	}
	for name, changed := range map[string]WorkflowRunRef{
		"repository":   {Repository: "other/project", RunID: identity.RunID, RunAttempt: identity.RunAttempt, SourceRunSHA: identity.SourceRunSHA, PullRequest: plan.Number},
		"run":          {Repository: plan.Repository, RunID: 124, RunAttempt: identity.RunAttempt, SourceRunSHA: identity.SourceRunSHA, PullRequest: plan.Number},
		"attempt":      {Repository: plan.Repository, RunID: identity.RunID, RunAttempt: 3, SourceRunSHA: identity.SourceRunSHA, PullRequest: plan.Number},
		"commit":       {Repository: plan.Repository, RunID: identity.RunID, RunAttempt: identity.RunAttempt, SourceRunSHA: strings.Repeat("9", 40), PullRequest: plan.Number},
		"pull request": {Repository: plan.Repository, RunID: identity.RunID, RunAttempt: identity.RunAttempt, SourceRunSHA: identity.SourceRunSHA, PullRequest: 43},
	} {
		if _, _, err := VerifyArtifact(context.Background(), directory, changed, client); err == nil {
			t.Fatalf("mismatched %s unexpectedly passed artifact source validation", name)
		}
	}

	evidencePath := filepath.Join(directory, candidateEvidenceFilename)
	file, err := os.OpenFile(evidencePath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("tampered\n"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, _, err := VerifyArtifact(context.Background(), directory, WorkflowRunRef{
		Repository: plan.Repository, RunID: identity.RunID, RunAttempt: identity.RunAttempt,
		SourceRunSHA: identity.SourceRunSHA, PullRequest: plan.Number,
	}, client); err == nil {
		t.Fatal("tampered evidence unexpectedly passed privileged verification")
	}
}

func TestCapturePairRejectsRunnerAndAcquisitionDrift(t *testing.T) {
	t.Parallel()
	baseline := reviewProfile("1.0.0", false)
	candidate := reviewProfile("2.0.0", true)
	candidate.Capture.RunnerImageID = "sha256:" + strings.Repeat("f", 64)
	candidate.Capture.Acquisition.ProxyRunnerImageID = candidate.Capture.RunnerImageID
	if err := validateCapturePair(baseline, candidate); err == nil {
		t.Fatal("runner fingerprint drift unexpectedly passed")
	}
	candidate = reviewProfile("2.0.0", true)
	candidate.Capture.Acquisition.PolicyVersion = "npm-registry-connect-v2"
	if err := validateCapturePair(baseline, candidate); err == nil {
		t.Fatal("acquisition policy drift unexpectedly passed")
	}
}

func TestSkippedArtifactContainsNoExecutableOrProfileContent(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	plan := Plan{ProtocolVersion: ProtocolVersion, PullRequestRef: testReference(), Skipped: true, SkipReason: "no root exact-version npm dependency changed"}
	if err := WritePlan(filepath.Join(directory, planFilename), plan); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildArtifact(directory, RunIdentity{
		Repository: plan.Repository, RunID: 7, RunAttempt: 1, SourceRunSHA: strings.Repeat("c", 40),
	}, "high")
	if err != nil {
		t.Fatal(err)
	}
	comment, err := RenderComment(manifest, directory)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.Result.Skipped || len(manifest.Files) != 1 || !strings.Contains(comment, "Capture skipped") {
		t.Fatalf("manifest=%#v comment=%q", manifest, comment)
	}
}

func TestArtifactManifestRejectsUnknownFieldsAndUnexpectedFiles(t *testing.T) {
	directory := t.TempDir()
	plan := writeReviewFixture(t, directory)
	identity := RunIdentity{Repository: plan.Repository, RunID: 123, RunAttempt: 1, SourceRunSHA: strings.Repeat("c", 40)}
	if _, err := BuildArtifact(directory, identity, "high"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "attacker.sh"), []byte("exit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := readBoundedRegularFile(filepath.Join(directory, manifestFilename), 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	var manifest ArtifactManifest
	if err := decodeSingleJSON(raw, &manifest, true); err != nil {
		t.Fatal(err)
	}
	if err := verifyArtifactDirectory(directory, manifest); err == nil {
		t.Fatal("unexpected executable artifact file was accepted")
	}
	tampered := append([]byte(nil), raw...)
	tampered = []byte(strings.TrimSpace(string(tampered[:len(tampered)-2])) + `,"unexpected":true}`)
	if err := decodeSingleJSON(tampered, &manifest, true); err == nil {
		t.Fatal("unknown artifact manifest field unexpectedly passed")
	}
}

func writeReviewFixture(t *testing.T, directory string) Plan {
	t.Helper()
	plan, err := BuildPlan(testReference(),
		packageManifest("dependencies", "example", "1.0.0"),
		packageManifest("dependencies", "example", "2.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePlan(filepath.Join(directory, planFilename), plan); err != nil {
		t.Fatal(err)
	}
	baseline := reviewProfile("1.0.0", false)
	candidate := reviewProfile("2.0.0", true)
	if err := model.WriteJSON(filepath.Join(directory, baselineProfileFilename), baseline); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, baselineEvidenceFilename), artifactEvidence, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := model.WriteJSON(filepath.Join(directory, candidateProfileFilename), candidate); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, candidateEvidenceFilename), artifactEvidence, 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err = readVerifiedProfile(filepath.Join(directory, baselineProfileFilename), filepath.Join(directory, baselineEvidenceFilename))
	if err != nil {
		t.Fatal(err)
	}
	candidate, err = readVerifiedProfile(filepath.Join(directory, candidateProfileFilename), filepath.Join(directory, candidateEvidenceFilename))
	if err != nil {
		t.Fatal(err)
	}
	diff, err := compare.Profiles(baseline, candidate, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := model.WriteJSON(filepath.Join(directory, diffFilename), diff); err != nil {
		t.Fatal(err)
	}
	return plan
}

func reviewProfile(version string, includeCandidateBehavior bool) model.Profile {
	profile := model.NewProfile(model.Subject{
		Ecosystem: "npm", Name: "example", Version: version, PURL: "pkg:npm/example@" + version,
		RegistryIntegrity: testIntegrity, DependencyLockSHA256: "sha256:" + strings.Repeat("d", 64),
	}, "test")
	profile.Capture.RunnerImage = "behaviorlock-runner:test"
	profile.Capture.RunnerImageID = "sha256:" + strings.Repeat("e", 64)
	profile.Capture.Architecture = "amd64"
	profile.Capture.NodeVersion = "v22.1.0"
	profile.Capture.NPMVersion = "10.8.0"
	profile.Capture.StraceVersion = "6.1"
	profile.Capture.NetworkMode = "none"
	profile.Capture.Acquisition = &model.AcquisitionInfo{
		NetworkMode: "registry-proxy-unix", PolicyVersion: "npm-registry-connect-v1",
		AllowedAuthority: "registry.npmjs.org:443", ProxyRunnerImageID: profile.Capture.RunnerImageID,
	}
	profile.Result = model.Result{Status: "complete", ExitCode: 0}
	profile.Behaviors = []model.Behavior{{
		Type: "process.exec", Operation: "exec", Target: "/usr/bin/npm", Outcome: "success", Count: 1,
		Evidence: []model.EvidenceRef{model.NewEvidenceRef(1, []byte("exec-one\n"))}, SourceCall: "execve",
	}}
	if includeCandidateBehavior {
		profile.Behaviors = append(profile.Behaviors, model.Behavior{
			Type: "filesystem.write", Operation: "write", Target: "/tmp/|<script>[x](javascript:alert(1))::set-output",
			Outcome: "success", Count: 1, Evidence: []model.EvidenceRef{model.NewEvidenceRef(2, []byte("write-two\n"))}, SourceCall: "openat",
		})
	}
	model.AttachEvidence(&profile, artifactEvidence, "retained", "behaviorlock-trace-v1-payload")
	profile.Normalize()
	return profile
}

func reviewAPIServer(t *testing.T, plan Plan, identity RunIdentity) *httptest.Server {
	t.Helper()
	baseline := packageManifest("dependencies", "example", "1.0.0")
	candidate := packageManifest("dependencies", "example", "2.0.0")
	return httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/owner/project/pulls/42":
			fmt.Fprintf(response, `{"number":42,"base":{"sha":"%s","repo":{"full_name":"owner/project"}},"head":{"sha":"%s","repo":{"full_name":"contributor/project"}}}`,
				plan.BaseSHA, plan.HeadSHA)
		case "/repos/owner/project/contents/package.json":
			writeContentResponse(response, baseline)
		case "/repos/contributor/project/contents/package.json":
			writeContentResponse(response, candidate)
		case "/repos/owner/project/actions/runs/123/artifacts":
			fmt.Fprintf(response, `{"artifacts":[{"id":8,"name":"behaviorlock-review-123","size_in_bytes":8192,"expired":false,"digest":"sha256:%s","workflow_run":{"id":%d}}]}`,
				strings.Repeat("f", 64), identity.RunID)
		default:
			http.NotFound(response, request)
		}
	}))
}

func writeContentResponse(response http.ResponseWriter, content []byte) {
	fmt.Fprintf(response, `{"type":"file","encoding":"base64","size":%d,"content":"%s"}`,
		len(content), base64.StdEncoding.EncodeToString(content))
}
