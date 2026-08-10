package reviewci

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var ErrNotFound = errors.New("GitHub resource not found")

type GitHubClient struct {
	baseURL string
	token   string
	client  *http.Client
}

type WorkflowRunRef struct {
	Repository   string
	RunID        int64
	RunAttempt   int
	SourceRunSHA string
	PullRequest  int
}

type ArtifactMetadata struct {
	ID      int64
	Name    string
	Size    int64
	Digest  string
	Expired bool
}

func NewGitHubClient(baseURL, token string, client *http.Client) (*GitHubClient, error) {
	if token == "" || len(token) > 4096 {
		return nil, errors.New("GitHub token is missing or invalid")
	}
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("GitHub API URL must be an absolute HTTPS origin")
	}
	if client == nil {
		client = http.DefaultClient
	}
	boundedClient := *client
	boundedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &GitHubClient{baseURL: parsed.String(), token: token, client: &boundedClient}, nil
}

func (client *GitHubClient) FetchManifest(ctx context.Context, repository, revision string) ([]byte, error) {
	if !fullNamePattern.MatchString(repository) || !shaPattern.MatchString(revision) {
		return nil, errors.New("manifest repository or revision is invalid")
	}
	endpoint := client.baseURL + "/repos/" + repository + "/contents/package.json?ref=" + url.QueryEscape(revision)
	var response struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		Size     int64  `json:"size"`
	}
	if err := client.getJSON(ctx, endpoint, &response, 2<<20); err != nil {
		return nil, err
	}
	if response.Type != "file" || response.Encoding != "base64" || response.Size < 1 || response.Size > maxManifestSize {
		return nil, errors.New("GitHub package.json response is invalid")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(response.Content, "\n", ""))
	if err != nil || int64(len(decoded)) != response.Size {
		return nil, errors.New("GitHub package.json content is malformed")
	}
	return decoded, nil
}

func (client *GitHubClient) FetchPullRequest(ctx context.Context, repository string, number int) (PullRequestRef, error) {
	if !fullNamePattern.MatchString(repository) || number < 1 || number > 1_000_000_000 {
		return PullRequestRef{}, errors.New("pull request lookup is invalid")
	}
	endpoint := client.baseURL + "/repos/" + repository + "/pulls/" + strconv.Itoa(number)
	var response struct {
		Number int `json:"number"`
		Base   struct {
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"base"`
		Head struct {
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	}
	if err := client.getJSON(ctx, endpoint, &response, 2<<20); err != nil {
		return PullRequestRef{}, err
	}
	reference := PullRequestRef{
		Repository:     repository,
		Number:         response.Number,
		BaseRepository: response.Base.Repo.FullName,
		BaseSHA:        response.Base.SHA,
		HeadRepository: response.Head.Repo.FullName,
		HeadSHA:        response.Head.SHA,
	}
	if reference.Number != number {
		return PullRequestRef{}, errors.New("GitHub pull request number does not match the request")
	}
	if err := reference.Validate(); err != nil {
		return PullRequestRef{}, err
	}
	return reference, nil
}

func (client *GitHubClient) FetchArtifact(ctx context.Context, repository string, runID int64, name string) (ArtifactMetadata, error) {
	if !fullNamePattern.MatchString(repository) || runID < 1 || !safeArtifactName(name) {
		return ArtifactMetadata{}, errors.New("artifact lookup is invalid")
	}
	endpoint := client.baseURL + "/repos/" + repository + "/actions/runs/" + strconv.FormatInt(runID, 10) + "/artifacts?per_page=100"
	var response struct {
		Artifacts []struct {
			ID          int64  `json:"id"`
			Name        string `json:"name"`
			SizeInBytes int64  `json:"size_in_bytes"`
			Expired     bool   `json:"expired"`
			Digest      string `json:"digest"`
			WorkflowRun struct {
				ID int64 `json:"id"`
			} `json:"workflow_run"`
		} `json:"artifacts"`
	}
	if err := client.getJSON(ctx, endpoint, &response, 4<<20); err != nil {
		return ArtifactMetadata{}, err
	}
	var found *ArtifactMetadata
	for _, artifact := range response.Artifacts {
		if artifact.Name != name {
			continue
		}
		if artifact.WorkflowRun.ID != 0 && artifact.WorkflowRun.ID != runID {
			return ArtifactMetadata{}, errors.New("artifact belongs to a different workflow run")
		}
		if found != nil {
			return ArtifactMetadata{}, errors.New("workflow run contains duplicate review artifacts")
		}
		found = &ArtifactMetadata{ID: artifact.ID, Name: artifact.Name, Size: artifact.SizeInBytes, Digest: artifact.Digest, Expired: artifact.Expired}
	}
	if found == nil {
		return ArtifactMetadata{}, ErrNotFound
	}
	if found.ID < 1 || found.Size < 1 || found.Size > 150<<20 || found.Expired || !validDigest(found.Digest) {
		return ArtifactMetadata{}, errors.New("review artifact metadata is invalid")
	}
	return *found, nil
}

func ParseWorkflowRunEvent(raw []byte) (WorkflowRunRef, error) {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return WorkflowRunRef{}, errors.New("workflow_run event is missing or too large")
	}
	var event struct {
		Action     string `json:"action"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		WorkflowRun struct {
			ID         int64  `json:"id"`
			RunAttempt int    `json:"run_attempt"`
			Name       string `json:"name"`
			Path       string `json:"path"`
			Event      string `json:"event"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
			HeadSHA    string `json:"head_sha"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
			PullRequests []struct {
				Number int `json:"number"`
			} `json:"pull_requests"`
		} `json:"workflow_run"`
	}
	if err := decodeSingleJSON(raw, &event, false); err != nil {
		return WorkflowRunRef{}, fmt.Errorf("decode workflow_run event: %w", err)
	}
	if event.Action != "completed" || event.WorkflowRun.Status != "completed" || event.WorkflowRun.Conclusion != "success" ||
		event.WorkflowRun.Name != WorkflowName || event.WorkflowRun.Path != WorkflowPath || event.WorkflowRun.Event != "pull_request" {
		return WorkflowRunRef{}, errors.New("workflow_run source identity or completion state is invalid")
	}
	if !fullNamePattern.MatchString(event.Repository.FullName) || event.WorkflowRun.Repository.FullName != event.Repository.FullName ||
		!shaPattern.MatchString(event.WorkflowRun.HeadSHA) || event.WorkflowRun.ID < 1 || event.WorkflowRun.RunAttempt < 1 ||
		len(event.WorkflowRun.PullRequests) != 1 || event.WorkflowRun.PullRequests[0].Number < 1 {
		return WorkflowRunRef{}, errors.New("workflow_run repository, commit, or pull request identity is invalid")
	}
	return WorkflowRunRef{
		Repository: event.Repository.FullName, RunID: event.WorkflowRun.ID, RunAttempt: event.WorkflowRun.RunAttempt,
		SourceRunSHA: event.WorkflowRun.HeadSHA, PullRequest: event.WorkflowRun.PullRequests[0].Number,
	}, nil
}

func (client *GitHubClient) getJSON(ctx context.Context, endpoint string, destination any, limit int64) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "behaviorlock-review-ci")
	response, err := client.client.Do(request)
	if err != nil {
		return fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return fmt.Errorf("GitHub API returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return fmt.Errorf("read GitHub API response: %w", err)
	}
	if int64(len(raw)) > limit {
		return errors.New("GitHub API response exceeded its bound")
	}
	if err := decodeSingleJSON(raw, destination, false); err != nil {
		return fmt.Errorf("decode GitHub API response: %w", err)
	}
	return nil
}

func safeArtifactName(value string) bool {
	if !strings.HasPrefix(value, "behaviorlock-review-") || len(value) > 96 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") && regexpHex(value[7:])
}

func regexpHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return value != ""
}
