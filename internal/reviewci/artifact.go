package reviewci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/kiranmagic7/behaviorlock/internal/compare"
	"github.com/kiranmagic7/behaviorlock/internal/model"
	"github.com/kiranmagic7/behaviorlock/internal/npm"
	"github.com/kiranmagic7/behaviorlock/internal/trace"
)

const (
	planFilename              = "plan.json"
	manifestFilename          = "artifact-manifest.json"
	baselineProfileFilename   = "baseline.profile.json"
	baselineEvidenceFilename  = "baseline.profile.json.evidence.strace"
	candidateProfileFilename  = "candidate.profile.json"
	candidateEvidenceFilename = "candidate.profile.json.evidence.strace"
	diffFilename              = "report.json"
)

type RunIdentity struct {
	Repository   string
	RunID        int64
	RunAttempt   int
	SourceRunSHA string
}

type FileRecord struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
	Purpose string `json:"purpose"`
}

type ReviewResult struct {
	Threshold             string `json:"threshold"`
	ThresholdReached      bool   `json:"thresholdReached"`
	HighestReviewLevel    string `json:"highestReviewLevel"`
	AddedCount            int    `json:"addedCount"`
	Skipped               bool   `json:"skipped"`
	BaselineProfilePath   string `json:"baselineProfilePath,omitempty"`
	BaselineEvidencePath  string `json:"baselineEvidencePath,omitempty"`
	CandidateProfilePath  string `json:"candidateProfilePath,omitempty"`
	CandidateEvidencePath string `json:"candidateEvidencePath,omitempty"`
	DiffPath              string `json:"diffPath,omitempty"`
}

type ArtifactManifest struct {
	ProtocolVersion string       `json:"protocolVersion"`
	WorkflowName    string       `json:"workflowName"`
	WorkflowPath    string       `json:"workflowPath"`
	Repository      string       `json:"repository"`
	RunID           int64        `json:"runId"`
	RunAttempt      int          `json:"runAttempt"`
	SourceRunSHA    string       `json:"sourceRunSha"`
	Plan            Plan         `json:"plan"`
	RunnerImageID   string       `json:"runnerImageId,omitempty"`
	Acquisition     string       `json:"acquisitionPolicy,omitempty"`
	Files           []FileRecord `json:"files"`
	Result          ReviewResult `json:"result"`
}

func ReadPlan(path string) (Plan, error) {
	raw, err := readBoundedRegularFile(path, 1<<20)
	if err != nil {
		return Plan{}, err
	}
	var plan Plan
	if err := decodeSingleJSON(raw, &plan, true); err != nil {
		return Plan{}, fmt.Errorf("decode review plan: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func WritePlan(path string, plan Plan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	return writeJSON(path, plan)
}

func BuildArtifact(directory string, identity RunIdentity, threshold string) (ArtifactManifest, error) {
	if err := validateRunIdentity(identity); err != nil {
		return ArtifactManifest{}, err
	}
	if model.ReviewLevelRank(threshold) == 0 {
		return ArtifactManifest{}, errors.New("review threshold must be low, medium, high, or critical")
	}
	plan, err := ReadPlan(filepath.Join(directory, planFilename))
	if err != nil {
		return ArtifactManifest{}, err
	}
	if plan.Repository != identity.Repository {
		return ArtifactManifest{}, errors.New("workflow repository does not match the review plan")
	}
	manifest := ArtifactManifest{
		ProtocolVersion: ProtocolVersion,
		WorkflowName:    WorkflowName,
		WorkflowPath:    WorkflowPath,
		Repository:      identity.Repository,
		RunID:           identity.RunID,
		RunAttempt:      identity.RunAttempt,
		SourceRunSHA:    identity.SourceRunSHA,
		Plan:            plan,
		Files:           []FileRecord{},
		Result: ReviewResult{
			Threshold: threshold, HighestReviewLevel: "none", Skipped: plan.Skipped,
		},
	}
	paths := []artifactPath{{planFilename, "review-plan", 1 << 20}}
	if !plan.Skipped {
		baseline, candidate, diff, err := validateReviewFiles(directory, plan)
		if err != nil {
			return ArtifactManifest{}, err
		}
		manifest.RunnerImageID = baseline.Capture.RunnerImageID
		manifest.Acquisition = baseline.Capture.Acquisition.PolicyVersion
		manifest.Result.ThresholdReached = model.ReviewLevelRank(diff.Summary.HighestReviewLevel) >= model.ReviewLevelRank(threshold)
		manifest.Result.HighestReviewLevel = diff.Summary.HighestReviewLevel
		manifest.Result.AddedCount = len(diff.Added)
		manifest.Result.BaselineProfilePath = baselineProfileFilename
		manifest.Result.BaselineEvidencePath = baselineEvidenceFilename
		manifest.Result.CandidateProfilePath = candidateProfileFilename
		manifest.Result.CandidateEvidencePath = candidateEvidenceFilename
		manifest.Result.DiffPath = diffFilename
		if baseline.Capture.RunnerImageID != candidate.Capture.RunnerImageID {
			return ArtifactManifest{}, errors.New("baseline and candidate runner image IDs differ")
		}
		paths = append(paths,
			artifactPath{baselineProfileFilename, "baseline-profile", 32 << 20},
			artifactPath{baselineEvidenceFilename, "baseline-evidence", trace.MaxTraceBytes},
			artifactPath{candidateProfileFilename, "candidate-profile", 32 << 20},
			artifactPath{candidateEvidenceFilename, "candidate-evidence", trace.MaxTraceBytes},
			artifactPath{diffFilename, "behavior-diff", 32 << 20},
		)
	}
	manifest.Files, err = hashArtifactFiles(directory, paths)
	if err != nil {
		return ArtifactManifest{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return ArtifactManifest{}, err
	}
	if err := writeJSON(filepath.Join(directory, manifestFilename), manifest); err != nil {
		return ArtifactManifest{}, err
	}
	return manifest, nil
}

func VerifyArtifact(ctx context.Context, directory string, source WorkflowRunRef, client *GitHubClient) (ArtifactManifest, string, error) {
	if client == nil {
		return ArtifactManifest{}, "", errors.New("GitHub client is required")
	}
	raw, err := readBoundedRegularFile(filepath.Join(directory, manifestFilename), 2<<20)
	if err != nil {
		return ArtifactManifest{}, "", err
	}
	var manifest ArtifactManifest
	if err := decodeSingleJSON(raw, &manifest, true); err != nil {
		return ArtifactManifest{}, "", fmt.Errorf("decode artifact manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return ArtifactManifest{}, "", err
	}
	if manifest.Repository != source.Repository || manifest.RunID != source.RunID || manifest.RunAttempt != source.RunAttempt ||
		manifest.SourceRunSHA != source.SourceRunSHA || manifest.Plan.Number != source.PullRequest {
		return ArtifactManifest{}, "", errors.New("artifact source does not match the triggering workflow run")
	}
	artifactName := "behaviorlock-review-" + strconv.FormatInt(source.RunID, 10)
	if _, err := client.FetchArtifact(ctx, source.Repository, source.RunID, artifactName); err != nil {
		return ArtifactManifest{}, "", fmt.Errorf("verify GitHub artifact identity: %w", err)
	}
	reference, err := client.FetchPullRequest(ctx, source.Repository, source.PullRequest)
	if err != nil {
		return ArtifactManifest{}, "", fmt.Errorf("fetch pull request for independent verification: %w", err)
	}
	baselineManifest, err := fetchOptionalManifest(ctx, client, reference.BaseRepository, reference.BaseSHA)
	if err != nil {
		return ArtifactManifest{}, "", err
	}
	candidateManifest, err := fetchOptionalManifest(ctx, client, reference.HeadRepository, reference.HeadSHA)
	if err != nil {
		return ArtifactManifest{}, "", err
	}
	expectedPlan, err := BuildPlan(reference, baselineManifest, candidateManifest)
	if err != nil {
		return ArtifactManifest{}, "", fmt.Errorf("rebuild review plan: %w", err)
	}
	if !reflect.DeepEqual(manifest.Plan, expectedPlan) {
		return ArtifactManifest{}, "", errors.New("artifact review plan does not match current GitHub manifests")
	}
	if err := verifyArtifactDirectory(directory, manifest); err != nil {
		return ArtifactManifest{}, "", err
	}
	if !manifest.Plan.Skipped {
		baseline, _, diff, err := validateReviewFiles(directory, manifest.Plan)
		if err != nil {
			return ArtifactManifest{}, "", err
		}
		expectedReached := model.ReviewLevelRank(diff.Summary.HighestReviewLevel) >= model.ReviewLevelRank(manifest.Result.Threshold)
		if manifest.RunnerImageID != baseline.Capture.RunnerImageID || manifest.Acquisition != baseline.Capture.Acquisition.PolicyVersion ||
			manifest.Result.ThresholdReached != expectedReached || manifest.Result.HighestReviewLevel != diff.Summary.HighestReviewLevel ||
			manifest.Result.AddedCount != len(diff.Added) {
			return ArtifactManifest{}, "", errors.New("artifact result summary does not match the validated profiles")
		}
	}
	comment, err := RenderComment(manifest, directory)
	if err != nil {
		return ArtifactManifest{}, "", err
	}
	return manifest, comment, nil
}

type artifactPath struct {
	Name    string
	Purpose string
	Limit   int64
}

func validateReviewFiles(directory string, plan Plan) (model.Profile, model.Profile, model.Diff, error) {
	baseline, err := readVerifiedProfile(filepath.Join(directory, baselineProfileFilename), filepath.Join(directory, baselineEvidenceFilename))
	if err != nil {
		return model.Profile{}, model.Profile{}, model.Diff{}, fmt.Errorf("baseline profile: %w", err)
	}
	candidate, err := readVerifiedProfile(filepath.Join(directory, candidateProfileFilename), filepath.Join(directory, candidateEvidenceFilename))
	if err != nil {
		return model.Profile{}, model.Profile{}, model.Diff{}, fmt.Errorf("candidate profile: %w", err)
	}
	baselineSpec, _ := npm.ParseExactSpec(plan.BaselinePackage)
	candidateSpec, _ := npm.ParseExactSpec(plan.CandidatePackage)
	if baseline.Subject.Name != baselineSpec.Name || baseline.Subject.Version != baselineSpec.Version ||
		candidate.Subject.Name != candidateSpec.Name || candidate.Subject.Version != candidateSpec.Version {
		return model.Profile{}, model.Profile{}, model.Diff{}, errors.New("profile subjects do not match the review package pair")
	}
	if err := validateCapturePair(baseline, candidate); err != nil {
		return model.Profile{}, model.Profile{}, model.Diff{}, err
	}
	reportRaw, err := readBoundedRegularFile(filepath.Join(directory, diffFilename), 32<<20)
	if err != nil {
		return model.Profile{}, model.Profile{}, model.Diff{}, err
	}
	var report model.Diff
	if err := decodeSingleJSON(reportRaw, &report, true); err != nil {
		return model.Profile{}, model.Profile{}, model.Diff{}, fmt.Errorf("decode behavior diff: %w", err)
	}
	if report.Tool.Version != baseline.Tool.Version || baseline.Tool.Version != candidate.Tool.Version {
		return model.Profile{}, model.Profile{}, model.Diff{}, errors.New("profile and diff tool versions differ")
	}
	expected, err := compare.Profiles(baseline, candidate, report.Tool.Version)
	if err != nil {
		return model.Profile{}, model.Profile{}, model.Diff{}, fmt.Errorf("recompute behavior diff: %w", err)
	}
	// Added and Removed are in-memory rendering counters; the JSON contract
	// derives them from the corresponding arrays and intentionally omits them.
	expected.Summary.Added = report.Summary.Added
	expected.Summary.Removed = report.Summary.Removed
	reportCanonical, reportErr := json.Marshal(report)
	expectedCanonical, expectedErr := json.Marshal(expected)
	if reportErr != nil || expectedErr != nil || !bytes.Equal(reportCanonical, expectedCanonical) {
		return model.Profile{}, model.Profile{}, model.Diff{}, errors.New("behavior diff does not match the validated profiles")
	}
	return baseline, candidate, report, nil
}

func validateCapturePair(baseline, candidate model.Profile) error {
	for label, profile := range map[string]model.Profile{"baseline": baseline, "candidate": candidate} {
		if profile.Capture.Phase != "lifecycle" || profile.Capture.TraceIntegrity != "isolated-root-tracer" ||
			profile.Capture.Acquisition.NetworkMode != "registry-proxy-unix" ||
			profile.Capture.Acquisition.PolicyVersion != "npm-registry-connect-v1" ||
			profile.Capture.Acquisition.AllowedAuthority != "registry.npmjs.org:443" ||
			(profile.Result.Status != "complete" && profile.Result.Status != "command_failed") {
			return fmt.Errorf("%s capture provenance or completion state is invalid", label)
		}
	}
	if baseline.Capture.RunnerImageID != candidate.Capture.RunnerImageID ||
		baseline.Capture.Architecture != candidate.Capture.Architecture || baseline.Capture.NodeVersion != candidate.Capture.NodeVersion ||
		baseline.Capture.NPMVersion != candidate.Capture.NPMVersion || baseline.Capture.StraceVersion != candidate.Capture.StraceVersion ||
		baseline.Capture.SandboxProfile != candidate.Capture.SandboxProfile ||
		baseline.Capture.ObservationPolicy != candidate.Capture.ObservationPolicy ||
		baseline.Capture.Acquisition.ProxyRunnerImageID != candidate.Capture.Acquisition.ProxyRunnerImageID {
		return errors.New("baseline and candidate capture fingerprints differ")
	}
	return nil
}

func readVerifiedProfile(profilePath, evidencePath string) (model.Profile, error) {
	profile, err := model.ReadProfile(profilePath)
	if err != nil {
		return model.Profile{}, err
	}
	evidence, err := readBoundedRegularFile(evidencePath, trace.MaxTraceBytes)
	if err != nil {
		return model.Profile{}, err
	}
	if err := model.VerifyEvidence(profile, evidence); err != nil {
		return model.Profile{}, err
	}
	return profile, nil
}

func hashArtifactFiles(directory string, paths []artifactPath) ([]FileRecord, error) {
	records := make([]FileRecord, 0, len(paths))
	for _, artifact := range paths {
		raw, err := readBoundedRegularFile(filepath.Join(directory, artifact.Name), artifact.Limit)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", artifact.Name, err)
		}
		sum := sha256.Sum256(raw)
		records = append(records, FileRecord{Path: artifact.Name, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Bytes: int64(len(raw)), Purpose: artifact.Purpose})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, nil
}

func verifyArtifactDirectory(directory string, manifest ArtifactManifest) error {
	expected := map[string]FileRecord{manifestFilename: {Path: manifestFilename}}
	for _, record := range manifest.Files {
		expected[record.Path] = record
		raw, err := readBoundedRegularFile(filepath.Join(directory, record.Path), maxFileLimit(record.Purpose))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		if record.Bytes != int64(len(raw)) || record.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
			return fmt.Errorf("artifact file %s digest or size does not match", record.Path)
		}
	}
	return filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact contains an unexpected directory or symlink: %s", entry.Name())
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil || strings.Contains(relative, string(filepath.Separator)) {
			return errors.New("artifact path is not a flat bounded filename")
		}
		if _, ok := expected[relative]; !ok {
			return fmt.Errorf("artifact contains unexpected file %s", relative)
		}
		return nil
	})
}

func validateManifest(manifest ArtifactManifest) error {
	if manifest.ProtocolVersion != ProtocolVersion || manifest.WorkflowName != WorkflowName || manifest.WorkflowPath != WorkflowPath ||
		!fullNamePattern.MatchString(manifest.Repository) || manifest.RunID < 1 || manifest.RunAttempt < 1 ||
		!shaPattern.MatchString(manifest.SourceRunSHA) || manifest.Plan.Repository != manifest.Repository {
		return errors.New("artifact manifest identity is invalid")
	}
	if err := manifest.Plan.Validate(); err != nil {
		return err
	}
	if model.ReviewLevelRank(manifest.Result.Threshold) == 0 || manifest.Result.AddedCount < 0 || manifest.Result.AddedCount > 250_000 {
		return errors.New("artifact result threshold or count is invalid")
	}
	if manifest.Plan.Skipped {
		if !manifest.Result.Skipped || manifest.RunnerImageID != "" || manifest.Acquisition != "" || len(manifest.Files) != 1 ||
			manifest.Result.ThresholdReached || manifest.Result.HighestReviewLevel != "none" || manifest.Result.AddedCount != 0 ||
			manifest.Result.BaselineProfilePath != "" || manifest.Result.BaselineEvidencePath != "" ||
			manifest.Result.CandidateProfilePath != "" || manifest.Result.CandidateEvidencePath != "" || manifest.Result.DiffPath != "" {
			return errors.New("skipped artifact manifest is inconsistent")
		}
	} else if manifest.Result.Skipped || !validDigest(manifest.RunnerImageID) || manifest.Acquisition != "npm-registry-connect-v1" || len(manifest.Files) != 6 ||
		!validHighestReviewLevel(manifest.Result.HighestReviewLevel) ||
		manifest.Result.BaselineProfilePath != baselineProfileFilename || manifest.Result.BaselineEvidencePath != baselineEvidenceFilename ||
		manifest.Result.CandidateProfilePath != candidateProfileFilename || manifest.Result.CandidateEvidencePath != candidateEvidenceFilename ||
		manifest.Result.DiffPath != diffFilename {
		return errors.New("captured artifact manifest is inconsistent")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, record := range manifest.Files {
		if expectedPurpose(record.Path) != record.Purpose || !validDigest(record.SHA256) || record.Bytes < 1 || record.Bytes > maxFileLimit(record.Purpose) {
			return errors.New("artifact file record is invalid")
		}
		if _, exists := seen[record.Path]; exists {
			return errors.New("artifact file record is duplicated")
		}
		seen[record.Path] = struct{}{}
	}
	required := []string{planFilename}
	if !manifest.Plan.Skipped {
		required = append(required, baselineProfileFilename, baselineEvidenceFilename, candidateProfileFilename, candidateEvidenceFilename, diffFilename)
	}
	for _, path := range required {
		if _, exists := seen[path]; !exists {
			return fmt.Errorf("artifact manifest is missing %s", path)
		}
	}
	return nil
}

func validateRunIdentity(identity RunIdentity) error {
	if !fullNamePattern.MatchString(identity.Repository) || identity.RunID < 1 || identity.RunAttempt < 1 || !shaPattern.MatchString(identity.SourceRunSHA) {
		return errors.New("workflow run identity is invalid")
	}
	return nil
}

func fetchOptionalManifest(ctx context.Context, client *GitHubClient, repository, revision string) ([]byte, error) {
	raw, err := client.FetchManifest(ctx, repository, revision)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fetch package.json at %s: %w", revision, err)
	}
	return raw, nil
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a bounded regular file", filepath.Base(path))
	}
	file, err := os.Open(path) // #nosec G304 -- caller-selected artifact directory is the explicit validation boundary.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("file exceeded its read bound")
	}
	return raw, nil
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o600)
}

func expectedPurpose(path string) string {
	switch path {
	case planFilename:
		return "review-plan"
	case baselineProfileFilename:
		return "baseline-profile"
	case baselineEvidenceFilename:
		return "baseline-evidence"
	case candidateProfileFilename:
		return "candidate-profile"
	case candidateEvidenceFilename:
		return "candidate-evidence"
	case diffFilename:
		return "behavior-diff"
	default:
		return ""
	}
}

func validHighestReviewLevel(level string) bool {
	return level == "none" || model.ReviewLevelRank(level) > 0
}

func maxFileLimit(purpose string) int64 {
	switch purpose {
	case "review-plan":
		return 1 << 20
	case "baseline-profile", "candidate-profile", "behavior-diff":
		return 32 << 20
	case "baseline-evidence", "candidate-evidence":
		return trace.MaxTraceBytes
	default:
		return 0
	}
}
