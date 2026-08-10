package reviewci

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kiranmagic7/behaviorlock/internal/npm"
)

const (
	ProtocolVersion = "behaviorlock-dependency-review-v1"
	WorkflowName    = "BehaviorLock dependency review capture"
	WorkflowPath    = ".github/workflows/dependency-review-capture.yml"
	CommentMarker   = "<!-- behaviorlock-dependency-review-v1 -->"
	maxManifestSize = 1 << 20
)

var (
	fullNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	shaPattern      = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type PullRequestRef struct {
	Repository     string `json:"repository"`
	Number         int    `json:"number"`
	BaseRepository string `json:"baseRepository"`
	BaseSHA        string `json:"baseSha"`
	HeadRepository string `json:"headRepository"`
	HeadSHA        string `json:"headSha"`
}

type Plan struct {
	ProtocolVersion string `json:"protocolVersion"`
	PullRequestRef
	BaselinePackage  string `json:"baselinePackage,omitempty"`
	CandidatePackage string `json:"candidatePackage,omitempty"`
	DependencyScope  string `json:"dependencyScope,omitempty"`
	Skipped          bool   `json:"skipped"`
	SkipReason       string `json:"skipReason,omitempty"`
}

type pullRequestEvent struct {
	Action     string `json:"action"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	PullRequest struct {
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
	} `json:"pull_request"`
}

func ParsePullRequestEvent(raw []byte) (PullRequestRef, error) {
	if len(raw) == 0 || len(raw) > maxManifestSize {
		return PullRequestRef{}, errors.New("pull request event is missing or too large")
	}
	var event pullRequestEvent
	if err := decodeSingleJSON(raw, &event, false); err != nil {
		return PullRequestRef{}, fmt.Errorf("decode pull request event: %w", err)
	}
	switch event.Action {
	case "opened", "reopened", "synchronize", "ready_for_review":
	default:
		return PullRequestRef{}, fmt.Errorf("unsupported pull request action %q", event.Action)
	}
	reference := PullRequestRef{
		Repository:     event.Repository.FullName,
		Number:         event.PullRequest.Number,
		BaseRepository: event.PullRequest.Base.Repo.FullName,
		BaseSHA:        event.PullRequest.Base.SHA,
		HeadRepository: event.PullRequest.Head.Repo.FullName,
		HeadSHA:        event.PullRequest.Head.SHA,
	}
	if err := reference.Validate(); err != nil {
		return PullRequestRef{}, err
	}
	return reference, nil
}

func (reference PullRequestRef) Validate() error {
	if !fullNamePattern.MatchString(reference.Repository) || reference.Repository != reference.BaseRepository ||
		!fullNamePattern.MatchString(reference.BaseRepository) || !fullNamePattern.MatchString(reference.HeadRepository) {
		return errors.New("pull request repository identity is invalid")
	}
	if reference.Number < 1 || reference.Number > 1_000_000_000 {
		return errors.New("pull request number is invalid")
	}
	if !shaPattern.MatchString(reference.BaseSHA) || !shaPattern.MatchString(reference.HeadSHA) || reference.BaseSHA == reference.HeadSHA {
		return errors.New("pull request commit identity is invalid")
	}
	return nil
}

func BuildPlan(reference PullRequestRef, baselineManifest, candidateManifest []byte) (Plan, error) {
	if err := reference.Validate(); err != nil {
		return Plan{}, err
	}
	plan := Plan{ProtocolVersion: ProtocolVersion, PullRequestRef: reference}
	if len(baselineManifest) == 0 && len(candidateManifest) == 0 {
		plan.Skipped = true
		plan.SkipReason = "no root package.json exists at either revision"
		return plan, nil
	}
	if len(baselineManifest) == 0 || len(candidateManifest) == 0 {
		plan.Skipped = true
		plan.SkipReason = "adding or removing the root package.json is unsupported"
		return plan, nil
	}
	baseline, err := parseManifest(baselineManifest)
	if err != nil {
		return Plan{}, fmt.Errorf("baseline package.json: %w", err)
	}
	candidate, err := parseManifest(candidateManifest)
	if err != nil {
		return Plan{}, fmt.Errorf("candidate package.json: %w", err)
	}
	changes := changedDependencies(baseline, candidate)
	if len(changes) == 0 {
		plan.Skipped = true
		plan.SkipReason = "no root exact-version npm dependency changed"
		return plan, nil
	}
	if len(changes) != 1 {
		return Plan{}, fmt.Errorf("exactly one dependency change is supported, found %d", len(changes))
	}
	change := changes[0]
	if change.Baseline == "" || change.Candidate == "" {
		plan.Skipped = true
		plan.SkipReason = "dependency additions and removals do not have a comparable version pair"
		return plan, nil
	}
	baselineSpec, err := npm.ParseExactSpec(change.Name + "@" + change.Baseline)
	if err != nil {
		return Plan{}, fmt.Errorf("baseline dependency %s is not an exact npm version: %w", change.Name, err)
	}
	candidateSpec, err := npm.ParseExactSpec(change.Name + "@" + change.Candidate)
	if err != nil {
		return Plan{}, fmt.Errorf("candidate dependency %s is not an exact npm version: %w", change.Name, err)
	}
	if baselineSpec.Name != candidateSpec.Name || baselineSpec.Version == candidateSpec.Version {
		return Plan{}, errors.New("dependency version pair is inconsistent")
	}
	plan.BaselinePackage = baselineSpec.String()
	plan.CandidatePackage = candidateSpec.String()
	plan.DependencyScope = change.Scope
	return plan, nil
}

func (plan Plan) Validate() error {
	if plan.ProtocolVersion != ProtocolVersion {
		return errors.New("review plan protocol is invalid")
	}
	if err := plan.PullRequestRef.Validate(); err != nil {
		return err
	}
	if plan.Skipped {
		if plan.BaselinePackage != "" || plan.CandidatePackage != "" || plan.DependencyScope != "" ||
			!safeFixedText(plan.SkipReason, 256) {
			return errors.New("skipped review plan is inconsistent")
		}
		return nil
	}
	baseline, err := npm.ParseExactSpec(plan.BaselinePackage)
	if err != nil {
		return fmt.Errorf("review baseline package: %w", err)
	}
	candidate, err := npm.ParseExactSpec(plan.CandidatePackage)
	if err != nil {
		return fmt.Errorf("review candidate package: %w", err)
	}
	if baseline.Name != candidate.Name || baseline.Version == candidate.Version || !validDependencyScope(plan.DependencyScope) || plan.SkipReason != "" {
		return errors.New("review package pair is inconsistent")
	}
	return nil
}

type manifestDependency struct {
	Version string
	Scope   string
}

type dependencyChange struct {
	Name      string
	Baseline  string
	Candidate string
	Scope     string
}

func parseManifest(raw []byte) (map[string]manifestDependency, error) {
	if len(raw) == 0 || len(raw) > maxManifestSize {
		return nil, errors.New("manifest is missing or exceeds 1 MiB")
	}
	top, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	if packageManagerRaw, ok := top["packageManager"]; ok {
		var packageManager string
		if err := json.Unmarshal(packageManagerRaw, &packageManager); err != nil || packageManager == "" {
			return nil, errors.New("packageManager must be a string")
		}
		if !strings.HasPrefix(packageManager, "npm@") {
			return nil, fmt.Errorf("package manager %q is not supported", packageManager)
		}
	}
	dependencies := make(map[string]manifestDependency)
	for _, scope := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		rawScope, ok := top[scope]
		if !ok {
			continue
		}
		members, err := decodeObject(rawScope)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", scope, err)
		}
		for name, rawVersion := range members {
			var version string
			if err := json.Unmarshal(rawVersion, &version); err != nil || version == "" {
				return nil, fmt.Errorf("%s.%s must be a nonempty string", scope, name)
			}
			if _, exists := dependencies[name]; exists {
				return nil, fmt.Errorf("dependency %s appears in multiple scopes", name)
			}
			dependencies[name] = manifestDependency{Version: version, Scope: scope}
		}
	}
	return dependencies, nil
}

func changedDependencies(baseline, candidate map[string]manifestDependency) []dependencyChange {
	names := make(map[string]struct{}, len(baseline)+len(candidate))
	for name := range baseline {
		names[name] = struct{}{}
	}
	for name := range candidate {
		names[name] = struct{}{}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	changes := make([]dependencyChange, 0, len(ordered))
	for _, name := range ordered {
		left, leftOK := baseline[name]
		right, rightOK := candidate[name]
		if leftOK && rightOK && left.Version == right.Version {
			continue
		}
		scope := right.Scope
		if !rightOK {
			scope = left.Scope
		}
		changes = append(changes, dependencyChange{Name: name, Baseline: left.Version, Candidate: right.Version, Scope: scope})
	}
	return changes
}

func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("decode object: %w", err)
	}
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("expected a JSON object")
	}
	members := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("decode object key: %w", err)
		}
		name, ok := token.(string)
		if !ok || name == "" {
			return nil, errors.New("object key is invalid")
		}
		if _, exists := members[name]; exists {
			return nil, fmt.Errorf("duplicate object key %q", name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("decode object value %q: %w", name, err)
		}
		members[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("close object: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	return members, nil
}

func decodeSingleJSON(raw []byte, destination any, strict bool) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func validDependencyScope(scope string) bool {
	switch scope {
	case "dependencies", "devDependencies", "optionalDependencies", "peerDependencies":
		return true
	default:
		return false
	}
}

func safeFixedText(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func ParseRunID(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 1 {
		return 0, errors.New("workflow run ID is invalid")
	}
	return parsed, nil
}
