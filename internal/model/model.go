package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/kiranmagic7/behaviorlock/internal/npm"
)

const (
	ProfileSchemaVersion = "1.0.0"
	DiffSchemaVersion    = "1.0.0"
	ProfileKind          = "npm.install.profile"
	DiffKind             = "npm.install.diff"
)

type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Subject struct {
	Ecosystem            string `json:"ecosystem"`
	Name                 string `json:"name"`
	Version              string `json:"version"`
	PURL                 string `json:"purl"`
	RegistryIntegrity    string `json:"registryIntegrity,omitempty"`
	TarballSHA256        string `json:"tarballSha256,omitempty"`
	DependencyLockSHA256 string `json:"dependencyLockSha256,omitempty"`
}

type CaptureCoverage struct {
	Scope        string   `json:"scope"`
	Lifecycle    []string `json:"lifecycle"`
	Completeness string   `json:"completeness"`
	Limitations  []string `json:"limitations"`
}

type CaptureInfo struct {
	RunnerImage    string          `json:"runnerImage,omitempty"`
	RunnerImageID  string          `json:"runnerImageId,omitempty"`
	Architecture   string          `json:"architecture,omitempty"`
	NodeVersion    string          `json:"nodeVersion,omitempty"`
	NPMVersion     string          `json:"npmVersion,omitempty"`
	StraceVersion  string          `json:"straceVersion,omitempty"`
	NetworkMode    string          `json:"networkMode"`
	SandboxProfile string          `json:"sandboxProfile"`
	RawTraceSHA256 string          `json:"rawTraceSha256"`
	TraceIntegrity string          `json:"traceIntegrity"`
	Attestation    string          `json:"attestation"`
	DurationMillis int64           `json:"durationMillis,omitempty"`
	Coverage       CaptureCoverage `json:"coverage"`
	Experimental   bool            `json:"experimental"`
}

type Result struct {
	Status    string `json:"status"`
	ExitCode  int    `json:"exitCode"`
	TimedOut  bool   `json:"timedOut"`
	Truncated bool   `json:"truncated"`
	Message   string `json:"message,omitempty"`
}

type Behavior struct {
	Type       string   `json:"type"`
	Operation  string   `json:"operation"`
	Target     string   `json:"target"`
	Arguments  []string `json:"arguments,omitempty"`
	Outcome    string   `json:"outcome"`
	Errno      string   `json:"errno,omitempty"`
	Sensitive  bool     `json:"sensitive,omitempty"`
	Count      int      `json:"count"`
	Evidence   string   `json:"evidence"`
	SourceCall string   `json:"sourceSyscall"`
}

type Profile struct {
	SchemaVersion string      `json:"schemaVersion"`
	Kind          string      `json:"kind"`
	Tool          ToolInfo    `json:"tool"`
	Subject       Subject     `json:"subject"`
	Capture       CaptureInfo `json:"capture"`
	Result        Result      `json:"result"`
	Behaviors     []Behavior  `json:"behaviors"`
}

type Change struct {
	Risk     string   `json:"risk"`
	RuleID   string   `json:"ruleId"`
	Reason   string   `json:"reason"`
	Behavior Behavior `json:"behavior"`
}

type DiffSummary struct {
	Added       int    `json:"-"`
	Removed     int    `json:"-"`
	HighestRisk string `json:"highestRisk"`
	Verdict     string `json:"verdict"`
}

type Diff struct {
	SchemaVersion   string      `json:"schemaVersion"`
	Kind            string      `json:"kind"`
	Tool            ToolInfo    `json:"tool"`
	Baseline        Subject     `json:"baseline"`
	Candidate       Subject     `json:"candidate"`
	BaselineDigest  string      `json:"baselineDigest"`
	CandidateDigest string      `json:"candidateDigest"`
	Added           []Change    `json:"added"`
	Removed         []Behavior  `json:"removed"`
	Summary         DiffSummary `json:"summary"`
	Limitations     []string    `json:"limitations"`
}

func NewProfile(subject Subject, toolVersion string) Profile {
	return Profile{
		SchemaVersion: ProfileSchemaVersion,
		Kind:          ProfileKind,
		Tool:          ToolInfo{Name: "behaviorlock", Version: toolVersion},
		Subject:       subject,
		Capture: CaptureInfo{
			NetworkMode:    "none",
			SandboxProfile: "behaviorlock-linux-npm-v1",
			TraceIntegrity: "isolated-root-tracer",
			Attestation:    "none",
			Coverage: CaptureCoverage{
				Scope:        "registry-install-lifecycle",
				Lifecycle:    []string{"preinstall", "install", "postinstall"},
				Completeness: "partial",
				Limitations: []string{
					"Only behavior exercised by npm rebuild is observed.",
					"strace changes timing and can be detected by package code.",
					"Environment variable reads are not observable through strace.",
				},
			},
			Experimental: true,
		},
		Result:    Result{Status: "trace_incomplete", ExitCode: 2},
		Behaviors: []Behavior{},
	}
}

func (p *Profile) Normalize() {
	counts := make(map[string]Behavior, len(p.Behaviors))
	for _, behavior := range p.Behaviors {
		behavior.Arguments = append([]string(nil), behavior.Arguments...)
		key := BehaviorKey(behavior)
		if existing, ok := counts[key]; ok {
			existing.Count += max(behavior.Count, 1)
			counts[key] = existing
			continue
		}
		behavior.Count = max(behavior.Count, 1)
		counts[key] = behavior
	}
	p.Behaviors = p.Behaviors[:0]
	for _, behavior := range counts {
		behavior.Evidence = StableEvidence(behavior)
		p.Behaviors = append(p.Behaviors, behavior)
	}
	sort.Slice(p.Behaviors, func(i, j int) bool {
		return BehaviorKey(p.Behaviors[i]) < BehaviorKey(p.Behaviors[j])
	})
	sort.Strings(p.Capture.Coverage.Lifecycle)
	sort.Strings(p.Capture.Coverage.Limitations)
}

func StableEvidence(behavior Behavior) string {
	sum := sha256.Sum256([]byte(BehaviorKey(behavior)))
	return "event:sha256:" + hex.EncodeToString(sum[:])
}

func BehaviorKey(b Behavior) string {
	return strings.Join([]string{
		b.Type,
		b.Operation,
		b.Target,
		strings.Join(b.Arguments, "\x1f"),
		b.Outcome,
		b.Errno,
		fmt.Sprintf("%t", b.Sensitive),
		b.SourceCall,
	}, "\x1e")
}

func (p Profile) StableDigest() (string, error) {
	p.Behaviors = append([]Behavior(nil), p.Behaviors...)
	p.Capture.Coverage.Lifecycle = append([]string(nil), p.Capture.Coverage.Lifecycle...)
	p.Capture.Coverage.Limitations = append([]string(nil), p.Capture.Coverage.Limitations...)
	p.Normalize()
	canonical := struct {
		SchemaVersion string      `json:"schemaVersion"`
		Kind          string      `json:"kind"`
		Tool          ToolInfo    `json:"tool"`
		Subject       Subject     `json:"subject"`
		Capture       CaptureInfo `json:"capture"`
		Result        Result      `json:"result"`
		Behaviors     []Behavior  `json:"behaviors"`
	}{p.SchemaVersion, p.Kind, p.Tool, p.Subject, p.Capture, p.Result, p.Behaviors}
	canonical.Behaviors = append([]Behavior(nil), canonical.Behaviors...)
	canonical.Capture.DurationMillis = 0
	canonical.Capture.RawTraceSHA256 = ""
	for index := range canonical.Behaviors {
		canonical.Behaviors[index].Count = 1
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateProfile(p Profile) error {
	if p.SchemaVersion != ProfileSchemaVersion {
		return fmt.Errorf("unsupported profile schema version %q", p.SchemaVersion)
	}
	if p.Kind != ProfileKind {
		return fmt.Errorf("unsupported profile kind %q", p.Kind)
	}
	if p.Tool.Name != "behaviorlock" || !safeField(p.Tool.Version, 128) {
		return errors.New("profile tool identity is invalid")
	}
	if p.Subject.Ecosystem != "npm" {
		return errors.New("profile subject ecosystem must be npm")
	}
	spec, err := npm.ParseExactSpec(p.Subject.Name + "@" + p.Subject.Version)
	if err != nil || p.Subject.PURL != spec.PURL() {
		return errors.New("profile subject name, version, and purl are inconsistent")
	}
	if p.Subject.RegistryIntegrity != "" && !strings.HasPrefix(p.Subject.RegistryIntegrity, "sha512-") {
		return errors.New("profile registry integrity is invalid")
	}
	if p.Subject.TarballSHA256 != "" && !validDigest(p.Subject.TarballSHA256) {
		return errors.New("profile tarball digest is invalid")
	}
	if p.Subject.DependencyLockSHA256 != "" && !validDigest(p.Subject.DependencyLockSHA256) {
		return errors.New("profile dependency lock digest is invalid")
	}
	switch p.Result.Status {
	case "complete", "command_failed", "timed_out", "trace_incomplete", "resource_exhausted":
	default:
		return fmt.Errorf("unsupported result status %q", p.Result.Status)
	}
	if p.Result.Status == "complete" && (p.Result.TimedOut || p.Result.Truncated) {
		return errors.New("a timed out or truncated trace cannot be complete")
	}
	if p.Result.Status == "timed_out" && !p.Result.TimedOut {
		return errors.New("a timed_out result must set timedOut")
	}
	if !safeField(p.Result.Message, 4096) {
		return errors.New("profile result message contains unsafe text")
	}
	if p.Result.ExitCode < 0 || p.Result.ExitCode > 255 {
		return errors.New("profile exit code is outside 0 through 255")
	}
	if !p.Capture.Experimental {
		return errors.New("profile must preserve the experimental capture marker")
	}
	if p.Capture.Attestation != "none" {
		return errors.New("unsupported profile attestation")
	}
	switch p.Capture.TraceIntegrity {
	case "isolated-root-tracer":
		if p.Capture.NetworkMode != "none" || p.Capture.SandboxProfile != "behaviorlock-linux-npm-v1" {
			return errors.New("captured profile has inconsistent sandbox evidence")
		}
		if p.Result.Status == "complete" || p.Result.Status == "command_failed" {
			for name, value := range map[string]string{
				"runner image":    p.Capture.RunnerImage,
				"runner image id": p.Capture.RunnerImageID,
				"architecture":    p.Capture.Architecture,
				"node version":    p.Capture.NodeVersion,
				"npm version":     p.Capture.NPMVersion,
				"strace version":  p.Capture.StraceVersion,
			} {
				if !safeField(value, 256) || value == "" {
					return fmt.Errorf("captured profile %s is missing or unsafe", name)
				}
			}
			if p.Subject.RegistryIntegrity == "" || p.Subject.DependencyLockSHA256 == "" {
				return errors.New("captured profile is missing acquisition provenance")
			}
		}
		if p.Capture.Coverage.Scope != "registry-install-lifecycle" || !sameStrings(p.Capture.Coverage.Lifecycle, []string{"install", "postinstall", "preinstall"}) {
			return errors.New("captured profile coverage is inconsistent")
		}
	case "external-unverified":
		if p.Capture.NetworkMode != "unknown" || p.Capture.SandboxProfile != "external-unverified" || p.Capture.Coverage.Scope != "external-strace" {
			return errors.New("external profile must not attest sandbox conditions")
		}
	default:
		return fmt.Errorf("unsupported trace integrity %q", p.Capture.TraceIntegrity)
	}
	if (p.Result.Status == "complete" || p.Result.Status == "command_failed") && !validDigest(p.Capture.RawTraceSHA256) {
		return errors.New("completed profile is missing a valid raw trace digest")
	}
	if (p.Result.Status == "complete" || p.Result.Status == "command_failed") && len(p.Behaviors) == 0 {
		return errors.New("completed profile contains no recognized behavior")
	}
	for index, behavior := range p.Behaviors {
		if err := validateBehavior(behavior); err != nil {
			return fmt.Errorf("behavior %d: %w", index, err)
		}
	}
	return nil
}

func ReadProfile(path string) (Profile, error) {
	// #nosec G304 -- reading a caller-selected profile path is the explicit local CLI contract.
	file, err := os.Open(path)
	if err != nil {
		return Profile{}, err
	}
	defer file.Close()
	const maxProfileBytes = 32 << 20
	raw, err := io.ReadAll(io.LimitReader(file, maxProfileBytes+1))
	if err != nil {
		return Profile{}, fmt.Errorf("read profile: %w", err)
	}
	if len(raw) > maxProfileBytes {
		return Profile{}, fmt.Errorf("profile exceeds %d bytes", maxProfileBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var profile Profile
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("decode profile: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Profile{}, errors.New("decode profile: trailing JSON value")
		}
		return Profile{}, fmt.Errorf("decode profile trailing data: %w", err)
	}
	if err := ValidateProfile(profile); err != nil {
		return Profile{}, err
	}
	profile.Normalize()
	return profile, nil
}

func validateBehavior(behavior Behavior) error {
	allowedTypes := map[string]bool{
		"filesystem.read": true, "filesystem.write": true, "filesystem.create": true,
		"filesystem.delete": true, "filesystem.rename": true, "filesystem.permission": true,
		"process.exec": true, "network.connect": true,
	}
	if !allowedTypes[behavior.Type] || !safeField(behavior.Operation, 64) || behavior.Operation == "" {
		return errors.New("type or operation is invalid")
	}
	if !safeField(behavior.Target, 4099) || !safeField(behavior.Errno, 128) || !safeField(behavior.SourceCall, 64) || behavior.SourceCall == "" {
		return errors.New("target, errno, or source syscall is unsafe")
	}
	for _, argument := range behavior.Arguments {
		if !safeField(argument, 4099) {
			return errors.New("argument is unsafe")
		}
	}
	if len(behavior.Arguments) > 32 || behavior.Count < 1 {
		return errors.New("argument or count limit is invalid")
	}
	switch behavior.Outcome {
	case "success", "blocked", "failed", "unknown":
	default:
		return errors.New("outcome is invalid")
	}
	if len(behavior.Evidence) != len("event:sha256:")+64 || !strings.HasPrefix(behavior.Evidence, "event:sha256:") {
		return errors.New("stable evidence identifier is invalid")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(behavior.Evidence, "event:sha256:")); err != nil {
		return errors.New("stable evidence identifier is invalid")
	}
	return nil
}

func safeField(value string, limit int) bool {
	if !utf8.ValidString(value) || len(value) > limit {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func WriteJSON(path string, value any) error {
	var writer io.Writer = os.Stdout
	var file *os.File
	if path != "" && path != "-" {
		var err error
		// #nosec G304 -- writing a caller-selected output path with mode 0600 is the explicit local CLI contract.
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		writer = file
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func SeverityRank(value string) int {
	switch value {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
