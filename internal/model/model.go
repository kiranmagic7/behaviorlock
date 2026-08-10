package model

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kiranmagic7/behaviorlock/internal/npm"
)

const (
	ProfileSchemaVersion = "2.0.0"
	DiffSchemaVersion    = "2.0.0"
	ProfileKind          = "npm.install.profile"
	DiffKind             = "npm.install.diff"
	maxProfileBehaviors  = 250_000
	maxBehaviorCount     = 250_000
	maxCoverageLimits    = 64
	maxEvidenceRefs      = 8
	maxEvidenceBytes     = 64 << 20
)

const (
	EvidenceMediaType = "application/vnd.behaviorlock.strace"
	EvidenceFormat    = "strace-lines-v1"
	ObservationPolicy = "strace-observation-v2"
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
	RunnerImage       string            `json:"runnerImage,omitempty"`
	RunnerImageID     string            `json:"runnerImageId,omitempty"`
	Architecture      string            `json:"architecture,omitempty"`
	NodeVersion       string            `json:"nodeVersion,omitempty"`
	NPMVersion        string            `json:"npmVersion,omitempty"`
	StraceVersion     string            `json:"straceVersion,omitempty"`
	NetworkMode       string            `json:"networkMode"`
	SandboxProfile    string            `json:"sandboxProfile"`
	TraceIntegrity    string            `json:"traceIntegrity"`
	ObservationPolicy string            `json:"observationPolicy"`
	Attestation       string            `json:"attestation"`
	DurationMillis    int64             `json:"durationMillis,omitempty"`
	Coverage          CaptureCoverage   `json:"coverage"`
	Acquisition       *AcquisitionInfo  `json:"acquisition,omitempty"`
	EvidenceArtifact  *EvidenceArtifact `json:"evidenceArtifact,omitempty"`
	Experimental      bool              `json:"experimental"`
}

type AcquisitionInfo struct {
	NetworkMode        string `json:"networkMode"`
	PolicyVersion      string `json:"policyVersion"`
	AllowedAuthority   string `json:"allowedAuthority"`
	ProxyRunnerImageID string `json:"proxyRunnerImageId"`
}

type EvidenceArtifact struct {
	SHA256    string `json:"sha256"`
	ByteSize  int64  `json:"byteSize"`
	MediaType string `json:"mediaType"`
	Format    string `json:"format"`
	Retention string `json:"retention"`
	Envelope  string `json:"envelope"`
}

type EvidenceRef struct {
	ArtifactSHA256 string `json:"artifactSha256"`
	Line           int    `json:"line"`
	LineSHA256     string `json:"lineSha256"`
}

type Result struct {
	Status    string `json:"status"`
	ExitCode  int    `json:"exitCode"`
	TimedOut  bool   `json:"timedOut"`
	Truncated bool   `json:"truncated"`
	Message   string `json:"message,omitempty"`
}

type Behavior struct {
	Type       string           `json:"type"`
	Operation  string           `json:"operation"`
	Target     string           `json:"target"`
	Arguments  []string         `json:"arguments,omitempty"`
	Outcome    string           `json:"outcome"`
	Errno      string           `json:"errno,omitempty"`
	Sensitive  bool             `json:"sensitive,omitempty"`
	Count      int              `json:"count"`
	ID         string           `json:"id"`
	Evidence   []EvidenceRef    `json:"evidence"`
	Runtime    []RuntimeContext `json:"runtime,omitempty"`
	SourceCall string           `json:"sourceSyscall"`
}

type RuntimeContext struct {
	Process     string `json:"process"`
	Parent      string `json:"parent,omitempty"`
	Descriptor  string `json:"descriptor,omitempty"`
	Attribution string `json:"attribution"`
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
	ReviewLevel string   `json:"reviewLevel"`
	RuleID      string   `json:"ruleId"`
	Reason      string   `json:"reason"`
	Behavior    Behavior `json:"behavior"`
}

type DiffSummary struct {
	Added              int    `json:"-"`
	Removed            int    `json:"-"`
	ReviewRequired     bool   `json:"reviewRequired"`
	HighestReviewLevel string `json:"highestReviewLevel"`
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
			NetworkMode:       "none",
			SandboxProfile:    "behaviorlock-linux-npm-v1",
			TraceIntegrity:    "isolated-root-tracer",
			ObservationPolicy: ObservationPolicy,
			Attestation:       "none",
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
		behavior.Evidence = normalizeEvidenceRefs(behavior.Evidence)
		behavior.Runtime = normalizeRuntimeContexts(behavior.Runtime)
		key := BehaviorKey(behavior)
		if existing, ok := counts[key]; ok {
			existing.Count += max(behavior.Count, 1)
			existing.Evidence = normalizeEvidenceRefs(append(existing.Evidence, behavior.Evidence...))
			existing.Runtime = normalizeRuntimeContexts(append(existing.Runtime, behavior.Runtime...))
			counts[key] = existing
			continue
		}
		behavior.Count = max(behavior.Count, 1)
		counts[key] = behavior
	}
	p.Behaviors = p.Behaviors[:0]
	for _, behavior := range counts {
		behavior.ID = StableBehaviorID(behavior)
		p.Behaviors = append(p.Behaviors, behavior)
	}
	sort.Slice(p.Behaviors, func(i, j int) bool {
		return BehaviorKey(p.Behaviors[i]) < BehaviorKey(p.Behaviors[j])
	})
	sort.Strings(p.Capture.Coverage.Lifecycle)
	sort.Strings(p.Capture.Coverage.Limitations)
}

func StableBehaviorID(behavior Behavior) string {
	sum := sha256.Sum256([]byte(BehaviorKey(behavior)))
	return "event:sha256:" + hex.EncodeToString(sum[:])
}

func NewEvidenceRef(line int, rawLine []byte) EvidenceRef {
	rawLine = bytes.TrimSuffix(rawLine, []byte("\n"))
	sum := sha256.Sum256(rawLine)
	return EvidenceRef{Line: line, LineSHA256: "sha256:" + hex.EncodeToString(sum[:])}
}

func AttachEvidence(profile *Profile, raw []byte, retention, envelope string) {
	artifact := NewEvidenceArtifact(raw, retention, envelope)
	profile.Capture.EvidenceArtifact = &artifact
	for index := range profile.Behaviors {
		for refIndex := range profile.Behaviors[index].Evidence {
			profile.Behaviors[index].Evidence[refIndex].ArtifactSHA256 = artifact.SHA256
		}
	}
}

func NewEvidenceArtifact(raw []byte, retention, envelope string) EvidenceArtifact {
	sum := sha256.Sum256(raw)
	return EvidenceArtifact{
		SHA256:    "sha256:" + hex.EncodeToString(sum[:]),
		ByteSize:  int64(len(raw)),
		MediaType: EvidenceMediaType,
		Format:    EvidenceFormat,
		Retention: retention,
		Envelope:  envelope,
	}
}

func normalizeEvidenceRefs(refs []EvidenceRef) []EvidenceRef {
	unique := make(map[string]EvidenceRef, len(refs))
	for _, ref := range refs {
		key := fmt.Sprintf("%s\x1e%d\x1e%s", ref.ArtifactSHA256, ref.Line, ref.LineSHA256)
		unique[key] = ref
	}
	refs = make([]EvidenceRef, 0, len(unique))
	for _, ref := range unique {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].ArtifactSHA256 != refs[j].ArtifactSHA256 {
			return refs[i].ArtifactSHA256 < refs[j].ArtifactSHA256
		}
		if refs[i].Line != refs[j].Line {
			return refs[i].Line < refs[j].Line
		}
		return refs[i].LineSHA256 < refs[j].LineSHA256
	})
	if len(refs) > maxEvidenceRefs {
		refs = refs[:maxEvidenceRefs]
	}
	return refs
}

func normalizeRuntimeContexts(contexts []RuntimeContext) []RuntimeContext {
	unique := make(map[string]RuntimeContext, len(contexts))
	for _, context := range contexts {
		key := strings.Join([]string{context.Process, context.Parent, context.Descriptor, context.Attribution}, "\x1e")
		unique[key] = context
	}
	contexts = make([]RuntimeContext, 0, len(unique))
	for _, context := range unique {
		contexts = append(contexts, context)
	}
	sort.Slice(contexts, func(i, j int) bool {
		left := strings.Join([]string{contexts[i].Process, contexts[i].Parent, contexts[i].Descriptor, contexts[i].Attribution}, "\x1e")
		right := strings.Join([]string{contexts[j].Process, contexts[j].Parent, contexts[j].Descriptor, contexts[j].Attribution}, "\x1e")
		return left < right
	})
	if len(contexts) > maxEvidenceRefs {
		contexts = contexts[:maxEvidenceRefs]
	}
	return contexts
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
	canonical.Capture.EvidenceArtifact = nil
	for index := range canonical.Behaviors {
		canonical.Behaviors[index].Count = 1
		canonical.Behaviors[index].Evidence = nil
		canonical.Behaviors[index].Runtime = nil
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
	if p.Tool.Name != "behaviorlock" || p.Tool.Version == "" || !safeField(p.Tool.Version, 128) {
		return errors.New("profile tool identity is invalid")
	}
	if p.Subject.Ecosystem != "npm" {
		return errors.New("profile subject ecosystem must be npm")
	}
	spec, err := npm.ParseExactSpec(p.Subject.Name + "@" + p.Subject.Version)
	if err != nil || p.Subject.PURL != spec.PURL() {
		return errors.New("profile subject name, version, and purl are inconsistent")
	}
	if p.Subject.RegistryIntegrity != "" && !ValidRegistryIntegrity(p.Subject.RegistryIntegrity) {
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
	if p.Capture.ObservationPolicy != ObservationPolicy {
		return errors.New("unsupported observation policy")
	}
	if !safeField(p.Capture.RunnerImage, 256) || !safeField(p.Capture.RunnerImageID, 256) ||
		!safeField(p.Capture.Architecture, 64) || !safeField(p.Capture.NodeVersion, 64) ||
		!safeField(p.Capture.NPMVersion, 64) || !safeField(p.Capture.StraceVersion, 64) ||
		!safeField(p.Capture.SandboxProfile, 128) {
		return errors.New("capture metadata contains unsafe text")
	}
	if err := validateCoverage(p.Capture.Coverage); err != nil {
		return err
	}
	if p.Capture.EvidenceArtifact != nil {
		if err := validateEvidenceArtifact(*p.Capture.EvidenceArtifact); err != nil {
			return err
		}
	}
	if p.Capture.Acquisition != nil {
		if err := validateAcquisition(*p.Capture.Acquisition); err != nil {
			return err
		}
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
			if !validDigest(p.Capture.RunnerImageID) {
				return errors.New("captured profile runner image id is invalid")
			}
			if p.Subject.RegistryIntegrity == "" || p.Subject.DependencyLockSHA256 == "" {
				return errors.New("captured profile is missing acquisition provenance")
			}
			if p.Capture.Acquisition == nil || p.Capture.Acquisition.NetworkMode != "registry-proxy-unix" ||
				p.Capture.Acquisition.PolicyVersion != "npm-registry-connect-v1" ||
				p.Capture.Acquisition.AllowedAuthority != "registry.npmjs.org:443" ||
				p.Capture.Acquisition.ProxyRunnerImageID != p.Capture.RunnerImageID {
				return errors.New("captured profile is missing the acquisition egress fingerprint")
			}
			if p.Capture.EvidenceArtifact == nil || p.Capture.EvidenceArtifact.Retention != "retained" || p.Capture.EvidenceArtifact.Envelope != "behaviorlock-trace-v1-payload" {
				return errors.New("captured profile is missing retained raw evidence metadata")
			}
		}
		if p.Capture.Coverage.Scope != "registry-install-lifecycle" || p.Capture.Coverage.Completeness != "partial" || !sameStrings(p.Capture.Coverage.Lifecycle, []string{"install", "postinstall", "preinstall"}) {
			return errors.New("captured profile coverage is inconsistent")
		}
	case "external-unverified":
		if p.Capture.NetworkMode != "unknown" || p.Capture.SandboxProfile != "external-unverified" || p.Capture.Coverage.Scope != "external-strace" || p.Capture.Coverage.Completeness != "unverified" || len(p.Capture.Coverage.Lifecycle) != 0 {
			return errors.New("external profile must not attest sandbox conditions")
		}
		if (p.Result.Status == "complete" || p.Result.Status == "command_failed") && (p.Capture.EvidenceArtifact == nil || p.Capture.EvidenceArtifact.Retention != "external-unverified" || p.Capture.EvidenceArtifact.Envelope != "external-strace") {
			return errors.New("external profile is missing retained unverified evidence metadata")
		}
		if p.Capture.Acquisition != nil {
			return errors.New("external profile must not claim trusted acquisition controls")
		}
	default:
		return fmt.Errorf("unsupported trace integrity %q", p.Capture.TraceIntegrity)
	}
	if (p.Result.Status == "complete" || p.Result.Status == "command_failed") && len(p.Behaviors) == 0 {
		return errors.New("completed profile contains no recognized behavior")
	}
	if len(p.Behaviors) > maxProfileBehaviors {
		return fmt.Errorf("profile exceeds %d behaviors", maxProfileBehaviors)
	}
	for index, behavior := range p.Behaviors {
		if err := validateBehavior(behavior, p.Capture.EvidenceArtifact); err != nil {
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
	var header struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return Profile{}, fmt.Errorf("decode profile header: %w", err)
	}
	if header.SchemaVersion != ProfileSchemaVersion {
		return Profile{}, fmt.Errorf("profile schema %q is not comparable with current schema %s; regenerate the profile", header.SchemaVersion, ProfileSchemaVersion)
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
	if err := ValidateProfile(profile); err != nil {
		return Profile{}, fmt.Errorf("normalized profile: %w", err)
	}
	return profile, nil
}

func validateBehavior(behavior Behavior, artifact *EvidenceArtifact) error {
	allowedTypes := map[string]bool{
		"filesystem.read": true, "filesystem.write": true, "filesystem.create": true,
		"filesystem.delete": true, "filesystem.rename": true, "filesystem.permission": true,
		"filesystem.truncate": true, "filesystem.descriptor_write": true, "filesystem.enumerate": true,
		"process.exec": true, "process.create": true, "process.memfd": true, "process.fileless_exec": true, "process.ptrace": true,
		"network.connect": true, "network.socket": true, "network.send": true, "network.dns": true,
		"network.bind": true, "network.listen": true, "network.accept": true,
		"environment.timing": true,
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
	if len(behavior.Arguments) > 32 || behavior.Count < 1 || behavior.Count > maxBehaviorCount {
		return errors.New("argument or count limit is invalid")
	}
	switch behavior.Outcome {
	case "success", "blocked", "failed", "unknown":
	default:
		return errors.New("outcome is invalid")
	}
	if behavior.ID != StableBehaviorID(behavior) {
		return errors.New("stable behavior identifier is invalid")
	}
	if len(behavior.Evidence) == 0 || len(behavior.Evidence) > maxEvidenceRefs {
		return errors.New("evidence reference count is invalid")
	}
	for _, ref := range behavior.Evidence {
		if artifact == nil || ref.ArtifactSHA256 != artifact.SHA256 || !validDigest(ref.ArtifactSHA256) ||
			ref.Line < 1 || !validDigest(ref.LineSHA256) {
			return errors.New("evidence reference is invalid")
		}
	}
	if len(behavior.Runtime) > maxEvidenceRefs {
		return errors.New("runtime attribution count is invalid")
	}
	for _, context := range behavior.Runtime {
		if !validRuntimeProcess(context.Process) || (context.Parent != "" && !validRuntimeProcess(context.Parent)) ||
			(context.Descriptor != "" && !validRuntimeDescriptor(context.Descriptor)) {
			return errors.New("runtime attribution identifier is invalid")
		}
		switch context.Attribution {
		case "direct", "descriptor", "unknown":
		default:
			return errors.New("runtime attribution mode is invalid")
		}
	}
	return nil
}

func validRuntimeProcess(value string) bool {
	if value == "root" {
		return true
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	return err == nil && parsed > 0
}

func validRuntimeDescriptor(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 31)
	return err == nil && parsed <= 1_000_000
}

func validateEvidenceArtifact(artifact EvidenceArtifact) error {
	if !validDigest(artifact.SHA256) || artifact.ByteSize < 1 || artifact.ByteSize > maxEvidenceBytes ||
		artifact.MediaType != EvidenceMediaType || artifact.Format != EvidenceFormat {
		return errors.New("raw evidence artifact metadata is invalid")
	}
	switch artifact.Retention {
	case "retained", "external-unverified":
	default:
		return errors.New("raw evidence retention is invalid")
	}
	switch artifact.Envelope {
	case "behaviorlock-trace-v1-payload", "external-strace":
	default:
		return errors.New("raw evidence envelope is invalid")
	}
	return nil
}

func validateAcquisition(acquisition AcquisitionInfo) error {
	if acquisition.NetworkMode != "registry-proxy-unix" || acquisition.PolicyVersion != "npm-registry-connect-v1" ||
		acquisition.AllowedAuthority != "registry.npmjs.org:443" || !validDigest(acquisition.ProxyRunnerImageID) {
		return errors.New("acquisition egress fingerprint is invalid")
	}
	return nil
}

func VerifyEvidence(profile Profile, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxEvidenceBytes {
		return fmt.Errorf("raw evidence must contain 1 through %d bytes", maxEvidenceBytes)
	}
	if profile.Capture.EvidenceArtifact == nil {
		return errors.New("profile does not declare a raw evidence artifact")
	}
	artifact := NewEvidenceArtifact(raw, profile.Capture.EvidenceArtifact.Retention, profile.Capture.EvidenceArtifact.Envelope)
	if artifact.SHA256 != profile.Capture.EvidenceArtifact.SHA256 || artifact.ByteSize != profile.Capture.EvidenceArtifact.ByteSize ||
		artifact.MediaType != profile.Capture.EvidenceArtifact.MediaType || artifact.Format != profile.Capture.EvidenceArtifact.Format {
		return errors.New("raw evidence artifact digest or metadata does not match the profile")
	}
	lines := bytes.Split(raw, []byte("\n"))
	for behaviorIndex, behavior := range profile.Behaviors {
		for refIndex, ref := range behavior.Evidence {
			if ref.Line > len(lines) || ref.ArtifactSHA256 != artifact.SHA256 {
				return fmt.Errorf("behavior %d evidence reference %d is outside the artifact", behaviorIndex, refIndex)
			}
			sum := sha256.Sum256(lines[ref.Line-1])
			if "sha256:"+hex.EncodeToString(sum[:]) != ref.LineSHA256 {
				return fmt.Errorf("behavior %d evidence reference %d line digest does not match", behaviorIndex, refIndex)
			}
		}
	}
	return nil
}

func validateCoverage(coverage CaptureCoverage) error {
	if !safeField(coverage.Scope, 64) || !safeField(coverage.Completeness, 64) ||
		len(coverage.Lifecycle) > 3 || len(coverage.Limitations) > maxCoverageLimits {
		return errors.New("profile capture coverage exceeds its limits")
	}
	for _, lifecycle := range coverage.Lifecycle {
		switch lifecycle {
		case "preinstall", "install", "postinstall":
		default:
			return errors.New("profile capture lifecycle is invalid")
		}
	}
	for _, limitation := range coverage.Limitations {
		if limitation == "" || !safeField(limitation, 1024) {
			return errors.New("profile capture limitation is unsafe")
		}
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

func ValidRegistryIntegrity(value string) bool {
	const prefix = "sha512-"
	if !strings.HasPrefix(value, prefix) || len(value) > 256 || !safeField(value, 256) {
		return false
	}
	digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(digest) == sha512.Size
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
	var encoded bytes.Buffer
	if err := EncodeJSON(&encoded, value); err != nil {
		return err
	}
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(encoded.Bytes())
		return err
	}
	return atomicWrite(path, encoded.Bytes())
}

func EncodeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func WriteEvidence(path string, raw []byte) error {
	if path == "" || path == "-" {
		return errors.New("raw evidence output must be a file path")
	}
	if len(raw) == 0 || len(raw) > maxEvidenceBytes {
		return fmt.Errorf("raw evidence must contain 1 through %d bytes", maxEvidenceBytes)
	}
	return atomicWrite(path, raw)
}

func atomicWrite(path string, content []byte) (err error) {
	directory := filepath.Dir(path)
	base := filepath.Base(path)
	// #nosec G304 -- creating a temporary file beside a caller-selected output is the explicit local CLI contract.
	temporary, err := os.CreateTemp(directory, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if temporaryPath != "" {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	temporaryPath = ""
	return nil
}

func ReviewLevelRank(value string) int {
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
