package benchmark

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kiranmagic7/behaviorlock/internal/compare"
	"github.com/kiranmagic7/behaviorlock/internal/model"
	"github.com/kiranmagic7/behaviorlock/internal/npm"
	"github.com/kiranmagic7/behaviorlock/internal/trace"
)

const (
	maxManifestBytes = 1 << 20
	toolVersion      = "benchmark-corpus-v1"
)

var idPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type Manifest struct {
	SchemaVersion               int          `json:"schemaVersion"`
	CorpusPolicy                CorpusPolicy `json:"corpusPolicy"`
	Cases                       []Case       `json:"cases"`
	ProjectedHistoricalCoverage []Projection `json:"projectedHistoricalCoverage"`
}

type CorpusPolicy struct {
	SampleClass       string   `json:"sampleClass"`
	NetworkPolicy     string   `json:"networkPolicy"`
	ProhibitedContent []string `json:"prohibitedContent"`
}

type Case struct {
	ID                   string      `json:"id"`
	Title                string      `json:"title"`
	ObservedPhase        string      `json:"observedPhase"`
	ReconstructionStatus string      `json:"reconstructionStatus"`
	Baseline             Fixture     `json:"baseline"`
	Candidate            Fixture     `json:"candidate"`
	Citations            []Citation  `json:"citations"`
	Expected             Expectation `json:"expected"`
	UnsupportedSignals   []string    `json:"unsupportedSignals"`
}

type Fixture struct {
	Package string `json:"package"`
	Trace   string `json:"trace"`
}

type Citation struct {
	Title        string `json:"title"`
	URL          string `json:"url"`
	Relationship string `json:"relationship"`
}

type Expectation struct {
	AddedBehaviorTypes []string `json:"addedBehaviorTypes"`
	RuleIDs            []string `json:"ruleIds"`
	HighestReviewLevel string   `json:"highestReviewLevel"`
}

type Projection struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Status      string     `json:"status"`
	FixtureIDs  []string   `json:"fixtureIds"`
	Citations   []Citation `json:"citations"`
	Limitations []string   `json:"limitations"`
}

type Report struct {
	SchemaVersion               int            `json:"schemaVersion"`
	Kind                        string         `json:"kind"`
	ManifestSHA256              string         `json:"manifestSha256"`
	CorpusPolicy                CorpusPolicy   `json:"corpusPolicy"`
	Observed                    ObservedReport `json:"observed"`
	ProjectedHistoricalCoverage []Projection   `json:"projectedHistoricalCoverage"`
	Limitations                 []string       `json:"limitations"`
}

type ObservedReport struct {
	CasesEvaluated      int          `json:"casesEvaluated"`
	CasesMatched        int          `json:"casesMatched"`
	ExpectationsMatched bool         `json:"expectationsMatched"`
	Cases               []CaseResult `json:"cases"`
}

type CaseResult struct {
	ID                   string   `json:"id"`
	Title                string   `json:"title"`
	ObservedPhase        string   `json:"observedPhase"`
	ReconstructionStatus string   `json:"reconstructionStatus"`
	ExpectationsMatched  bool     `json:"expectationsMatched"`
	AddedBehaviorTypes   []string `json:"addedBehaviorTypes"`
	RuleIDs              []string `json:"ruleIds"`
	HighestReviewLevel   string   `json:"highestReviewLevel"`
	BaselineDigest       string   `json:"baselineDigest"`
	CandidateDigest      string   `json:"candidateDigest"`
	UnsupportedSignals   []string `json:"unsupportedSignals"`
}

func Load(path string) (Manifest, []byte, error) {
	// #nosec G304 -- the local CLI explicitly accepts a caller-selected manifest.
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, nil, err
	}
	if len(raw) > maxManifestBytes {
		return Manifest{}, nil, fmt.Errorf("benchmark manifest exceeds %d bytes", maxManifestBytes)
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, nil, fmt.Errorf("decode benchmark manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return Manifest{}, nil, errors.New("benchmark manifest contains multiple JSON values")
		}
		return Manifest{}, nil, fmt.Errorf("decode benchmark manifest trailing data: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, nil, err
	}
	return manifest, raw, nil
}

func Run(manifestPath string) (Report, error) {
	manifest, raw, err := Load(manifestPath)
	if err != nil {
		return Report{}, err
	}
	baseDirectory, err := filepath.Abs(filepath.Dir(manifestPath))
	if err != nil {
		return Report{}, err
	}
	results := make([]CaseResult, 0, len(manifest.Cases))
	for _, benchmarkCase := range manifest.Cases {
		result, err := runCase(baseDirectory, benchmarkCase)
		if err != nil {
			return Report{}, fmt.Errorf("benchmark case %s: %w", benchmarkCase.ID, err)
		}
		results = append(results, result)
	}
	sum := sha256.Sum256(raw)
	report := Report{
		SchemaVersion:  1,
		Kind:           "behaviorlock.inert-benchmark.report",
		ManifestSHA256: "sha256:" + hex.EncodeToString(sum[:]),
		CorpusPolicy:   manifest.CorpusPolicy,
		Observed: ObservedReport{
			CasesEvaluated:      len(results),
			CasesMatched:        len(results),
			ExpectationsMatched: true,
			Cases:               results,
		},
		ProjectedHistoricalCoverage: append([]Projection(nil), manifest.ProjectedHistoricalCoverage...),
		Limitations: []string{
			"Observed results come only from inert offline trace reconstructions.",
			"Projected historical coverage is citation-backed analysis, not an executed detection result.",
			"A matched behavior family is review evidence and is not a malware, safety, or intent classification.",
		},
	}
	return report, nil
}

func runCase(baseDirectory string, benchmarkCase Case) (CaseResult, error) {
	baseline, err := profileFixture(baseDirectory, benchmarkCase.Baseline)
	if err != nil {
		return CaseResult{}, fmt.Errorf("baseline: %w", err)
	}
	candidate, err := profileFixture(baseDirectory, benchmarkCase.Candidate)
	if err != nil {
		return CaseResult{}, fmt.Errorf("candidate: %w", err)
	}
	difference, err := compare.ProfilesWithOptions(baseline, candidate, toolVersion, compare.Options{AllowExternal: true})
	if err != nil {
		return CaseResult{}, err
	}
	behaviorTypes := uniqueSorted(len(difference.Added), func(index int) string { return difference.Added[index].Behavior.Type })
	ruleIDs := uniqueSorted(len(difference.Added), func(index int) string { return difference.Added[index].RuleID })
	expectedTypes := sortedCopy(benchmarkCase.Expected.AddedBehaviorTypes)
	expectedRules := sortedCopy(benchmarkCase.Expected.RuleIDs)
	if !equalStrings(behaviorTypes, expectedTypes) {
		return CaseResult{}, fmt.Errorf("added behavior types changed: expected %v, observed %v", expectedTypes, behaviorTypes)
	}
	if !equalStrings(ruleIDs, expectedRules) {
		return CaseResult{}, fmt.Errorf("rule identifiers changed: expected %v, observed %v", expectedRules, ruleIDs)
	}
	if difference.Summary.HighestReviewLevel != benchmarkCase.Expected.HighestReviewLevel {
		return CaseResult{}, fmt.Errorf("highest review level changed: expected %s, observed %s", benchmarkCase.Expected.HighestReviewLevel, difference.Summary.HighestReviewLevel)
	}
	return CaseResult{
		ID:                   benchmarkCase.ID,
		Title:                benchmarkCase.Title,
		ObservedPhase:        benchmarkCase.ObservedPhase,
		ReconstructionStatus: benchmarkCase.ReconstructionStatus,
		ExpectationsMatched:  true,
		AddedBehaviorTypes:   behaviorTypes,
		RuleIDs:              ruleIDs,
		HighestReviewLevel:   difference.Summary.HighestReviewLevel,
		BaselineDigest:       difference.BaselineDigest,
		CandidateDigest:      difference.CandidateDigest,
		UnsupportedSignals:   append([]string(nil), benchmarkCase.UnsupportedSignals...),
	}, nil
}

func profileFixture(baseDirectory string, fixture Fixture) (model.Profile, error) {
	spec, err := npm.ParseExactSpec(fixture.Package)
	if err != nil {
		return model.Profile{}, err
	}
	tracePath, err := confinedTracePath(baseDirectory, fixture.Trace)
	if err != nil {
		return model.Profile{}, err
	}
	// #nosec G304 -- confinedTracePath proves the path is a regular file inside benchmark/corpus.
	raw, err := os.ReadFile(tracePath)
	if err != nil {
		return model.Profile{}, err
	}
	parsed, err := trace.Parse(bytes.NewReader(raw))
	if err != nil {
		return model.Profile{}, err
	}
	if parsed.Stats.RecognizedLines == 0 {
		return model.Profile{}, errors.New("trace contains no recognized events")
	}
	profile := model.NewProfile(model.Subject{Ecosystem: "npm", Name: spec.Name, Version: spec.Version, PURL: spec.PURL()}, toolVersion)
	profile.Capture.RunnerImage = "external-trace"
	profile.Capture.RunnerImageID = "unverified"
	profile.Capture.Architecture = "unknown"
	profile.Capture.NodeVersion = "unknown"
	profile.Capture.NPMVersion = "unknown"
	profile.Capture.StraceVersion = "unknown"
	profile.Capture.NetworkMode = "unknown"
	profile.Capture.SandboxProfile = "external-unverified"
	profile.Capture.TraceIntegrity = "external-unverified"
	profile.Capture.Phase = "external"
	profile.Capture.Coverage = model.CaptureCoverage{
		Scope: "external-strace", Lifecycle: []string{}, Completeness: "unverified",
		Limitations: []string{"The benchmark replays an inert handwritten trace; capture conditions are not attested."},
	}
	profile.Behaviors = parsed.Behaviors
	profile.Sequences = model.BuildObservationSequences(parsed.Behaviors)
	model.AttachEvidence(&profile, raw, "external-unverified", "external-strace")
	profile.Result = model.Result{Status: "complete", ExitCode: 0}
	profile.Normalize()
	if err := model.ValidateProfile(profile); err != nil {
		return model.Profile{}, err
	}
	return profile, nil
}

func confinedTracePath(baseDirectory, relative string) (string, error) {
	if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || !strings.HasPrefix(filepath.ToSlash(relative), "corpus/") {
		return "", errors.New("trace path must be a canonical relative path under corpus")
	}
	corpusRoot := filepath.Join(baseDirectory, "corpus")
	rootResolved, err := filepath.EvalSymlinks(corpusRoot)
	if err != nil {
		return "", fmt.Errorf("resolve corpus root: %w", err)
	}
	joined := filepath.Join(baseDirectory, relative)
	info, err := os.Lstat(joined)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("trace fixture must be a regular non-symlink file")
	}
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", err
	}
	relativeToRoot, err := filepath.Rel(rootResolved, resolved)
	if err != nil || relativeToRoot == ".." || strings.HasPrefix(relativeToRoot, ".."+string(filepath.Separator)) {
		return "", errors.New("trace fixture escapes the corpus root")
	}
	return resolved, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != 1 {
		return errors.New("unsupported benchmark manifest schema version")
	}
	if manifest.CorpusPolicy.SampleClass != "inert-reconstruction-only" || manifest.CorpusPolicy.NetworkPolicy != "offline-trace-replay" {
		return errors.New("benchmark corpus policy must remain inert and offline")
	}
	if len(manifest.CorpusPolicy.ProhibitedContent) == 0 || len(manifest.CorpusPolicy.ProhibitedContent) > 16 {
		return errors.New("benchmark corpus prohibited-content policy is missing or too large")
	}
	if len(manifest.Cases) == 0 || len(manifest.Cases) > 128 || len(manifest.ProjectedHistoricalCoverage) > 128 {
		return errors.New("benchmark case or projection count is outside its bound")
	}
	caseIDs := make(map[string]struct{}, len(manifest.Cases))
	for _, benchmarkCase := range manifest.Cases {
		if !validID(benchmarkCase.ID) || !safeText(benchmarkCase.Title, 256) || benchmarkCase.ObservedPhase != "external" || benchmarkCase.ReconstructionStatus != "inert-handwritten" {
			return fmt.Errorf("benchmark case %q has invalid identity or reconstruction metadata", benchmarkCase.ID)
		}
		if _, exists := caseIDs[benchmarkCase.ID]; exists {
			return fmt.Errorf("duplicate benchmark case %s", benchmarkCase.ID)
		}
		caseIDs[benchmarkCase.ID] = struct{}{}
		baselineSpec, err := npm.ParseExactSpec(benchmarkCase.Baseline.Package)
		if err != nil {
			return fmt.Errorf("benchmark case %s baseline package: %w", benchmarkCase.ID, err)
		}
		candidateSpec, err := npm.ParseExactSpec(benchmarkCase.Candidate.Package)
		if err != nil {
			return fmt.Errorf("benchmark case %s candidate package: %w", benchmarkCase.ID, err)
		}
		if baselineSpec.Name != candidateSpec.Name {
			return fmt.Errorf("benchmark case %s compares different packages", benchmarkCase.ID)
		}
		if err := validateFixture(benchmarkCase.Baseline); err != nil {
			return fmt.Errorf("benchmark case %s baseline: %w", benchmarkCase.ID, err)
		}
		if err := validateFixture(benchmarkCase.Candidate); err != nil {
			return fmt.Errorf("benchmark case %s candidate: %w", benchmarkCase.ID, err)
		}
		if err := validateCitations(benchmarkCase.Citations); err != nil {
			return fmt.Errorf("benchmark case %s citations: %w", benchmarkCase.ID, err)
		}
		if err := validateExpectation(benchmarkCase.Expected); err != nil {
			return fmt.Errorf("benchmark case %s expectation: %w", benchmarkCase.ID, err)
		}
		if err := validateTextSet(benchmarkCase.UnsupportedSignals, 1, 32, 512); err != nil {
			return fmt.Errorf("benchmark case %s unsupported signals: %w", benchmarkCase.ID, err)
		}
	}
	projectionIDs := make(map[string]struct{}, len(manifest.ProjectedHistoricalCoverage))
	for _, projection := range manifest.ProjectedHistoricalCoverage {
		if !validID(projection.ID) || !safeText(projection.Title, 256) || projection.Status != "projection-only" {
			return fmt.Errorf("historical projection %q is invalid", projection.ID)
		}
		if _, exists := projectionIDs[projection.ID]; exists {
			return fmt.Errorf("duplicate historical projection %s", projection.ID)
		}
		projectionIDs[projection.ID] = struct{}{}
		if err := validateTextSet(projection.FixtureIDs, 1, 32, 64); err != nil {
			return fmt.Errorf("historical projection %s fixture ids: %w", projection.ID, err)
		}
		for _, fixtureID := range projection.FixtureIDs {
			if _, exists := caseIDs[fixtureID]; !exists {
				return fmt.Errorf("historical projection %s references unknown fixture %s", projection.ID, fixtureID)
			}
		}
		if err := validateCitations(projection.Citations); err != nil {
			return fmt.Errorf("historical projection %s citations: %w", projection.ID, err)
		}
		if err := validateTextSet(projection.Limitations, 1, 32, 512); err != nil {
			return fmt.Errorf("historical projection %s limitations: %w", projection.ID, err)
		}
	}
	return nil
}

func validateFixture(fixture Fixture) error {
	path := filepath.ToSlash(fixture.Trace)
	if filepath.IsAbs(fixture.Trace) || filepath.Clean(fixture.Trace) != fixture.Trace || !strings.HasPrefix(path, "corpus/") || !strings.HasSuffix(path, ".strace") {
		return errors.New("trace must be a canonical corpus .strace path")
	}
	return nil
}

func validateCitations(citations []Citation) error {
	if len(citations) == 0 || len(citations) > 16 {
		return errors.New("citation count is outside its bound")
	}
	seen := make(map[string]struct{}, len(citations))
	for _, citation := range citations {
		parsed, err := url.Parse(citation.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || !safeText(citation.Title, 256) || !safeText(citation.Relationship, 128) {
			return errors.New("citation is incomplete or unsafe")
		}
		if _, exists := seen[citation.URL]; exists {
			return errors.New("citation URLs must be unique")
		}
		seen[citation.URL] = struct{}{}
	}
	return nil
}

func validateExpectation(expectation Expectation) error {
	if err := validateTextSet(expectation.AddedBehaviorTypes, 1, 64, 128); err != nil {
		return err
	}
	if err := validateTextSet(expectation.RuleIDs, 1, 64, 8); err != nil {
		return err
	}
	for _, ruleID := range expectation.RuleIDs {
		if len(ruleID) != 5 || !strings.HasPrefix(ruleID, "BL") {
			return fmt.Errorf("invalid rule identifier %q", ruleID)
		}
	}
	if model.ReviewLevelRank(expectation.HighestReviewLevel) == 0 {
		return errors.New("highest review level must be low, medium, high, or critical")
	}
	return nil
}

func validateTextSet(values []string, minimum, maximum, maxLength int) error {
	if len(values) < minimum || len(values) > maximum {
		return errors.New("item count is outside its bound")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !safeText(value, maxLength) || value == "" {
			return errors.New("item contains unsafe text")
		}
		if _, exists := seen[value]; exists {
			return errors.New("items must be unique")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validID(value string) bool {
	return len(value) <= 64 && idPattern.MatchString(value)
}

func safeText(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func uniqueSorted(length int, value func(int) string) []string {
	set := make(map[string]struct{}, length)
	for index := 0; index < length; index++ {
		set[value(index)] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for item := range set {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func MarshalJSON(report Report) ([]byte, error) {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func RenderMarkdown(report Report) string {
	var builder strings.Builder
	builder.WriteString("# Inert benchmark report\n\n")
	fmt.Fprintf(&builder, "Manifest: `%s`\n\n", report.ManifestSHA256)
	fmt.Fprintf(&builder, "All %d inert reconstruction cases matched their exact declared expectations.\n\n", report.Observed.CasesMatched)
	builder.WriteString("| Case | Added behavior types | Rule IDs | Highest review level |\n")
	builder.WriteString("| --- | --- | --- | --- |\n")
	for _, result := range report.Observed.Cases {
		fmt.Fprintf(&builder, "| %s | %s | %s | %s |\n", markdownEscape(result.ID), markdownEscape(strings.Join(result.AddedBehaviorTypes, ", ")), markdownEscape(strings.Join(result.RuleIDs, ", ")), markdownEscape(result.HighestReviewLevel))
	}
	builder.WriteString("\n## Projected historical coverage\n\n")
	builder.WriteString("These entries were not executed and are not demonstrated detections.\n\n")
	for _, projection := range report.ProjectedHistoricalCoverage {
		fmt.Fprintf(&builder, "- **%s:** projection only; reconstructed fixture families: %s.\n", markdownEscape(projection.Title), markdownEscape(strings.Join(projection.FixtureIDs, ", ")))
	}
	builder.WriteString("\n## Limits\n\n")
	for _, limitation := range report.Limitations {
		fmt.Fprintf(&builder, "- %s\n", markdownEscape(limitation))
	}
	return builder.String()
}

func markdownEscape(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "|", "\\|", "*", "\\*", "_", "\\_", "`", "\\`")
	return replacer.Replace(value)
}
