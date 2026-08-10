package releasegate

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const maxInputBytes = 1 << 20

type Config struct {
	SchemaVersion int             `json:"schemaVersion"`
	MaxAgeHours   int             `json:"maxAgeHours"`
	Proofs        []RequiredProof `json:"proofs"`
}

type RequiredProof struct {
	ID          string `json:"id"`
	Check       string `json:"check"`
	Description string `json:"description"`
}

type Evidence struct {
	SchemaVersion int             `json:"schemaVersion"`
	Repository    string          `json:"repository"`
	SourceSHA     string          `json:"sourceSha"`
	GeneratedAt   time.Time       `json:"generatedAt"`
	Proofs        []ObservedProof `json:"proofs"`
}

type ObservedProof struct {
	ID          string    `json:"id"`
	Check       string    `json:"check"`
	Status      string    `json:"status"`
	Conclusion  string    `json:"conclusion"`
	SourceSHA   string    `json:"sourceSha"`
	CompletedAt time.Time `json:"completedAt"`
	DetailsURL  string    `json:"detailsUrl"`
}

type Report struct {
	SchemaVersion     int          `json:"schemaVersion"`
	Kind              string       `json:"kind"`
	Repository        string       `json:"repository"`
	SourceSHA         string       `json:"sourceSha"`
	EvidenceGenerated time.Time    `json:"evidenceGeneratedAt"`
	AssessedAt        time.Time    `json:"assessedAt"`
	MaxAgeHours       int          `json:"maxAgeHours"`
	GatesExpected     int          `json:"gatesExpected"`
	GatesSatisfied    int          `json:"gatesSatisfied"`
	AllGatesSatisfied bool         `json:"allGatesSatisfied"`
	Issues            []string     `json:"issues"`
	Gates             []GateResult `json:"gates"`
}

type GateResult struct {
	ID          string    `json:"id"`
	Check       string    `json:"check"`
	Description string    `json:"description"`
	Satisfied   bool      `json:"satisfied"`
	Status      string    `json:"status"`
	Conclusion  string    `json:"conclusion"`
	CompletedAt time.Time `json:"completedAt"`
	DetailsURL  string    `json:"detailsUrl,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

func Load(configPath, evidencePath string) (Config, Evidence, error) {
	var config Config
	if err := decodeStrict(configPath, &config); err != nil {
		return Config{}, Evidence{}, fmt.Errorf("release proof configuration: %w", err)
	}
	var evidence Evidence
	if err := decodeStrict(evidencePath, &evidence); err != nil {
		return Config{}, Evidence{}, fmt.Errorf("release proof evidence: %w", err)
	}
	return config, evidence, nil
}

func Verify(config Config, evidence Evidence, repository, sourceSHA string, now time.Time) error {
	report, err := Assess(config, evidence, repository, sourceSHA, now)
	if err != nil {
		return err
	}
	if report.AllGatesSatisfied {
		return nil
	}
	if len(report.Issues) > 0 {
		return errors.New(report.Issues[0])
	}
	for _, gate := range report.Gates {
		if !gate.Satisfied {
			return fmt.Errorf("proof %s %s", gate.ID, gate.Reason)
		}
	}
	return errors.New("release proofs are incomplete")
}

func Assess(config Config, evidence Evidence, repository, sourceSHA string, now time.Time) (Report, error) {
	if config.SchemaVersion != 1 || evidence.SchemaVersion != 1 {
		return Report{}, errors.New("unsupported release proof schema version")
	}
	if len(config.Proofs) != 14 {
		return Report{}, fmt.Errorf("release proof configuration must define exactly 14 gates, found %d", len(config.Proofs))
	}
	if config.MaxAgeHours < 1 || config.MaxAgeHours > 168 {
		return Report{}, errors.New("release proof maxAgeHours must be between 1 and 168")
	}
	if !validRepository(repository) || !validSHA(sourceSHA) {
		return Report{}, errors.New("expected repository or source SHA is invalid")
	}

	required := make(map[string]RequiredProof, len(config.Proofs))
	checks := make(map[string]struct{}, len(config.Proofs))
	for _, proof := range config.Proofs {
		if proof.ID == "" || proof.Check == "" || proof.Description == "" {
			return Report{}, errors.New("release proof configuration contains an incomplete gate")
		}
		if _, exists := required[proof.ID]; exists {
			return Report{}, fmt.Errorf("duplicate required proof %s", proof.ID)
		}
		if _, exists := checks[proof.Check]; exists {
			return Report{}, fmt.Errorf("duplicate required check %s", proof.Check)
		}
		required[proof.ID] = proof
		checks[proof.Check] = struct{}{}
	}

	report := Report{
		SchemaVersion:     1,
		Kind:              "behaviorlock.release-gate.report",
		Repository:        repository,
		SourceSHA:         sourceSHA,
		EvidenceGenerated: evidence.GeneratedAt,
		AssessedAt:        now.UTC(),
		MaxAgeHours:       config.MaxAgeHours,
		GatesExpected:     len(config.Proofs),
		Issues:            []string{},
		Gates:             make([]GateResult, 0, len(config.Proofs)),
	}
	maxAge := time.Duration(config.MaxAgeHours) * time.Hour
	if evidence.Repository != repository || evidence.SourceSHA != sourceSHA {
		report.Issues = append(report.Issues, "release proof evidence does not describe the expected repository and source SHA")
	}
	if err := fresh("evidence manifest", evidence.GeneratedAt, now, maxAge); err != nil {
		report.Issues = append(report.Issues, err.Error())
	}

	observed := make(map[string]ObservedProof, len(evidence.Proofs))
	for _, proof := range evidence.Proofs {
		if _, exists := observed[proof.ID]; exists {
			report.Issues = append(report.Issues, fmt.Sprintf("duplicate observed proof %s", proof.ID))
			continue
		}
		observed[proof.ID] = proof
	}
	for _, expectation := range config.Proofs {
		id := expectation.ID
		result := GateResult{ID: id, Check: expectation.Check, Description: expectation.Description}
		proof, exists := observed[id]
		if !exists {
			result.Status = "missing"
			result.Conclusion = "missing"
			result.Reason = "is missing"
			report.Gates = append(report.Gates, result)
			continue
		}
		result.Status = proof.Status
		result.Conclusion = proof.Conclusion
		result.CompletedAt = proof.CompletedAt
		result.DetailsURL = proof.DetailsURL
		switch {
		case proof.Check != expectation.Check || proof.SourceSHA != sourceSHA:
			result.Reason = "does not match its required check and source SHA"
		case proof.Status != "completed" || proof.Conclusion != "success":
			result.Reason = fmt.Sprintf("did not complete successfully: status=%s conclusion=%s", proof.Status, proof.Conclusion)
		case fresh("proof "+id, proof.CompletedAt, now, maxAge) != nil:
			result.Reason = freshReason(id, proof.CompletedAt, now, maxAge)
		case !trustedDetailsURL(proof.DetailsURL, repository):
			result.Reason = "has an untrusted details URL"
		default:
			result.Satisfied = true
			report.GatesSatisfied++
		}
		report.Gates = append(report.Gates, result)
	}
	for id := range observed {
		if _, exists := required[id]; !exists {
			report.Issues = append(report.Issues, fmt.Sprintf("release proof evidence contains unexpected gate %s", id))
		}
	}
	sort.Strings(report.Issues)
	report.AllGatesSatisfied = report.GatesSatisfied == report.GatesExpected && len(report.Issues) == 0
	return report, nil
}

func freshReason(id string, completedAt, now time.Time, maxAge time.Duration) string {
	if err := fresh("proof "+id, completedAt, now, maxAge); err != nil {
		return strings.TrimPrefix(err.Error(), "proof "+id+" ")
	}
	return "has invalid freshness evidence"
}

func decodeStrict(path string, target any) error {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("input must be a regular non-symlink file")
	}
	if pathInfo.Size() > maxInputBytes {
		return fmt.Errorf("input exceeds %d bytes", maxInputBytes)
	}
	// #nosec G304 -- path is explicit CLI input; Lstat, SameFile, mode, and size checks reject links and replacement races.
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Size() > maxInputBytes || !os.SameFile(pathInfo, openedInfo) {
		return errors.New("input changed or became unsafe while opening")
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func fresh(label string, timestamp, now time.Time, maxAge time.Duration) error {
	if timestamp.IsZero() {
		return fmt.Errorf("%s timestamp is missing", label)
	}
	if timestamp.After(now.Add(5 * time.Minute)) {
		return fmt.Errorf("%s timestamp is in the future", label)
	}
	if now.Sub(timestamp) > maxAge {
		return fmt.Errorf("%s is stale", label)
	}
	return nil
}

func validRepository(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.Trim(part, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != "" {
			return false
		}
	}
	return true
}

func validSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func trustedDetailsURL(value, repository string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	prefix := "/" + repository + "/actions/runs/"
	return strings.HasPrefix(parsed.EscapedPath(), prefix) && len(parsed.EscapedPath()) > len(prefix)
}

func MarshalReport(report Report) ([]byte, error) {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func RenderMarkdown(report Report) string {
	var builder strings.Builder
	builder.WriteString("# Release gate status\n\n")
	fmt.Fprintf(&builder, "Source: `%s@%s`\n\n", markdownEscape(report.Repository), markdownEscape(report.SourceSHA))
	fmt.Fprintf(&builder, "Satisfied gates: **%d of %d**. All gates satisfied: **%t**.\n\n", report.GatesSatisfied, report.GatesExpected, report.AllGatesSatisfied)
	if len(report.Issues) > 0 {
		builder.WriteString("## Evidence issues\n\n")
		for _, issue := range report.Issues {
			fmt.Fprintf(&builder, "- %s\n", markdownEscape(issue))
		}
		builder.WriteString("\n")
	}
	builder.WriteString("| Gate | Required check | Satisfied | Evidence state | Reason |\n")
	builder.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, gate := range report.Gates {
		state := gate.Status + "/" + gate.Conclusion
		fmt.Fprintf(&builder, "| %s | %s | %t | %s | %s |\n", markdownEscape(gate.ID), markdownEscape(gate.Check), gate.Satisfied, markdownEscape(state), markdownEscape(gate.Reason))
	}
	builder.WriteString("\nA report is descriptive evidence only. It cannot authorize a tag, release, image publication, Marketplace submission, or launch.\n")
	return builder.String()
}

func markdownEscape(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "|", "\\|", "*", "\\*", "_", "\\_", "`", "\\`")
	return replacer.Replace(value)
}
