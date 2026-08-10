package releasegate

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

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
	if config.SchemaVersion != 1 || evidence.SchemaVersion != 1 {
		return errors.New("unsupported release proof schema version")
	}
	if len(config.Proofs) != 14 {
		return fmt.Errorf("release proof configuration must define exactly 14 gates, found %d", len(config.Proofs))
	}
	if config.MaxAgeHours < 1 || config.MaxAgeHours > 168 {
		return errors.New("release proof maxAgeHours must be between 1 and 168")
	}
	if !validRepository(repository) || !validSHA(sourceSHA) {
		return errors.New("expected repository or source SHA is invalid")
	}
	if evidence.Repository != repository || evidence.SourceSHA != sourceSHA {
		return errors.New("release proof evidence does not describe the expected repository and source SHA")
	}
	maxAge := time.Duration(config.MaxAgeHours) * time.Hour
	if err := fresh("evidence manifest", evidence.GeneratedAt, now, maxAge); err != nil {
		return err
	}

	required := make(map[string]RequiredProof, len(config.Proofs))
	checks := make(map[string]struct{}, len(config.Proofs))
	for _, proof := range config.Proofs {
		if proof.ID == "" || proof.Check == "" || proof.Description == "" {
			return errors.New("release proof configuration contains an incomplete gate")
		}
		if _, exists := required[proof.ID]; exists {
			return fmt.Errorf("duplicate required proof %s", proof.ID)
		}
		if _, exists := checks[proof.Check]; exists {
			return fmt.Errorf("duplicate required check %s", proof.Check)
		}
		required[proof.ID] = proof
		checks[proof.Check] = struct{}{}
	}

	observed := make(map[string]ObservedProof, len(evidence.Proofs))
	for _, proof := range evidence.Proofs {
		if _, exists := observed[proof.ID]; exists {
			return fmt.Errorf("duplicate observed proof %s", proof.ID)
		}
		observed[proof.ID] = proof
	}
	for id, expectation := range required {
		proof, exists := observed[id]
		if !exists {
			return fmt.Errorf("required proof %s is missing", id)
		}
		if proof.Check != expectation.Check || proof.SourceSHA != sourceSHA {
			return fmt.Errorf("proof %s does not match its required check and source SHA", id)
		}
		if proof.Status != "completed" || proof.Conclusion != "success" {
			return fmt.Errorf("proof %s did not complete successfully: status=%s conclusion=%s", id, proof.Status, proof.Conclusion)
		}
		if err := fresh("proof "+id, proof.CompletedAt, now, maxAge); err != nil {
			return err
		}
		if !trustedDetailsURL(proof.DetailsURL, repository) {
			return fmt.Errorf("proof %s has an untrusted details URL", id)
		}
	}
	if len(observed) != len(required) {
		return errors.New("release proof evidence contains unexpected gates")
	}
	return nil
}

func decodeStrict(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
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
