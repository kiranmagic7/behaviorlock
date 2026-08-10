package compare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/kiranmagic7/behaviorlock/internal/model"
)

func TestVersionedRuleRegistryHasUniqueStableIdentifiers(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "rules-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		SchemaVersion int `json:"schemaVersion"`
		Rules         []struct {
			ID          string `json:"id"`
			ReviewLevel string `json:"reviewLevel"`
			Family      string `json:"family"`
			Description string `json:"description"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	if registry.SchemaVersion != 1 || len(registry.Rules) == 0 {
		t.Fatal("rule registry schema or content is invalid")
	}
	identifier := regexp.MustCompile(`^BL[0-9]{3}$`)
	seen := make(map[string]string, len(registry.Rules))
	for _, rule := range registry.Rules {
		if !identifier.MatchString(rule.ID) || seen[rule.ID] != "" || rule.Family == "" || rule.Description == "" {
			t.Fatalf("invalid or duplicate rule: %#v", rule)
		}
		if rule.ReviewLevel != "low" && rule.ReviewLevel != "medium" && rule.ReviewLevel != "high" && rule.ReviewLevel != "critical" {
			t.Fatalf("invalid review level for %s", rule.ID)
		}
		seen[rule.ID] = rule.ReviewLevel
	}
	if seen["BL500"] == "" || seen["BL600"] == "" {
		t.Fatal("ordinary reads and environment fingerprints lost their established identifiers")
	}

	representatives := []model.Behavior{
		{Type: "filesystem.read", Target: "$HOME/.ssh/id_rsa", Sensitive: true},
		{Type: "network.connect"}, {Type: "network.send"}, {Type: "network.dns"},
		{Type: "network.bind"}, {Type: "network.accept"}, {Type: "network.socket"},
		{Type: "process.exec", Target: "/bin/sh"}, {Type: "process.exec", Target: "/usr/bin/node"},
		{Type: "process.create"}, {Type: "process.memfd"}, {Type: "process.ptrace"},
		{Type: "filesystem.write", Target: "/etc/example"},
		{Type: "filesystem.write", Target: "$WORK/example"},
		{Type: "filesystem.delete"}, {Type: "filesystem.truncate"},
		{Type: "filesystem.read", Target: "/etc/hosts"}, {Type: "filesystem.enumerate"},
		{Type: "filesystem.read", Target: "/.dockerenv"}, {Type: "environment.timing"},
		{Type: "future.observation"},
	}
	classified := make(map[string]bool, len(representatives))
	for _, behavior := range representatives {
		level, ruleID, _ := classify(behavior)
		if registryLevel := seen[ruleID]; registryLevel == "" || registryLevel != level {
			t.Fatalf("classification %s %s is absent from or disagrees with the registry", ruleID, level)
		}
		classified[ruleID] = true
	}
	for ruleID := range seen {
		if !classified[ruleID] {
			t.Fatalf("registry rule %s has no representative runtime classification", ruleID)
		}
	}
}
