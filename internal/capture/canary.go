package capture

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/kiranmagic7/behaviorlock/internal/model"
)

type canarySpec struct {
	Descriptor model.CanaryDescriptor
	Value      string
	RunnerEnv  string
	PackageEnv string
}

var canaryTemplates = []struct {
	id         string
	kind       string
	location   string
	runnerEnv  string
	packageEnv string
}{
	{"canary:ssh-private-key", "file", "$HOME/.ssh/id_rsa", "BEHAVIORLOCK_CANARY_SSH", ""},
	{"canary:aws-credentials-file", "file", "$HOME/.aws/credentials", "BEHAVIORLOCK_CANARY_AWS_FILE", ""},
	{"canary:docker-config", "file", "$HOME/.docker/config.json", "BEHAVIORLOCK_CANARY_DOCKER", ""},
	{"canary:npm-config", "file", "$HOME/.npmrc", "BEHAVIORLOCK_CANARY_NPM_FILE", ""},
	{"canary:aws-access-key-id", "environment", "env:AWS_ACCESS_KEY_ID", "", "AWS_ACCESS_KEY_ID"},
	{"canary:aws-secret-access-key", "environment", "env:AWS_SECRET_ACCESS_KEY", "", "AWS_SECRET_ACCESS_KEY"},
	{"canary:npm-token", "environment", "env:NPM_TOKEN", "", "NPM_TOKEN"},
	{"canary:github-token", "environment", "env:GITHUB_TOKEN", "", "GITHUB_TOKEN"},
}

func newCanarySet(reader io.Reader) ([]canarySpec, error) {
	canaries := make([]canarySpec, 0, len(canaryTemplates))
	seen := make(map[string]struct{}, len(canaryTemplates))
	for _, template := range canaryTemplates {
		random := make([]byte, 16)
		if _, err := io.ReadFull(reader, random); err != nil {
			return nil, fmt.Errorf("generate canary %s: %w", template.id, err)
		}
		value := "behaviorlock-canary.invalid/" + strings.TrimPrefix(template.id, "canary:") + "/" + hex.EncodeToString(random)
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("generated duplicate canary value")
		}
		seen[value] = struct{}{}
		canaries = append(canaries, canarySpec{
			Descriptor: model.CanaryDescriptor{ID: template.id, Kind: template.kind, Location: template.location},
			Value:      value, RunnerEnv: template.runnerEnv, PackageEnv: template.packageEnv,
		})
	}
	return canaries, nil
}

func canaryDescriptors(canaries []canarySpec) []model.CanaryDescriptor {
	descriptors := make([]model.CanaryDescriptor, 0, len(canaries))
	for _, canary := range canaries {
		descriptors = append(descriptors, canary.Descriptor)
	}
	return descriptors
}

func appendCanaryEnvironment(arguments []string, canaries []canarySpec) []string {
	for _, canary := range canaries {
		if canary.RunnerEnv != "" {
			arguments = append(arguments, "--env", canary.RunnerEnv+"="+canary.Value)
		}
		if canary.PackageEnv != "" {
			arguments = append(arguments, "--env", canary.PackageEnv+"="+canary.Value)
		}
	}
	return arguments
}

func applyCanaryObservations(behaviors []model.Behavior, canaries []canarySpec) {
	for index := range behaviors {
		behavior := &behaviors[index]
		if strings.HasPrefix(behavior.Type, "filesystem.") {
			behavior.Target, behavior.CanaryIDs = replaceVisibleCanaries(behavior.Target, behavior.CanaryIDs, canaries)
		}
		if strings.HasPrefix(behavior.Type, "process.") {
			for argumentIndex := range behavior.Arguments {
				behavior.Arguments[argumentIndex], behavior.CanaryIDs = replaceVisibleCanaries(behavior.Arguments[argumentIndex], behavior.CanaryIDs, canaries)
			}
		}
	}
}

func replaceVisibleCanaries(value string, identifiers []string, canaries []canarySpec) (string, []string) {
	for _, canary := range canaries {
		if !strings.Contains(value, canary.Value) {
			continue
		}
		value = strings.ReplaceAll(value, canary.Value, "$CANARY["+strings.TrimPrefix(canary.Descriptor.ID, "canary:")+"]")
		identifiers = append(identifiers, canary.Descriptor.ID)
	}
	return value, identifiers
}
