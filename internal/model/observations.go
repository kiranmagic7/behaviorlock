package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

func normalizeStrings(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			unique[value] = struct{}{}
		}
	}
	values = make([]string, 0, len(unique))
	for value := range unique {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func normalizeCanaryDescriptors(canaries []CanaryDescriptor) []CanaryDescriptor {
	normalized := make([]CanaryDescriptor, len(canaries))
	copy(normalized, canaries)
	canaries = normalized
	sort.Slice(canaries, func(i, j int) bool {
		return canaries[i].ID < canaries[j].ID
	})
	return canaries
}

func normalizeObservationSequences(sequences []ObservationSequence) []ObservationSequence {
	unique := make(map[string]ObservationSequence, len(sequences))
	for _, sequence := range sequences {
		sequence.BehaviorIDs = deduplicateOrdered(sequence.BehaviorIDs)
		sequence.CanaryIDs = normalizeStrings(sequence.CanaryIDs)
		sequence.ID = StableSequenceID(sequence)
		unique[sequence.ID] = sequence
	}
	sequences = make([]ObservationSequence, 0, len(unique))
	for _, sequence := range unique {
		sequences = append(sequences, sequence)
	}
	sort.Slice(sequences, func(i, j int) bool {
		return sequences[i].ID < sequences[j].ID
	})
	if len(sequences) > maxSequences {
		sequences = sequences[:maxSequences]
	}
	return sequences
}

func deduplicateOrdered(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func StableSequenceID(sequence ObservationSequence) string {
	canonical := strings.Join([]string{
		sequence.Scope,
		strings.Join(sequence.BehaviorIDs, "\x1f"),
		strings.Join(normalizeStrings(sequence.CanaryIDs), "\x1f"),
	}, "\x1e")
	sum := sha256.Sum256([]byte(canonical))
	return "sequence:sha256:" + hex.EncodeToString(sum[:])
}

// BuildObservationSequences groups selected observations by their root process
// lineage. Runtime process identifiers are used only during construction and
// never enter the resulting sequence or stable identifier.
func BuildObservationSequences(behaviors []Behavior) []ObservationSequence {
	parents := make(map[string]string)
	for _, behavior := range behaviors {
		for _, runtime := range behavior.Runtime {
			if runtime.Process != "" && runtime.Parent != "" {
				parents[runtime.Process] = runtime.Parent
			}
		}
	}

	type lineageEvents struct {
		behaviorIDs []string
		canaryIDs   []string
		hasAnchor   bool
		hasAction   bool
	}
	lineages := make(map[string]*lineageEvents)
	for _, behavior := range behaviors {
		if !sequenceRelevant(behavior) || len(behavior.Runtime) == 0 {
			continue
		}
		process := behavior.Runtime[0].Process
		root := lineageRoot(process, parents)
		lineage := lineages[root]
		if lineage == nil {
			lineage = &lineageEvents{}
			lineages[root] = lineage
		}
		identifier := StableBehaviorID(behavior)
		if len(lineage.behaviorIDs) == 0 || lineage.behaviorIDs[len(lineage.behaviorIDs)-1] != identifier {
			if len(lineage.behaviorIDs) < maxSequenceEvents {
				lineage.behaviorIDs = append(lineage.behaviorIDs, identifier)
			}
		}
		lineage.canaryIDs = append(lineage.canaryIDs, behavior.CanaryIDs...)
		if behavior.Sensitive || len(behavior.CanaryIDs) > 0 || behavior.Type == "filesystem.create" || behavior.Type == "filesystem.write" {
			lineage.hasAnchor = true
		}
		if strings.HasPrefix(behavior.Type, "network.") || strings.HasPrefix(behavior.Type, "process.") || behavior.Type == "filesystem.permission" {
			lineage.hasAction = true
		}
	}

	sequences := make([]ObservationSequence, 0, len(lineages))
	for _, lineage := range lineages {
		behaviorIDs := deduplicateOrdered(lineage.behaviorIDs)
		if len(behaviorIDs) < 2 || !lineage.hasAnchor || !lineage.hasAction {
			continue
		}
		sequence := ObservationSequence{
			Scope:       "process-lineage-observed-order",
			BehaviorIDs: behaviorIDs,
			CanaryIDs:   normalizeStrings(lineage.canaryIDs),
		}
		sequence.ID = StableSequenceID(sequence)
		sequences = append(sequences, sequence)
	}
	return normalizeObservationSequences(sequences)
}

func lineageRoot(process string, parents map[string]string) string {
	seen := make(map[string]struct{})
	current := process
	for current != "" && current != "root" {
		if _, exists := seen[current]; exists {
			break
		}
		seen[current] = struct{}{}
		parent := parents[current]
		if parent == "" || parent == "root" {
			break
		}
		current = parent
	}
	return current
}

func sequenceRelevant(behavior Behavior) bool {
	if behavior.Sensitive || len(behavior.CanaryIDs) > 0 {
		return true
	}
	switch behavior.Type {
	case "filesystem.create", "filesystem.write", "filesystem.permission",
		"process.exec", "process.create", "process.fileless_exec", "process.memfd",
		"network.connect", "network.send", "network.dns", "network.listen":
		return true
	default:
		return false
	}
}

func validateObservationMetadata(profile Profile) error {
	if len(profile.Capture.Canaries) > maxCanaries {
		return fmt.Errorf("profile exceeds %d canary descriptors", maxCanaries)
	}
	canaries := make(map[string]struct{}, len(profile.Capture.Canaries))
	for _, canary := range profile.Capture.Canaries {
		if !validCanaryID(canary.ID) || !safeField(canary.Location, 512) || canary.Location == "" {
			return errors.New("profile canary descriptor is invalid")
		}
		if canary.Kind != "file" && canary.Kind != "environment" {
			return errors.New("profile canary kind is invalid")
		}
		if _, exists := canaries[canary.ID]; exists {
			return errors.New("profile canary identifiers are not unique")
		}
		canaries[canary.ID] = struct{}{}
	}
	if profile.Capture.Sinkhole != nil {
		for _, canaryID := range profile.Capture.Sinkhole.CanaryIDs {
			if _, exists := canaries[canaryID]; !exists {
				return errors.New("sinkhole references an undeclared canary")
			}
		}
	}

	behaviorIDs := make(map[string]struct{}, len(profile.Behaviors))
	for _, behavior := range profile.Behaviors {
		behaviorIDs[behavior.ID] = struct{}{}
		for _, canaryID := range behavior.CanaryIDs {
			if _, exists := canaries[canaryID]; !exists {
				return errors.New("behavior references an undeclared canary")
			}
		}
	}

	if len(profile.Sequences) > maxSequences {
		return fmt.Errorf("profile exceeds %d observation sequences", maxSequences)
	}
	sequenceIDs := make(map[string]struct{}, len(profile.Sequences))
	for _, sequence := range profile.Sequences {
		if sequence.Scope != "process-lineage-observed-order" || len(sequence.BehaviorIDs) < 2 || len(sequence.BehaviorIDs) > maxSequenceEvents || sequence.ID != StableSequenceID(sequence) {
			return errors.New("observation sequence identity or scope is invalid")
		}
		if _, exists := sequenceIDs[sequence.ID]; exists {
			return errors.New("observation sequence identifiers are not unique")
		}
		sequenceIDs[sequence.ID] = struct{}{}
		seenBehaviors := make(map[string]struct{}, len(sequence.BehaviorIDs))
		for _, behaviorID := range sequence.BehaviorIDs {
			if _, exists := behaviorIDs[behaviorID]; !exists {
				return errors.New("observation sequence references an unknown behavior")
			}
			if _, exists := seenBehaviors[behaviorID]; exists {
				return errors.New("observation sequence repeats a behavior identifier")
			}
			seenBehaviors[behaviorID] = struct{}{}
		}
		for _, canaryID := range sequence.CanaryIDs {
			if _, exists := canaries[canaryID]; !exists {
				return errors.New("observation sequence references an undeclared canary")
			}
		}
	}
	return nil
}

func validCanaryID(value string) bool {
	if !strings.HasPrefix(value, "canary:") || len(value) < len("canary:a") || len(value) > 96 {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "canary:") {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
