package capture

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kiranmagic7/behaviorlock/internal/model"
)

func TestCanariesAreUniqueReservedMarkersAndOnlyVisibleSurfacesAreAnnotated(t *testing.T) {
	t.Parallel()
	raw := make([]byte, 16*len(canaryTemplates))
	for index := range raw {
		raw[index] = byte(index)
	}
	canaries, err := newCanarySet(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, len(canaries))
	for _, canary := range canaries {
		if !strings.HasPrefix(canary.Value, "behaviorlock-canary.invalid/") {
			t.Fatalf("canary does not use the reserved invalid marker: %q", canary.Value)
		}
		if _, exists := seen[canary.Value]; exists {
			t.Fatalf("duplicate canary value: %q", canary.Value)
		}
		seen[canary.Value] = struct{}{}
	}
	value := canaries[0].Value
	behaviors := []model.Behavior{
		{Type: "process.exec", Target: "/bin/sh", Arguments: []string{"-c", "send " + value}},
		{Type: "filesystem.create", Target: "$WORK/" + value},
		{Type: "network.connect", Target: "AF_INET:" + value + ":443"},
	}
	applyCanaryObservations(behaviors, canaries)
	if len(behaviors[0].CanaryIDs) != 1 || !strings.Contains(behaviors[0].Arguments[1], "$CANARY[ssh-private-key]") {
		t.Fatalf("process argument did not receive a stable canary reference: %#v", behaviors[0])
	}
	if len(behaviors[1].CanaryIDs) != 1 || !strings.Contains(behaviors[1].Target, "$CANARY[ssh-private-key]") {
		t.Fatalf("filesystem target did not receive a stable canary reference: %#v", behaviors[1])
	}
	if len(behaviors[2].CanaryIDs) != 0 || !strings.Contains(behaviors[2].Target, value) {
		t.Fatalf("non-approved network target surface was scanned or rewritten: %#v", behaviors[2])
	}
}
