package model

import "testing"

func TestObservationSequencesIgnoreRuntimePIDChanges(t *testing.T) {
	t.Parallel()
	build := func(parent, child string) []Behavior {
		return []Behavior{
			{Type: "filesystem.read", Operation: "read", Target: "$HOME/.ssh/id_rsa", Outcome: "success", Sensitive: true, CanaryIDs: []string{"canary:ssh-private-key"}, Count: 1, SourceCall: "openat", Runtime: []RuntimeContext{{Process: parent, Parent: "root", Attribution: "direct"}}},
			{Type: "process.create", Operation: "clone", Target: "child", Outcome: "success", Count: 1, SourceCall: "clone", Runtime: []RuntimeContext{{Process: parent, Parent: "root", Attribution: "direct"}}},
			{Type: "network.connect", Operation: "connect", Target: "AF_INET:127.0.0.1:80", Outcome: "success", Count: 1, SourceCall: "connect", Runtime: []RuntimeContext{{Process: child, Parent: parent, Attribution: "direct"}}},
		}
	}
	left := BuildObservationSequences(build("101", "102"))
	right := BuildObservationSequences(build("901", "902"))
	if len(left) != 1 || len(right) != 1 || left[0].ID != right[0].ID {
		t.Fatalf("runtime PID changes altered observed sequence identity: %#v %#v", left, right)
	}
	if len(left[0].CanaryIDs) != 1 || left[0].CanaryIDs[0] != "canary:ssh-private-key" {
		t.Fatalf("sequence lost canary context: %#v", left[0])
	}
	reordered := build("101", "102")
	reordered[1], reordered[2] = reordered[2], reordered[1]
	changed := BuildObservationSequences(reordered)
	if len(changed) != 1 || changed[0].ID == left[0].ID {
		t.Fatalf("observed order did not affect sequence identity: %#v %#v", left, changed)
	}
}
