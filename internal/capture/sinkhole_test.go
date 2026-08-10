package capture

import (
	"context"
	"strings"
	"testing"
)

func TestSinkholeArgumentsHaveNoRouteOrHostMaterial(t *testing.T) {
	t.Parallel()
	canaries := deterministicCanaries(t)
	arguments, err := buildSinkholeArgs("behaviorlock-sinkhole-test", testRunnerImageID, canaries)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(arguments, " ")
	for _, required := range []string{"--network none", "--read-only", "--cap-drop ALL", "--cap-add NET_BIND_SERVICE", "no-new-privileges:true", "BEHAVIORLOCK_SINKHOLE_CANARIES="} {
		if !strings.Contains(joined, required) {
			t.Fatalf("sinkhole arguments are missing %q: %q", required, arguments)
		}
	}
	for _, forbidden := range []string{"--privileged", "--network host", "/var/run/docker.sock", canaries[0].Value} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("sinkhole arguments expose forbidden value %q: %q", forbidden, arguments)
		}
	}
}

func TestSinkholeAuditRetainsCountsAndCanaryIDsWithoutPayloads(t *testing.T) {
	t.Parallel()
	canaries := deterministicCanaries(t)
	runner := &DockerRunner{dockerPath: "docker"}
	runner.run = func(_ context.Context, arguments []string, _, _ int64) (commandResult, error) {
		if strings.Join(arguments, " ") != "logs behaviorlock-sinkhole-test" {
			t.Fatalf("unexpected Docker arguments: %q", arguments)
		}
		return commandResult{Stdout: []byte("BEHAVIORLOCK_SINKHOLE_READY_V1 inert-sinkhole-v1\n" +
			"BEHAVIORLOCK_SINKHOLE_V1 {\"kind\":\"dns\",\"canaryIds\":[]}\n" +
			"BEHAVIORLOCK_SINKHOLE_V1 {\"kind\":\"http\",\"canaryIds\":[\"" + canaries[0].Descriptor.ID + "\"]}\n")}, nil
	}
	info, err := runner.readSinkholeAudit("behaviorlock-sinkhole-test", canaries)
	if err != nil {
		t.Fatal(err)
	}
	if info.DNSRequests != 1 || info.HTTPRequests != 1 || info.TCPConnections != 1 || len(info.CanaryIDs) != 1 {
		t.Fatalf("unexpected sinkhole audit: %#v", info)
	}
}

func TestSinkholeAuditRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	runner := &DockerRunner{dockerPath: "docker"}
	runner.run = func(_ context.Context, _ []string, _, _ int64) (commandResult, error) {
		return commandResult{Stdout: []byte("BEHAVIORLOCK_SINKHOLE_READY_V1 inert-sinkhole-v1\n" +
			"BEHAVIORLOCK_SINKHOLE_V1 {\"kind\":\"dns\",\"canaryIds\":[]} {}\n")}, nil
	}
	if _, err := runner.readSinkholeAudit("behaviorlock-sinkhole-test", deterministicCanaries(t)); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("trailing sinkhole JSON was not rejected: %v", err)
	}
}
