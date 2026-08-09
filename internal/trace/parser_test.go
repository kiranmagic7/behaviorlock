package trace

import (
	"strings"
	"testing"
)

func TestParseNormalizesObservedBehavior(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`execve("/usr/bin/node", ["node", "/work/index.js"], 0x7ffc) = 0`,
		`openat(AT_FDCWD, "/home/scanner/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = -1 EACCES (Permission denied)`,
		`openat(AT_FDCWD, "/work/output.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3`,
		`connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = -1 ENETUNREACH (Network is unreachable)`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Behaviors) != 4 {
		t.Fatalf("got %d behaviors, want 4", len(result.Behaviors))
	}
	if !result.Behaviors[1].Sensitive || result.Behaviors[1].Outcome != "blocked" {
		t.Fatalf("sensitive read was not classified correctly: %#v", result.Behaviors[1])
	}
	if got := result.Behaviors[1].Target; got != "$HOME/.ssh/id_rsa" {
		t.Fatalf("normalized target = %q", got)
	}
}

func TestParseRejectsUnfinishedTrace(t *testing.T) {
	t.Parallel()
	_, err := Parse(strings.NewReader(`openat(AT_FDCWD, "/tmp/x", O_RDONLY <unfinished ...>`))
	if err == nil {
		t.Fatal("expected unfinished trace to fail")
	}
}

func TestNormalizePathReplacesOnlyRootBoundaries(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`openat(AT_FDCWD, "/work/output.txt", O_WRONLY|O_CREAT, 0600) = 3`,
		`openat(AT_FDCWD, "/workspace/output.txt", O_WRONLY|O_CREAT, 0600) = 3`,
		`openat(AT_FDCWD, "/home/scanner/.npmrc", O_RDONLY) = 3`,
		`openat(AT_FDCWD, "/home/scanner-backup/.npmrc", O_RDONLY) = 3`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"$WORK/output.txt", "/workspace/output.txt", "$HOME/.npmrc", "/home/scanner-backup/.npmrc"}
	for index, target := range want {
		if result.Behaviors[index].Target != target {
			t.Fatalf("target %d = %q, want %q", index, result.Behaviors[index].Target, target)
		}
	}
}

func TestNormalizePathReplacesOnlyProcPIDBoundaries(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`openat(AT_FDCWD, "/proc/1/status", O_RDONLY) = 3`,
		`openat(AT_FDCWD, "/proc/1", O_RDONLY) = 3`,
		`openat(AT_FDCWD, "/proc/1-backup/status", O_RDONLY) = 3`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/proc/$PID/status", "/proc/$PID", "/proc/1-backup/status"}
	for index, target := range want {
		if result.Behaviors[index].Target != target {
			t.Fatalf("target %d = %q, want %q", index, result.Behaviors[index].Target, target)
		}
	}
}

func TestParseObservesEnvironmentFingerprintPaths(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`openat(AT_FDCWD, "/.dockerenv", O_RDONLY|O_CLOEXEC) = 3`,
		`access("/run/.containerenv", F_OK) = -1 ENOENT (No such file or directory)`,
		`stat("/proc/1/cgroup", {st_mode=S_IFREG|0444}) = 0`,
		`openat(AT_FDCWD, "/proc/self/status", O_RDONLY|O_CLOEXEC) = 4`,
		`newfstatat(AT_FDCWD, "/proc/self/mountinfo", {st_mode=S_IFREG|0444}, 0) = 0`,
		`openat(AT_FDCWD, "/proc/cpuinfo", O_RDONLY|O_CLOEXEC) = 5`,
		`lstat("/proc/meminfo", {st_mode=S_IFREG|0444}) = 0`,
		`readlink("/proc/uptime", 0x7ffc, 4095) = -1 EINVAL (Invalid argument)`,
		`openat(AT_FDCWD, "/sys/class/dmi/id/product_name", O_RDONLY|O_CLOEXEC) = 6`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/.dockerenv",
		"/run/.containerenv",
		"/proc/$PID/cgroup",
		"/proc/self/status",
		"/proc/self/mountinfo",
		"/proc/cpuinfo",
		"/proc/meminfo",
		"/proc/uptime",
		"/sys/class/dmi/id/product_name",
	}
	if len(result.Behaviors) != len(want) {
		t.Fatalf("got %d behaviors, want %d", len(result.Behaviors), len(want))
	}
	for index, target := range want {
		behavior := result.Behaviors[index]
		if behavior.Type != "filesystem.read" || behavior.Target != target {
			t.Fatalf("behavior %d = %#v, want filesystem.read %q", index, behavior, target)
		}
	}
}

func TestParseEnvelopeRequiresCompletionMarker(t *testing.T) {
	t.Parallel()
	_, _, _, err := ParseEnvelope([]byte("BEHAVIORLOCK_TRACE_V1\nexecve(\"/bin/true\", [\"true\"], 0x0) = 0\n"))
	if err == nil {
		t.Fatal("expected missing completion marker to fail")
	}
}

func TestParseEnvelopeRejectsEmptyEvidence(t *testing.T) {
	t.Parallel()
	_, _, _, err := ParseEnvelope([]byte("BEHAVIORLOCK_TRACE_V1\nBEHAVIORLOCK_TRACE_END exit=0\n"))
	if err == nil {
		t.Fatal("empty trace envelope unexpectedly succeeded")
	}
}

func TestParseEnvelopeRequiresBothSentinels(t *testing.T) {
	t.Parallel()
	data := []byte("BEHAVIORLOCK_TRACE_V1\nopenat(AT_FDCWD, \"/opt/behaviorlock/sentinel-start\", O_RDONLY) = 3\nBEHAVIORLOCK_TRACE_END exit=0\n")
	if _, _, _, err := ParseEnvelope(data); err == nil {
		t.Fatal("one sentinel unexpectedly succeeded")
	}
}

func TestParseEnvelopeReturnsExitCode(t *testing.T) {
	t.Parallel()
	data := []byte("BEHAVIORLOCK_TRACE_V1\nopenat(AT_FDCWD, \"/opt/behaviorlock/sentinel-start\", O_RDONLY) = 3\nexecve(\"/bin/true\", [\"true\"], 0x0) = 0\nopenat(AT_FDCWD, \"/opt/behaviorlock/sentinel-end\", O_RDONLY) = 3\nBEHAVIORLOCK_TRACE_END exit=7\n")
	result, raw, exitCode, err := ParseEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 7 || len(result.Behaviors) != 3 || len(raw) == 0 {
		t.Fatalf("unexpected envelope result: exit=%d behaviors=%d raw=%d", exitCode, len(result.Behaviors), len(raw))
	}
}
