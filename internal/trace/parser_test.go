package trace

import (
	"strconv"
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

func TestParseKeepsEscapedFakeSyscallInsideOneBehavior(t *testing.T) {
	t.Parallel()
	input := `openat(AT_FDCWD, "/work/legitimate\nexecve(\"/bin/sh\", [\"sh\"], 0x0) = 0::error::workflow-marker", O_RDONLY) = 3`
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Behaviors) != 1 {
		t.Fatalf("escaped fake syscall produced %d behaviors, want 1", len(result.Behaviors))
	}
	target := result.Behaviors[0].Target
	if strings.ContainsAny(target, "\r\n\x1b\x7f") {
		t.Fatalf("target retained a terminal control character: %q", target)
	}
	if !strings.Contains(target, `\u000aexecve("/bin/sh"`) || !strings.Contains(target, "::error::workflow-marker") {
		t.Fatalf("escaped fake syscall was not retained as inert text: %q", target)
	}
}

func TestSanitizeEscapesTerminalControlCharacters(t *testing.T) {
	t.Parallel()
	input := "\x1b[31m::error::workflow-marker\r\n\x7f"
	got := sanitize(input)
	want := `\u001b[31m::error::workflow-marker\u000d\u000a\u007f`
	if got != want {
		t.Fatalf("sanitize() = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "\r\n\x1b\x7f") {
		t.Fatalf("sanitize retained a terminal control character: %q", got)
	}
}

func TestParseReassemblesMatchingResumedSyscall(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`[pid 123] connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16 <unfinished ...>`,
		`[pid 123] <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Behaviors) != 1 || result.Behaviors[0].Type != "network.connect" || len(result.Behaviors[0].Evidence) != 2 {
		t.Fatalf("unexpected resumed behavior: %#v", result.Behaviors)
	}
}

func TestParseRejectsMismatchedResumedSyscall(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`[pid 123] connect(3, {sa_family=AF_INET}, 16 <unfinished ...>`,
		`[pid 123] <... read resumed>"x", 1) = 1`,
	}, "\n")
	if _, err := Parse(strings.NewReader(input)); err == nil {
		t.Fatal("mismatched resumed syscall unexpectedly succeeded")
	}
}

func TestParseObservesUDPAndListenerOperations(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`100 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3<socket:[1]>`,
		`100 sendto(3<socket:[1]>, "query", 5, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH (Network is unreachable)`,
		`100 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4<socket:[2]>`,
		`100 bind(4<socket:[2]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0`,
		`100 listen(4<socket:[2]>, 128) = 0`,
		`100 accept4(4<socket:[2]>, {sa_family=AF_INET, sin_port=htons(50000), sin_addr=inet_addr("127.0.0.1")}, [16], SOCK_CLOEXEC) = 5<socket:[3]>`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	wantTypes := []string{"network.socket", "network.dns", "network.socket", "network.bind", "network.listen", "network.accept"}
	if len(result.Behaviors) != len(wantTypes) {
		t.Fatalf("got %d behaviors, want %d: %#v", len(result.Behaviors), len(wantTypes), result.Behaviors)
	}
	for index, want := range wantTypes {
		if result.Behaviors[index].Type != want {
			t.Fatalf("behavior %d type = %q, want %q", index, result.Behaviors[index].Type, want)
		}
	}
	if result.Behaviors[1].Target != "AF_INET:8.8.8.8:53" || result.Behaviors[4].Target != "AF_INET:0.0.0.0:8080" {
		t.Fatalf("network attribution failed: %#v", result.Behaviors)
	}
}

func TestParseAcceptsStraceAlignedResultColumns(t *testing.T) {
	t.Parallel()
	input := `[pid 33] 1786329664.837566 listen(19, 511)       = 0`
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Behaviors) != 1 || result.Behaviors[0].Type != "network.listen" || result.Behaviors[0].Outcome != "success" {
		t.Fatalf("aligned strace result was not parsed: %#v", result.Behaviors)
	}
}

func TestParseDoesNotAttributeMalformedNetworkDescriptorsToZero(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`500 connect(not_a_descriptor, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = 0`,
		`500 bind(not_a_descriptor, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0`,
		`500 listen(0, 8) = 0`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Behaviors) != 1 {
		t.Fatalf("behaviors = %#v", result.Behaviors)
	}
	behavior := result.Behaviors[0]
	if behavior.Type != "network.listen" || behavior.Target != "fd:unknown" ||
		len(behavior.Runtime) != 1 || behavior.Runtime[0].Descriptor != "0" || behavior.Runtime[0].Attribution != "unknown" {
		t.Fatalf("malformed network descriptor polluted descriptor zero: %#v", behavior)
	}
}

func TestParseAttributesDescriptorMutationAndEnumeration(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`200 openat(AT_FDCWD, "/work/data.bin", O_RDWR|O_CREAT, 0600) = 3</work/data.bin>`,
		`200 dup(3</work/data.bin>) = 8</work/data.bin>`,
		`200 ftruncate(8</work/data.bin>, 0) = 0`,
		`200 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, 3</work/data.bin>, 0) = 0x7f00`,
		`200 close(8</work/data.bin>) = 0`,
		`200 openat(AT_FDCWD, "/work/list", O_RDONLY|O_DIRECTORY) = 8</work/list>`,
		`200 getdents64(8</work/list>, 0x7f00, 32768) = 48`,
		`200 truncate("/work/direct.bin", 10) = 0`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"ftruncate":  "$WORK/data.bin",
		"mmap":       "$WORK/data.bin",
		"getdents64": "$WORK/list",
		"truncate":   "$WORK/direct.bin",
	}
	for _, behavior := range result.Behaviors {
		if target, exists := want[behavior.SourceCall]; exists {
			if behavior.Target != target {
				t.Fatalf("%s target = %q, want %q", behavior.SourceCall, behavior.Target, target)
			}
			delete(want, behavior.SourceCall)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing descriptor observations: %#v", want)
	}
}

func TestParseKeepsDescriptorTablesSeparateAndClearsClosedDescriptors(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`[pid 300] openat(AT_FDCWD, "/work/a", O_RDWR) = 3</work/a>`,
		`[pid 301] openat(AT_FDCWD, "/work/b", O_RDWR) = 3</work/b>`,
		`[pid 300] ftruncate(3</work/a>, 0) = 0`,
		`[pid 301] ftruncate(3</work/b>, 0) = 0`,
		`[pid 300] close(3</work/a>) = 0`,
		`[pid 300] ftruncate(3, 0) = -1 EBADF (Bad file descriptor)`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{}
	for _, behavior := range result.Behaviors {
		if behavior.SourceCall == "ftruncate" {
			targets = append(targets, behavior.Target)
		}
	}
	want := []string{"$WORK/a", "$WORK/b", "fd:unknown"}
	if len(targets) != len(want) {
		t.Fatalf("targets = %#v", targets)
	}
	for index := range want {
		if targets[index] != want[index] {
			t.Fatalf("target %d = %q, want %q", index, targets[index], want[index])
		}
	}
}

func TestParseCopiesDescriptorAttributionIntoChildProcess(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`500 openat(AT_FDCWD, "/work/inherited", O_RDWR) = 3</work/inherited>`,
		`500 clone(child_stack=NULL, flags=SIGCHLD) = 501`,
		`[pid 501] ftruncate(3</work/inherited>, 0) = 0`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	behavior := result.Behaviors[len(result.Behaviors)-1]
	if behavior.Type != "filesystem.descriptor_write" || behavior.Target != "$WORK/inherited" ||
		len(behavior.Runtime) != 1 || behavior.Runtime[0].Parent != "500" {
		t.Fatalf("child descriptor attribution was not inherited: %#v", behavior)
	}
}

func TestParseClearsCloseOnExecDescriptorsAfterSuccessfulExec(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`700 openat(AT_FDCWD, "/work/closed-on-exec", O_RDWR|O_CLOEXEC) = 3</work/closed-on-exec>`,
		`700 openat(AT_FDCWD, "/work/retained", O_RDWR) = 4</work/retained>`,
		`700 execve("/usr/bin/node", ["node"], 0x0) = 0`,
		`700 ftruncate(3, 0) = -1 EBADF (Bad file descriptor)`,
		`700 ftruncate(4</work/retained>, 0) = 0`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{}
	for _, behavior := range result.Behaviors {
		if behavior.SourceCall == "ftruncate" {
			targets = append(targets, behavior.Target)
		}
	}
	want := []string{"fd:unknown", "$WORK/retained"}
	if len(targets) != len(want) || targets[0] != want[0] || targets[1] != want[1] {
		t.Fatalf("close-on-exec attribution = %#v, want %#v", targets, want)
	}
}

func TestParseClearsDescriptorsWhenAnObservedProcessExits(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`800 openat(AT_FDCWD, "/work/old-process", O_RDWR) = 3</work/old-process>`,
		`800 +++ exited with 0 +++`,
		`800 ftruncate(3, 0) = -1 EBADF (Bad file descriptor)`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	behavior := result.Behaviors[len(result.Behaviors)-1]
	if behavior.Type != "filesystem.descriptor_write" || behavior.Target != "fd:unknown" {
		t.Fatalf("exited process descriptor state leaked into a reused pid: %#v", behavior)
	}
}

func TestParseRecordsProcessLineageFilelessExecutionPtraceAndTiming(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		`400 clone(child_stack=NULL, flags=SIGCHLD) = 401`,
		`[pid 401] memfd_create("stage", MFD_CLOEXEC) = 4</memfd:stage>`,
		`[pid 401] execveat(4</memfd:stage>, "", ["stage"], 0x0, AT_EMPTY_PATH) = 0`,
		`[pid 401] ptrace(PTRACE_TRACEME, 0, NULL, NULL) = -1 EPERM (Operation not permitted)`,
		`[pid 401] clock_gettime(CLOCK_MONOTONIC, {tv_sec=1, tv_nsec=2}) = 0`,
	}, "\n")
	result, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	wantTypes := []string{"process.create", "process.memfd", "process.fileless_exec", "process.ptrace", "environment.timing"}
	if len(result.Behaviors) != len(wantTypes) {
		t.Fatalf("behaviors = %#v", result.Behaviors)
	}
	for index, want := range wantTypes {
		behavior := result.Behaviors[index]
		if behavior.Type != want {
			t.Fatalf("behavior %d type = %q, want %q", index, behavior.Type, want)
		}
		if index > 0 && (len(behavior.Runtime) != 1 || behavior.Runtime[0].Process != "401" || behavior.Runtime[0].Parent != "400") {
			t.Fatalf("behavior %d lost process lineage: %#v", index, behavior.Runtime)
		}
	}
	if result.Behaviors[2].Target != "memfd:stage" || result.Behaviors[2].Runtime[0].Attribution != "descriptor" {
		t.Fatalf("fileless execution attribution failed: %#v", result.Behaviors[2])
	}
}

func TestParseDoesNotTreatOrdinaryExecveatDotPathAsFileless(t *testing.T) {
	t.Parallel()
	result, err := Parse(strings.NewReader(`600 execveat(AT_FDCWD, ".", ["."], 0x0, 0) = -1 EACCES (Permission denied)`))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Behaviors) != 1 || result.Behaviors[0].Type != "process.exec" || result.Behaviors[0].Target != "." {
		t.Fatalf("ordinary execveat dot path was misclassified: %#v", result.Behaviors)
	}
}

func TestParserStateEnforcesProcessAndDescriptorBounds(t *testing.T) {
	t.Parallel()
	processState := newParserState()
	for identifier := 1; identifier <= maxTrackedProcesses; identifier++ {
		if err := processState.observeProcess(strconv.Itoa(identifier)); err != nil {
			t.Fatalf("process %d was rejected before the bound: %v", identifier, err)
		}
	}
	if err := processState.observeProcess(strconv.Itoa(maxTrackedProcesses + 1)); err == nil {
		t.Fatal("process state exceeded its bound")
	}

	descriptorState := newParserState()
	for descriptor := 0; descriptor < maxTrackedDescriptors; descriptor++ {
		if err := descriptorState.setDescriptor("root", descriptor, descriptorInfo{target: "$WORK/bounded", kind: "file"}); err != nil {
			t.Fatalf("descriptor %d was rejected before the bound: %v", descriptor, err)
		}
	}
	if err := descriptorState.setDescriptor("root", maxTrackedDescriptors, descriptorInfo{target: "$WORK/overflow", kind: "file"}); err == nil {
		t.Fatal("descriptor state exceeded its bound")
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

func TestNormalizePathReplacesNodeCompileCacheNonceOnly(t *testing.T) {
	t.Parallel()
	first := normalizePath("/tmp/node-compile-cache/v22.23.2-x64-9ac5647c-65532/00bf0630.UxGNV0")
	second := normalizePath("/tmp/node-compile-cache/v22.23.2-x64-9ac5647c-65532/00bf0630.0ZWDib")
	want := "/tmp/node-compile-cache/v22.23.2-x64-9ac5647c-65532/00bf0630.$RANDOM"
	if first != want || second != want {
		t.Fatalf("compile-cache nonce was not normalized: first=%q second=%q", first, second)
	}
	lookalike := "/tmp/node-compile-cache/v22.23.2-x64-9ac5647c-65532/not-a-cache-file.UxGNV0"
	if got := normalizePath(lookalike); got != lookalike {
		t.Fatalf("lookalike cache path was rewritten: %q", got)
	}
}

func TestNormalizePathReplacesNPMDebugLogTimestamp(t *testing.T) {
	t.Parallel()
	first := normalizePath("/work/.npm-cache/_logs/2026-08-10T05_19_29_294Z-debug-0.log")
	second := normalizePath("/work/.npm-cache/_logs/2026-08-10T05_19_31_632Z-debug-0.log")
	want := "$WORK/.npm-cache/_logs/$TIMESTAMP-debug-$N.log"
	if first != want || second != want {
		t.Fatalf("npm debug timestamp was not normalized: first=%q second=%q", first, second)
	}
	lookalike := "/work/.npm-cache/_logs/not-a-timestamp-debug-0.log"
	if got := normalizePath(lookalike); got != "$WORK/.npm-cache/_logs/not-a-timestamp-debug-0.log" {
		t.Fatalf("lookalike npm log was rewritten: %q", got)
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
