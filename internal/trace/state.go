package trace

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/kiranmagic7/behaviorlock/internal/model"
)

const (
	maxTrackedProcesses   = 4096
	maxTrackedDescriptors = 16_384
)

var (
	bracketProcessPattern = regexp.MustCompile(`^\[pid\s+([0-9]+)\]\s+`)
	plainProcessPattern   = regexp.MustCompile(`^([0-9]+)\s+`)
	timestampPattern      = regexp.MustCompile(`^[0-9]+\.[0-9]+\s+`)
	resumedPattern        = regexp.MustCompile(`^<\.\.\.\s+([a-zA-Z0-9_]+)\s+resumed>(.*)$`)
	cloneFlagsPattern     = regexp.MustCompile(`flags=([^,}]+)`)
	leadingIntegerPattern = regexp.MustCompile(`^-?[0-9]+`)
)

type descriptorInfo struct {
	target      string
	kind        string
	closeOnExec bool
}

type pendingSyscall struct {
	call     string
	prefix   string
	evidence model.EvidenceRef
}

type parserState struct {
	descriptors     map[string]map[int]descriptorInfo
	parents         map[string]string
	pending         map[string]pendingSyscall
	processes       map[string]struct{}
	descriptorCount int
}

func newParserState() *parserState {
	return &parserState{
		descriptors: make(map[string]map[int]descriptorInfo),
		parents:     make(map[string]string),
		pending:     make(map[string]pendingSyscall),
		processes:   make(map[string]struct{}),
	}
}

func (state *parserState) consume(line string, evidence model.EvidenceRef) (model.Behavior, bool, error) {
	process, syscallLine, err := splitRuntimePrefix(line)
	if err != nil {
		return model.Behavior{}, false, err
	}
	if syscallLine == "" {
		return model.Behavior{}, false, nil
	}
	if strings.HasPrefix(syscallLine, "+++") {
		state.releaseProcess(process)
		return model.Behavior{}, false, nil
	}
	if strings.HasPrefix(syscallLine, "---") {
		return model.Behavior{}, false, nil
	}
	if err := state.observeProcess(process); err != nil {
		return model.Behavior{}, false, err
	}

	if unfinished := strings.Index(syscallLine, " <unfinished ...>"); unfinished >= 0 {
		call, ok := syscallName(syscallLine)
		if !ok {
			return model.Behavior{}, false, nil
		}
		if _, exists := state.pending[process]; exists {
			return model.Behavior{}, false, errors.New("process has multiple unfinished syscalls")
		}
		if len(state.pending) >= maxTrackedProcesses {
			return model.Behavior{}, false, errors.New("unfinished syscall state exceeds its bound")
		}
		state.pending[process] = pendingSyscall{call: call, prefix: syscallLine[:unfinished], evidence: evidence}
		return model.Behavior{}, true, nil
	}

	evidenceRefs := []model.EvidenceRef{evidence}
	if resumed := resumedPattern.FindStringSubmatch(syscallLine); len(resumed) == 3 {
		pending, exists := state.pending[process]
		if !exists || pending.call != resumed[1] {
			return model.Behavior{}, false, errors.New("resumed syscall has no matching unfinished call")
		}
		delete(state.pending, process)
		syscallLine = pending.prefix + resumed[2]
		evidenceRefs = []model.EvidenceRef{pending.evidence, evidence}
	} else if _, exists := state.pending[process]; exists {
		return model.Behavior{}, false, errors.New("process issued a syscall before its unfinished call resumed")
	}

	return state.parseSyscall(process, syscallLine, evidenceRefs)
}

func (state *parserState) finish() error {
	if len(state.pending) != 0 {
		return errors.New("trace ended with an unfinished syscall")
	}
	return nil
}

func (state *parserState) parseSyscall(process, line string, evidence []model.EvidenceRef) (model.Behavior, bool, error) {
	call, ok := syscallName(line)
	if !ok {
		return model.Behavior{}, false, nil
	}
	resultPart := syscallResult(line)
	outcome, errno := classifyResult(resultPart)
	arguments := splitSyscallArguments(line)
	resultNumber, hasResultNumber := numericResult(resultPart)

	switch call {
	case "execve", "execveat":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false, nil
		}
		behaviorType := "process.exec"
		target := normalizePath(quoted[0])
		attribution := "direct"
		descriptor := -1
		if call == "execveat" && quoted[0] == "" && strings.Contains(line, "AT_EMPTY_PATH") {
			descriptor, _ = integerArgument(arguments, 0)
			if info, exists := state.descriptor(process, descriptor); exists {
				target = info.target
				attribution = "descriptor"
			} else {
				target = "fd:unknown"
				attribution = "unknown"
			}
			behaviorType = "process.fileless_exec"
		}
		visibleArguments := quoted[1:]
		if len(visibleArguments) > 32 {
			visibleArguments = visibleArguments[:32]
		}
		behavior := model.Behavior{
			Type: behaviorType, Operation: "exec", Target: target,
			Arguments: sanitizeValues(visibleArguments), Outcome: outcome, Errno: errno,
			Count: 1, Evidence: evidence, SourceCall: call,
		}
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, descriptor, attribution)}
		if outcome == "success" {
			state.closeExecDescriptors(process)
		}
		return behavior, true, nil

	case "open", "openat", "openat2", "creat":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false, nil
		}
		path := normalizePath(quoted[0])
		operation := "read"
		behaviorType := "filesystem.read"
		if strings.Contains(line, "O_WRONLY") || strings.Contains(line, "O_RDWR") ||
			strings.Contains(line, "O_CREAT") || strings.Contains(line, "O_TRUNC") || strings.Contains(line, "O_APPEND") {
			operation = "write"
			behaviorType = "filesystem.write"
		}
		if outcome == "success" && hasResultNumber && resultNumber >= 0 {
			if err := state.setDescriptor(process, resultNumber, descriptorInfo{
				target: path, kind: "file", closeOnExec: strings.Contains(line, "O_CLOEXEC"),
			}); err != nil {
				return model.Behavior{}, false, err
			}
		}
		behavior := fileBehavior(behaviorType, operation, path, call, outcome, errno, evidence...)
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, resultNumber, "direct")}
		return behavior, true, nil

	case "access", "faccessat", "faccessat2", "stat", "lstat", "newfstatat", "readlink", "readlinkat":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false, nil
		}
		behavior := fileBehavior("filesystem.read", "inspect", normalizePath(quoted[0]), call, outcome, errno, evidence...)
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, -1, "direct")}
		return behavior, true, nil

	case "unlink", "unlinkat", "rmdir":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false, nil
		}
		behavior := fileBehavior("filesystem.delete", "delete", normalizePath(quoted[0]), call, outcome, errno, evidence...)
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, -1, "direct")}
		return behavior, true, nil

	case "mkdir", "mkdirat", "mknod", "mknodat", "symlink", "symlinkat", "link", "linkat":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false, nil
		}
		behavior := fileBehavior("filesystem.create", "create", normalizePath(quoted[len(quoted)-1]), call, outcome, errno, evidence...)
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, -1, "direct")}
		return behavior, true, nil

	case "rename", "renameat", "renameat2":
		quoted := extractQuoted(line)
		if len(quoted) < 2 {
			return model.Behavior{}, false, nil
		}
		target := normalizePath(quoted[len(quoted)-2]) + " -> " + normalizePath(quoted[len(quoted)-1])
		behavior := fileBehavior("filesystem.rename", "rename", target, call, outcome, errno, evidence...)
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, -1, "direct")}
		return behavior, true, nil

	case "chmod", "fchmodat", "chown", "lchown", "fchownat":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false, nil
		}
		behavior := fileBehavior("filesystem.permission", "permission", normalizePath(quoted[0]), call, outcome, errno, evidence...)
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, -1, "direct")}
		return behavior, true, nil

	case "truncate":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false, nil
		}
		behavior := fileBehavior("filesystem.truncate", "truncate", normalizePath(quoted[0]), call, outcome, errno, evidence...)
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, -1, "direct")}
		return behavior, true, nil

	case "ftruncate":
		fd, valid := integerArgument(arguments, 0)
		if !valid {
			return model.Behavior{}, false, nil
		}
		target, attribution := state.descriptorTarget(process, fd)
		behavior := fileBehavior("filesystem.descriptor_write", "truncate", target, call, outcome, errno, evidence...)
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, fd, attribution)}
		return behavior, true, nil

	case "mmap", "mmap2":
		if len(arguments) < 6 || !strings.Contains(arguments[2], "PROT_WRITE") || !strings.Contains(arguments[3], "MAP_SHARED") {
			return model.Behavior{}, true, nil
		}
		fd, valid := integerArgument(arguments, 4)
		if !valid || fd < 0 {
			return model.Behavior{}, true, nil
		}
		target, attribution := state.descriptorTarget(process, fd)
		behavior := fileBehavior("filesystem.descriptor_write", "mmap-write", target, call, outcome, errno, evidence...)
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, fd, attribution)}
		return behavior, true, nil

	case "getdents", "getdents64":
		fd, valid := integerArgument(arguments, 0)
		if !valid {
			return model.Behavior{}, false, nil
		}
		target, attribution := state.descriptorTarget(process, fd)
		behavior := fileBehavior("filesystem.enumerate", "enumerate", target, call, outcome, errno, evidence...)
		behavior.Runtime = []model.RuntimeContext{state.runtimeContext(process, fd, attribution)}
		return behavior, true, nil

	case "socket":
		target := "socket:unknown"
		if len(arguments) >= 3 {
			target = sanitize(strings.Join([]string{strings.TrimSpace(arguments[0]), strings.TrimSpace(arguments[1]), strings.TrimSpace(arguments[2])}, ":"))
		}
		fd := -1
		if outcome == "success" && hasResultNumber && resultNumber >= 0 {
			fd = resultNumber
			if err := state.setDescriptor(process, fd, descriptorInfo{
				target: target, kind: "socket", closeOnExec: strings.Contains(line, "SOCK_CLOEXEC"),
			}); err != nil {
				return model.Behavior{}, false, err
			}
		}
		behavior := state.behavior(process, fd, "direct", "network.socket", "socket", target, call, outcome, errno, evidence)
		return behavior, true, nil

	case "connect":
		fd, valid := integerArgument(arguments, 0)
		if !valid {
			return model.Behavior{}, false, nil
		}
		target, _ := networkEndpoint(line)
		if outcome == "success" {
			if err := state.updateDescriptorTarget(process, fd, target, "socket"); err != nil {
				return model.Behavior{}, false, err
			}
		}
		behavior := state.behavior(process, fd, "direct", "network.connect", "connect", target, call, outcome, errno, evidence)
		return behavior, true, nil

	case "sendto", "sendmsg", "sendmmsg":
		fd, valid := integerArgument(arguments, 0)
		if !valid {
			return model.Behavior{}, false, nil
		}
		target, port := networkEndpoint(line)
		attribution := "direct"
		if target == "endpoint:unknown" {
			target, attribution = state.descriptorTarget(process, fd)
			port = endpointPort(target)
		}
		behaviorType := "network.send"
		operation := "send"
		if port == "53" {
			behaviorType = "network.dns"
			operation = "query"
		}
		behavior := state.behavior(process, fd, attribution, behaviorType, operation, target, call, outcome, errno, evidence)
		return behavior, true, nil

	case "bind":
		fd, valid := integerArgument(arguments, 0)
		if !valid {
			return model.Behavior{}, false, nil
		}
		target, _ := networkEndpoint(line)
		if outcome == "success" {
			if err := state.updateDescriptorTarget(process, fd, target, "socket"); err != nil {
				return model.Behavior{}, false, err
			}
		}
		behavior := state.behavior(process, fd, "direct", "network.bind", "bind", target, call, outcome, errno, evidence)
		return behavior, true, nil

	case "listen":
		fd, valid := integerArgument(arguments, 0)
		if !valid {
			return model.Behavior{}, false, nil
		}
		target, attribution := state.descriptorTarget(process, fd)
		behavior := state.behavior(process, fd, attribution, "network.listen", "listen", target, call, outcome, errno, evidence)
		return behavior, true, nil

	case "accept", "accept4":
		listeningFD, valid := integerArgument(arguments, 0)
		if !valid {
			return model.Behavior{}, false, nil
		}
		target, _ := networkEndpoint(line)
		if target == "endpoint:unknown" {
			target, _ = state.descriptorTarget(process, listeningFD)
		}
		acceptedFD := -1
		if outcome == "success" && hasResultNumber && resultNumber >= 0 {
			acceptedFD = resultNumber
			if err := state.setDescriptor(process, acceptedFD, descriptorInfo{
				target: target, kind: "socket", closeOnExec: call == "accept4" && strings.Contains(line, "SOCK_CLOEXEC"),
			}); err != nil {
				return model.Behavior{}, false, err
			}
		}
		behavior := state.behavior(process, acceptedFD, "direct", "network.accept", "accept", target, call, outcome, errno, evidence)
		return behavior, true, nil

	case "dup", "dup2", "dup3":
		oldFD, valid := integerArgument(arguments, 0)
		if !valid || outcome != "success" || !hasResultNumber || resultNumber < 0 {
			return model.Behavior{}, true, nil
		}
		closeOnExec := call == "dup3" && len(arguments) > 2 && strings.Contains(arguments[2], "O_CLOEXEC")
		if err := state.copyDescriptor(process, oldFD, resultNumber, closeOnExec); err != nil {
			return model.Behavior{}, false, err
		}
		return model.Behavior{}, true, nil

	case "fcntl", "fcntl64":
		oldFD, valid := integerArgument(arguments, 0)
		if !valid {
			return model.Behavior{}, false, nil
		}
		if len(arguments) > 1 && strings.Contains(arguments[1], "F_SETFD") {
			if outcome == "success" {
				state.setDescriptorCloseOnExec(process, oldFD, len(arguments) > 2 && strings.Contains(arguments[2], "FD_CLOEXEC"))
			}
			return model.Behavior{}, true, nil
		}
		if len(arguments) <= 1 || !strings.Contains(arguments[1], "F_DUPFD") || outcome != "success" || !hasResultNumber || resultNumber < 0 {
			return model.Behavior{}, true, nil
		}
		if err := state.copyDescriptor(process, oldFD, resultNumber, strings.Contains(arguments[1], "F_DUPFD_CLOEXEC")); err != nil {
			return model.Behavior{}, false, err
		}
		return model.Behavior{}, true, nil

	case "close":
		fd, valid := integerArgument(arguments, 0)
		if valid && outcome == "success" {
			state.closeDescriptor(process, fd)
		}
		return model.Behavior{}, true, nil

	case "memfd_create":
		quoted := extractQuoted(line)
		target := "memfd:unnamed"
		if len(quoted) > 0 && quoted[0] != "" {
			target = "memfd:" + quoted[0]
		}
		fd := -1
		if outcome == "success" && hasResultNumber && resultNumber >= 0 {
			fd = resultNumber
			if err := state.setDescriptor(process, fd, descriptorInfo{
				target: target, kind: "memfd", closeOnExec: strings.Contains(line, "MFD_CLOEXEC"),
			}); err != nil {
				return model.Behavior{}, false, err
			}
		}
		behavior := state.behavior(process, fd, "direct", "process.memfd", "create", target, call, outcome, errno, evidence)
		return behavior, true, nil

	case "clone", "clone3", "fork", "vfork":
		if outcome == "success" && hasResultNumber && resultNumber == 0 {
			return model.Behavior{}, true, nil
		}
		if outcome == "success" && hasResultNumber && resultNumber > 0 {
			child := strconv.Itoa(resultNumber)
			if err := state.registerChild(process, child); err != nil {
				return model.Behavior{}, false, err
			}
		}
		visibleArguments := []string{}
		if flags := firstMatch(cloneFlagsPattern, line); flags != "" {
			visibleArguments = []string{flags}
		}
		behavior := state.behavior(process, -1, "direct", "process.create", call, "child-process", call, outcome, errno, evidence)
		behavior.Arguments = visibleArguments
		return behavior, true, nil

	case "ptrace":
		target := "request:unknown"
		if len(arguments) > 0 {
			target = sanitize(strings.TrimSpace(arguments[0]))
		}
		behavior := state.behavior(process, -1, "direct", "process.ptrace", "inspect", target, call, outcome, errno, evidence)
		return behavior, true, nil

	case "clock_gettime", "clock_getres", "gettimeofday", "time", "nanosleep", "clock_nanosleep":
		operation := "read"
		target := "wall-clock"
		if strings.Contains(call, "nanosleep") {
			operation = "sleep"
			target = "requested-delay"
		} else if len(arguments) > 0 && strings.HasPrefix(call, "clock_") {
			target = sanitize(strings.TrimSpace(arguments[0]))
		}
		behavior := state.behavior(process, -1, "direct", "environment.timing", operation, target, call, outcome, errno, evidence)
		return behavior, true, nil

	default:
		return model.Behavior{}, false, nil
	}
}

func (state *parserState) behavior(process string, descriptor int, attribution, kind, operation, target, call, outcome, errno string, evidence []model.EvidenceRef) model.Behavior {
	return model.Behavior{
		Type: kind, Operation: operation, Target: sanitize(target), Outcome: outcome, Errno: errno,
		Count: 1, Evidence: evidence, Runtime: []model.RuntimeContext{state.runtimeContext(process, descriptor, attribution)}, SourceCall: call,
	}
}

func (state *parserState) runtimeContext(process string, descriptor int, attribution string) model.RuntimeContext {
	context := model.RuntimeContext{Process: process, Parent: state.parents[process], Attribution: attribution}
	if descriptor >= 0 {
		context.Descriptor = strconv.Itoa(descriptor)
	}
	return context
}

func (state *parserState) observeProcess(process string) error {
	if process == "root" {
		return nil
	}
	if _, exists := state.processes[process]; exists {
		return nil
	}
	if len(state.processes) >= maxTrackedProcesses {
		return errors.New("process attribution exceeds its bound")
	}
	state.processes[process] = struct{}{}
	return nil
}

func (state *parserState) registerChild(parent, child string) error {
	if err := state.observeProcess(child); err != nil {
		return err
	}
	state.parents[child] = parent
	parentDescriptors := state.descriptors[parent]
	if len(parentDescriptors) == 0 {
		state.releaseDescriptors(child)
		return nil
	}
	existing := len(state.descriptors[child])
	if state.descriptorCount-existing+len(parentDescriptors) > maxTrackedDescriptors {
		return errors.New("descriptor attribution exceeds its bound")
	}
	childDescriptors := make(map[int]descriptorInfo, len(parentDescriptors))
	for fd, info := range parentDescriptors {
		childDescriptors[fd] = info
	}
	state.descriptors[child] = childDescriptors
	state.descriptorCount += len(childDescriptors) - existing
	return nil
}

func (state *parserState) setDescriptor(process string, descriptor int, info descriptorInfo) error {
	if descriptor < 0 || descriptor > 1_000_000 {
		return errors.New("descriptor is outside its bound")
	}
	table := state.descriptors[process]
	if table == nil {
		table = make(map[int]descriptorInfo)
		state.descriptors[process] = table
	}
	if _, exists := table[descriptor]; !exists {
		if state.descriptorCount >= maxTrackedDescriptors {
			return errors.New("descriptor attribution exceeds its bound")
		}
		state.descriptorCount++
	}
	table[descriptor] = info
	return nil
}

func (state *parserState) copyDescriptor(process string, source, destination int, closeOnExec bool) error {
	info, exists := state.descriptor(process, source)
	if !exists {
		return state.setDescriptor(process, destination, descriptorInfo{target: "fd:unknown", kind: "unknown", closeOnExec: closeOnExec})
	}
	info.closeOnExec = closeOnExec
	return state.setDescriptor(process, destination, info)
}

func (state *parserState) updateDescriptorTarget(process string, descriptor int, target, kind string) error {
	info, exists := state.descriptor(process, descriptor)
	if !exists {
		return state.setDescriptor(process, descriptor, descriptorInfo{target: target, kind: kind})
	}
	info.target = target
	info.kind = kind
	return state.setDescriptor(process, descriptor, info)
}

func (state *parserState) setDescriptorCloseOnExec(process string, descriptor int, closeOnExec bool) {
	info, exists := state.descriptor(process, descriptor)
	if !exists {
		return
	}
	info.closeOnExec = closeOnExec
	state.descriptors[process][descriptor] = info
}

func (state *parserState) closeExecDescriptors(process string) {
	table := state.descriptors[process]
	for descriptor, info := range table {
		if info.closeOnExec {
			delete(table, descriptor)
			state.descriptorCount--
		}
	}
}

func (state *parserState) closeDescriptor(process string, descriptor int) {
	table := state.descriptors[process]
	if _, exists := table[descriptor]; exists {
		delete(table, descriptor)
		state.descriptorCount--
	}
}

func (state *parserState) releaseDescriptors(process string) {
	if table, exists := state.descriptors[process]; exists {
		state.descriptorCount -= len(table)
		delete(state.descriptors, process)
	}
}

func (state *parserState) releaseProcess(process string) {
	if process == "root" {
		return
	}
	state.releaseDescriptors(process)
	delete(state.parents, process)
	delete(state.processes, process)
}

func (state *parserState) descriptor(process string, descriptor int) (descriptorInfo, bool) {
	info, exists := state.descriptors[process][descriptor]
	return info, exists
}

func (state *parserState) descriptorTarget(process string, descriptor int) (string, string) {
	if info, exists := state.descriptor(process, descriptor); exists && info.target != "" {
		return info.target, "descriptor"
	}
	return "fd:unknown", "unknown"
}

func splitRuntimePrefix(line string) (string, string, error) {
	process := "root"
	if match := bracketProcessPattern.FindStringSubmatch(line); len(match) == 2 {
		process = match[1]
		line = line[len(match[0]):]
	} else if match := plainProcessPattern.FindStringSubmatch(line); len(match) == 2 {
		process = match[1]
		line = line[len(match[0]):]
	}
	if process != "root" {
		parsed, err := strconv.ParseUint(process, 10, 32)
		if err != nil || parsed == 0 {
			return "", "", errors.New("runtime process identifier is invalid")
		}
	}
	line = timestampPattern.ReplaceAllString(line, "")
	return process, strings.TrimSpace(line), nil
}

func syscallName(line string) (string, bool) {
	open := strings.IndexByte(line, '(')
	if open <= 0 {
		return "", false
	}
	call := strings.TrimSpace(line[:open])
	for _, character := range call {
		if !(character == '_' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return "", false
		}
	}
	return call, true
}

func splitSyscallArguments(line string) []string {
	open := strings.IndexByte(line, '(')
	close, _, validResult := syscallResultBoundary(line)
	if open < 0 || !validResult || close <= open {
		return nil
	}
	input := line[open+1 : close]
	result := make([]string, 0, 8)
	start := 0
	depth := 0
	quoted := false
	escaped := false
	for index, character := range input {
		if quoted {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
			} else if character == '"' {
				quoted = false
			}
			continue
		}
		switch character {
		case '"':
			quoted = true
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				result = append(result, strings.TrimSpace(input[start:index]))
				start = index + 1
			}
		}
	}
	result = append(result, strings.TrimSpace(input[start:]))
	return result
}

func integerArgument(arguments []string, index int) (int, bool) {
	if index < 0 || index >= len(arguments) {
		return 0, false
	}
	value := strings.TrimSpace(arguments[index])
	value = leadingIntegerPattern.FindString(value)
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil
}

func numericResult(value string) (int, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, false
	}
	parsed, err := strconv.Atoi(leadingIntegerPattern.FindString(fields[0]))
	return parsed, err == nil
}

func networkEndpoint(line string) (string, string) {
	family := firstMatch(familyPattern, line)
	address := firstMatch(ipv4Pattern, line)
	if address == "" {
		address = firstMatch(ipv6Pattern, line)
	}
	if family == "AF_UNIX" {
		quoted := extractQuoted(line)
		if len(quoted) > 0 {
			address = normalizePath(quoted[len(quoted)-1])
		}
	}
	port := firstMatch(portPattern, line)
	if family == "" && address == "" && port == "" {
		return "endpoint:unknown", ""
	}
	if family == "" {
		family = "AF_UNKNOWN"
	}
	if address == "" {
		address = "unknown"
	}
	target := family + ":" + address
	if port != "" {
		target += ":" + port
	}
	return sanitize(target), port
}

func endpointPort(target string) string {
	parts := strings.Split(target, ":")
	if len(parts) < 3 {
		return ""
	}
	port := parts[len(parts)-1]
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return ""
	}
	return port
}
