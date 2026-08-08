package trace

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kiranmagic7/behaviorlock/internal/model"
)

const (
	MaxTraceBytes = 64 << 20
	MaxLineBytes  = 256 << 10
	MaxBehaviors  = 250_000
)

var (
	quotedPattern   = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	pidPattern      = regexp.MustCompile(`^\[pid\s+[0-9]+\]\s+`)
	plainPIDPattern = regexp.MustCompile(`^[0-9]+\s+`)
	procPIDPattern  = regexp.MustCompile(`/proc/[0-9]+`)
	tmpPattern      = regexp.MustCompile(`/tmp/(?:npm-|behaviorlock-)[^/\s",)]+`)
	portPattern     = regexp.MustCompile(`(?:sin6?_port=htons\()([0-9]+)\)`)
	ipv4Pattern     = regexp.MustCompile(`sin_addr=inet_addr\("([^"]+)"\)`)
	ipv6Pattern     = regexp.MustCompile(`inet_pton\(AF_INET6,\s*"([^"]+)"`)
	familyPattern   = regexp.MustCompile(`sa_family=(AF_[A-Z0-9_]+)`)
)

type Stats struct {
	Lines           int
	RecognizedLines int
	IgnoredLines    int
}

type ParseResult struct {
	Behaviors []model.Behavior
	Stats     Stats
}

func Parse(reader io.Reader) (ParseResult, error) {
	limited := &io.LimitedReader{R: reader, N: MaxTraceBytes + 1}
	buffered := bufio.NewReaderSize(limited, 64<<10)
	result := ParseResult{Behaviors: make([]model.Behavior, 0, 256)}
	for {
		line, err := buffered.ReadString('\n')
		if len(line) > MaxLineBytes {
			return ParseResult{}, fmt.Errorf("trace line exceeds %d bytes", MaxLineBytes)
		}
		if len(line) > 0 {
			result.Stats.Lines++
			if !utf8.ValidString(line) {
				return ParseResult{}, fmt.Errorf("trace line %d contains invalid UTF-8", result.Stats.Lines)
			}
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "<unfinished ...>") || strings.Contains(trimmed, "resumed>") {
				return ParseResult{}, fmt.Errorf("trace line %d contains an unfinished syscall", result.Stats.Lines)
			}
			if behavior, ok := parseLine(trimmed, result.Stats.Lines); ok {
				result.Behaviors = append(result.Behaviors, behavior)
				result.Stats.RecognizedLines++
				if len(result.Behaviors) > MaxBehaviors {
					return ParseResult{}, fmt.Errorf("trace exceeds %d recognized behaviors", MaxBehaviors)
				}
			} else if trimmed != "" && !strings.HasPrefix(trimmed, "+++") && !strings.HasPrefix(trimmed, "---") {
				result.Stats.IgnoredLines++
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ParseResult{}, fmt.Errorf("read trace: %w", err)
		}
	}
	if limited.N <= 0 {
		return ParseResult{}, fmt.Errorf("trace exceeds %d bytes", MaxTraceBytes)
	}
	return result, nil
}

func ParseEnvelope(data []byte) (ParseResult, []byte, int, error) {
	const header = "BEHAVIORLOCK_TRACE_V1\n"
	const footerPrefix = "\nBEHAVIORLOCK_TRACE_END exit="
	if !bytes.HasPrefix(data, []byte(header)) {
		return ParseResult{}, nil, 0, errors.New("trace envelope header is missing")
	}
	footerIndex := bytes.LastIndex(data, []byte(footerPrefix))
	if footerIndex < len(header) {
		return ParseResult{}, nil, 0, errors.New("trace envelope completion marker is missing")
	}
	footer := strings.TrimSpace(string(data[footerIndex+1:]))
	if !strings.HasPrefix(footer, "BEHAVIORLOCK_TRACE_END exit=") {
		return ParseResult{}, nil, 0, errors.New("trace envelope footer is invalid")
	}
	exitCode, err := strconv.Atoi(strings.TrimPrefix(footer, "BEHAVIORLOCK_TRACE_END exit="))
	if err != nil || exitCode < 0 || exitCode > 255 {
		return ParseResult{}, nil, 0, errors.New("trace envelope exit code is invalid")
	}
	raw := append([]byte(nil), data[len(header):footerIndex]...)
	parsed, err := Parse(bytes.NewReader(raw))
	if err != nil {
		return ParseResult{}, nil, 0, err
	}
	if parsed.Stats.RecognizedLines == 0 {
		return ParseResult{}, nil, 0, errors.New("trace envelope contains no recognized events")
	}
	if !hasSentinel(parsed.Behaviors, "/opt/behaviorlock/sentinel-start") || !hasSentinel(parsed.Behaviors, "/opt/behaviorlock/sentinel-end") {
		return ParseResult{}, nil, 0, errors.New("trace envelope sentinel events are missing")
	}
	return parsed, raw, exitCode, nil
}

func hasSentinel(behaviors []model.Behavior, target string) bool {
	for _, behavior := range behaviors {
		if behavior.Type == "filesystem.read" && behavior.Target == target && behavior.Outcome == "success" {
			return true
		}
	}
	return false
}

func parseLine(line string, lineNumber int) (model.Behavior, bool) {
	line = pidPattern.ReplaceAllString(line, "")
	line = plainPIDPattern.ReplaceAllString(line, "")
	open := strings.IndexByte(line, '(')
	if open <= 0 {
		return model.Behavior{}, false
	}
	call := strings.TrimSpace(line[:open])
	resultPart := syscallResult(line)
	outcome, errno := classifyResult(resultPart)
	evidence := fmt.Sprintf("trace:L%d", lineNumber)

	switch call {
	case "execve", "execveat":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false
		}
		arguments := quoted[1:]
		if len(arguments) > 32 {
			arguments = arguments[:32]
		}
		return model.Behavior{
			Type: "process.exec", Operation: "exec", Target: normalizePath(quoted[0]),
			Arguments: sanitizeValues(arguments), Outcome: outcome, Errno: errno,
			Count: 1, Evidence: evidence, SourceCall: call,
		}, true
	case "connect":
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
		target := family + ":" + address
		if port != "" {
			target += ":" + port
		}
		return model.Behavior{
			Type: "network.connect", Operation: "connect", Target: sanitize(target),
			Outcome: outcome, Errno: errno, Count: 1, Evidence: evidence, SourceCall: call,
		}, true
	case "open", "openat", "openat2", "creat":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false
		}
		path := normalizePath(quoted[0])
		operation := "read"
		behaviorType := "filesystem.read"
		if strings.Contains(line, "O_WRONLY") || strings.Contains(line, "O_RDWR") ||
			strings.Contains(line, "O_CREAT") || strings.Contains(line, "O_TRUNC") || strings.Contains(line, "O_APPEND") {
			operation = "write"
			behaviorType = "filesystem.write"
		}
		return fileBehavior(behaviorType, operation, path, call, outcome, errno, evidence), true
	case "access", "faccessat", "faccessat2", "stat", "lstat", "newfstatat", "readlink", "readlinkat":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false
		}
		return fileBehavior("filesystem.read", "inspect", normalizePath(quoted[0]), call, outcome, errno, evidence), true
	case "unlink", "unlinkat", "rmdir":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false
		}
		return fileBehavior("filesystem.delete", "delete", normalizePath(quoted[0]), call, outcome, errno, evidence), true
	case "mkdir", "mkdirat", "mknod", "mknodat", "symlink", "symlinkat", "link", "linkat":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false
		}
		return fileBehavior("filesystem.create", "create", normalizePath(quoted[len(quoted)-1]), call, outcome, errno, evidence), true
	case "rename", "renameat", "renameat2":
		quoted := extractQuoted(line)
		if len(quoted) < 2 {
			return model.Behavior{}, false
		}
		target := normalizePath(quoted[len(quoted)-2]) + " -> " + normalizePath(quoted[len(quoted)-1])
		return fileBehavior("filesystem.rename", "rename", target, call, outcome, errno, evidence), true
	case "chmod", "fchmodat", "chown", "lchown", "fchownat":
		quoted := extractQuoted(line)
		if len(quoted) == 0 {
			return model.Behavior{}, false
		}
		return fileBehavior("filesystem.permission", "permission", normalizePath(quoted[0]), call, outcome, errno, evidence), true
	default:
		return model.Behavior{}, false
	}
}

func fileBehavior(kind, operation, target, call, outcome, errno, evidence string) model.Behavior {
	return model.Behavior{
		Type: kind, Operation: operation, Target: target, Outcome: outcome, Errno: errno,
		Sensitive: isSensitivePath(target), Count: 1, Evidence: evidence, SourceCall: call,
	}
}

func extractQuoted(value string) []string {
	matches := quotedPattern.FindAllString(value, 64)
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		decoded, err := strconv.Unquote(match)
		if err != nil {
			continue
		}
		result = append(result, sanitize(decoded))
	}
	return result
}

func syscallResult(line string) string {
	index := strings.LastIndex(line, ") = ")
	if index < 0 {
		return ""
	}
	return strings.TrimSpace(line[index+4:])
}

func classifyResult(value string) (string, string) {
	if value == "" || strings.HasPrefix(value, "?") {
		return "unknown", ""
	}
	if !strings.HasPrefix(value, "-1 ") {
		return "success", ""
	}
	fields := strings.Fields(value)
	errno := "UNKNOWN"
	if len(fields) > 1 {
		errno = sanitize(fields[1])
	}
	switch errno {
	case "EACCES", "EPERM", "EROFS", "ENETUNREACH", "EHOSTUNREACH", "ECONNREFUSED":
		return "blocked", errno
	default:
		return "failed", errno
	}
}

func normalizePath(value string) string {
	value = sanitize(value)
	value = normalizeRoot(value, "/home/scanner", "$HOME")
	value = normalizeRoot(value, "/work", "$WORK")
	value = procPIDPattern.ReplaceAllString(value, "/proc/$PID")
	value = tmpPattern.ReplaceAllString(value, "$TMP")
	value = filepath.Clean(value)
	if strings.HasPrefix(value, "../") || value == ".." {
		return "$RELATIVE_ESCAPE/" + strings.TrimPrefix(value, "../")
	}
	return value
}

func normalizeRoot(value, root, replacement string) string {
	if value == root {
		return replacement
	}
	if strings.HasPrefix(value, root+"/") {
		return replacement + strings.TrimPrefix(value, root)
	}
	return value
}

func isSensitivePath(value string) bool {
	lower := strings.ToLower(value)
	patterns := []string{
		"/.ssh/", "/.npmrc", "/.netrc", "/.git-credentials", "/.aws/credentials",
		"/.config/gcloud/", "/.docker/config.json", "/run/secrets/", "/proc/$pid/environ",
		"id_rsa", "id_ed25519", "credentials.json",
	}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func firstMatch(pattern *regexp.Regexp, value string) string {
	match := pattern.FindStringSubmatch(value)
	if len(match) < 2 {
		return ""
	}
	return sanitize(match[1])
}

func sanitizeValues(values []string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = sanitize(value)
	}
	return result
}

func sanitize(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			builder.WriteString(fmt.Sprintf("\\u%04x", character))
			continue
		}
		builder.WriteRune(character)
		if builder.Len() >= 4096 {
			builder.WriteString("…")
			break
		}
	}
	return builder.String()
}
