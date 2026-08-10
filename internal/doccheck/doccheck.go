package doccheck

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxMarkdownBytes = 4 << 20

var inlineLinkPattern = regexp.MustCompile(`!?\[[^\]]*\]\(([^)]+)\)`)

type Issue struct {
	File   string
	Line   int
	Target string
	Reason string
}

func (issue Issue) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", issue.File, issue.Line, issue.Target, issue.Reason)
}

func Check(root string) ([]Issue, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var issues []Issue
	err = filepath.WalkDir(absoluteRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" || entry.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".md") {
			return nil
		}
		fileIssues, err := checkFile(absoluteRoot, path)
		if err != nil {
			return err
		}
		issues = append(issues, fileIssues...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].File != issues[j].File {
			return issues[i].File < issues[j].File
		}
		if issues[i].Line != issues[j].Line {
			return issues[i].Line < issues[j].Line
		}
		return issues[i].Target < issues[j].Target
	})
	return issues, nil
}

func checkFile(root, path string) ([]Issue, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxMarkdownBytes {
		return nil, fmt.Errorf("markdown file %s exceeds %d bytes", path, maxMarkdownBytes)
	}
	// #nosec G304 -- path is obtained from the bounded repository walk.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	relativeFile, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	var issues []Issue
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		for _, match := range inlineLinkPattern.FindAllStringSubmatch(scanner.Text(), -1) {
			target := normalizeTarget(match[1])
			if target == "" || externalTarget(target) {
				continue
			}
			decoded, err := url.PathUnescape(target)
			if err != nil {
				issues = append(issues, Issue{relativeFile, lineNumber, target, "invalid URL escape"})
				continue
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(path), filepath.FromSlash(decoded)))
			relativeToRoot, relErr := filepath.Rel(root, resolved)
			if relErr != nil || relativeToRoot == ".." || strings.HasPrefix(relativeToRoot, ".."+string(filepath.Separator)) {
				issues = append(issues, Issue{relativeFile, lineNumber, target, "target escapes repository"})
				continue
			}
			if _, statErr := os.Stat(resolved); statErr != nil {
				issues = append(issues, Issue{relativeFile, lineNumber, target, "target does not exist"})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return issues, nil
}

func normalizeTarget(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "<") {
		if end := strings.Index(value, ">"); end > 0 {
			value = value[1:end]
		}
	} else if separator := strings.IndexAny(value, " \t"); separator >= 0 {
		value = value[:separator]
	}
	if fragment := strings.IndexByte(value, '#'); fragment >= 0 {
		value = value[:fragment]
	}
	if query := strings.IndexByte(value, '?'); query >= 0 {
		value = value[:query]
	}
	return value
}

func externalTarget(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasPrefix(value, "#") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "data:")
}
