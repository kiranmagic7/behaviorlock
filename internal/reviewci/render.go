package reviewci

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/kiranmagic7/behaviorlock/internal/model"
)

func RenderComment(manifest ArtifactManifest, directory string) (string, error) {
	if err := validateManifest(manifest); err != nil {
		return "", err
	}
	var builder strings.Builder
	builder.WriteString(CommentMarker)
	builder.WriteString("\n## BehaviorLock dependency behavior evidence\n\n")
	if manifest.Plan.Skipped {
		fmt.Fprintf(&builder, "Capture skipped: %s.\n\n", markdownText(manifest.Plan.SkipReason, 256))
		builder.WriteString("No package code was executed by the privileged workflow.\n")
		return boundedComment(builder.String())
	}
	reportRaw, err := readBoundedRegularFile(filepath.Join(directory, diffFilename), 32<<20)
	if err != nil {
		return "", err
	}
	var report model.Diff
	if err := decodeSingleJSON(reportRaw, &report, true); err != nil {
		return "", fmt.Errorf("decode validated report for rendering: %w", err)
	}
	fmt.Fprintf(&builder, "Observed package: `%s` → `%s`  \n", markdownCode(manifest.Plan.BaselinePackage, 256), markdownCode(manifest.Plan.CandidatePackage, 256))
	fmt.Fprintf(&builder, "Review threshold reached: **%s** (`%s`)  \n", yesNo(manifest.Result.ThresholdReached), markdownCode(manifest.Result.Threshold, 16))
	fmt.Fprintf(&builder, "Highest review level: **%s**  \n", markdownText(manifest.Result.HighestReviewLevel, 16))
	fmt.Fprintf(&builder, "Added observations: **%d** · Removed observations: **%d** · Added sequences: **%d** · Removed sequences: **%d**\n\n",
		len(report.Added), len(report.Removed), len(report.AddedSequences), len(report.RemovedSequences))

	if len(report.Added) == 0 {
		builder.WriteString("No new normalized behavior was observed in this capture pair.\n\n")
	} else {
		builder.WriteString("| Review level | Rule | Observed behavior |\n| --- | --- | --- |\n")
		limit := min(len(report.Added), 50)
		for _, change := range report.Added[:limit] {
			target := change.Behavior.Type + " " + change.Behavior.Target
			fmt.Fprintf(&builder, "| %s | `%s` | %s |\n",
				markdownText(change.ReviewLevel, 16), markdownCode(change.RuleID, 32), markdownText(target, 320))
		}
		if len(report.Added) > limit {
			fmt.Fprintf(&builder, "\n%d additional observations remain in the retained JSON diff.\n", len(report.Added)-limit)
		}
		builder.WriteString("\n")
	}
	if len(report.Limitations) > 0 {
		builder.WriteString("Capture limitations:\n")
		for _, limitation := range report.Limitations[:min(len(report.Limitations), 8)] {
			fmt.Fprintf(&builder, "- %s\n", markdownText(limitation, 500))
		}
		builder.WriteString("\n")
	}
	fmt.Fprintf(&builder, "Runner fingerprint: `%s`  \n", markdownCode(manifest.RunnerImageID, 80))
	fmt.Fprintf(&builder, "Acquisition policy: `%s`\n\n", markdownCode(manifest.Acquisition, 64))
	builder.WriteString("This is observed evidence for human review, not a package safety verdict. Profiles and raw evidence were structurally revalidated; signer authenticity is not asserted. The privileged workflow did not execute pull-request code or artifact content.\n")
	return boundedComment(builder.String())
}

func markdownText(value string, limit int) string {
	value = safeDisplayText(value, limit)
	replacer := strings.NewReplacer(
		"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "{", "\\{", "}", "\\}",
		"[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)", "#", "\\#", "+", "\\+", "-", "\\-",
		".", "\\.", "!", "\\!", "|", "\\|", ">", "\\>", "<", "&lt;",
	)
	return replacer.Replace(value)
}

func markdownCode(value string, limit int) string {
	return strings.ReplaceAll(safeDisplayText(value, limit), "`", "\\`")
}

func safeDisplayText(value string, limit int) string {
	var builder strings.Builder
	for _, character := range value {
		if builder.Len() >= limit {
			break
		}
		if character < 0x20 || character == 0x7f || !utf8.ValidRune(character) {
			builder.WriteByte(' ')
			continue
		}
		if builder.Len()+utf8.RuneLen(character) > limit {
			break
		}
		builder.WriteRune(character)
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}

func boundedComment(comment string) (string, error) {
	if !strings.HasPrefix(comment, CommentMarker) {
		return "", errors.New("comment marker is missing")
	}
	if len(comment) > 60_000 || !utf8.ValidString(comment) {
		return "", errors.New("rendered comment exceeds its safety bound")
	}
	return comment, nil
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
