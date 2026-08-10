package compare

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kiranmagic7/behaviorlock/internal/model"
)

type Options struct {
	AllowExternal bool
}

func Profiles(baseline, candidate model.Profile, toolVersion string) (model.Diff, error) {
	return ProfilesWithOptions(baseline, candidate, toolVersion, Options{})
}

func ProfilesWithOptions(baseline, candidate model.Profile, toolVersion string, options Options) (model.Diff, error) {
	if err := model.ValidateProfile(baseline); err != nil {
		return model.Diff{}, fmt.Errorf("baseline: %w", err)
	}
	if err := model.ValidateProfile(candidate); err != nil {
		return model.Diff{}, fmt.Errorf("candidate: %w", err)
	}
	if baseline.Result.Status != "complete" || candidate.Result.Status != "complete" {
		return model.Diff{}, fmt.Errorf("both profiles must have complete traces; baseline=%s candidate=%s", baseline.Result.Status, candidate.Result.Status)
	}
	if baseline.Subject.Name != candidate.Subject.Name {
		return model.Diff{}, fmt.Errorf("profiles describe different packages: %s and %s", baseline.Subject.Name, candidate.Subject.Name)
	}
	if baseline.Capture.TraceIntegrity != candidate.Capture.TraceIntegrity {
		return model.Diff{}, fmt.Errorf("profiles use different trace integrity modes: %s and %s", baseline.Capture.TraceIntegrity, candidate.Capture.TraceIntegrity)
	}
	if baseline.Capture.TraceIntegrity == "external-unverified" && !options.AllowExternal {
		return model.Diff{}, fmt.Errorf("external unverified profiles require explicit allowExternal acknowledgement")
	}
	checks := []struct {
		label               string
		baseline, candidate string
	}{
		{"capture phase", baseline.Capture.Phase, candidate.Capture.Phase},
		{"runner image reference", baseline.Capture.RunnerImage, candidate.Capture.RunnerImage},
		{"runner image id", baseline.Capture.RunnerImageID, candidate.Capture.RunnerImageID},
		{"architecture", baseline.Capture.Architecture, candidate.Capture.Architecture},
		{"node version", baseline.Capture.NodeVersion, candidate.Capture.NodeVersion},
		{"npm version", baseline.Capture.NPMVersion, candidate.Capture.NPMVersion},
		{"strace version", baseline.Capture.StraceVersion, candidate.Capture.StraceVersion},
		{"observation policy", baseline.Capture.ObservationPolicy, candidate.Capture.ObservationPolicy},
		{"network mode", baseline.Capture.NetworkMode, candidate.Capture.NetworkMode},
		{"sandbox profile", baseline.Capture.SandboxProfile, candidate.Capture.SandboxProfile},
		{"coverage scope", baseline.Capture.Coverage.Scope, candidate.Capture.Coverage.Scope},
	}
	for _, check := range checks {
		if check.baseline != check.candidate {
			return model.Diff{}, fmt.Errorf("profiles have different %s: %s and %s", check.label, check.baseline, check.candidate)
		}
	}
	if (baseline.Capture.Acquisition == nil) != (candidate.Capture.Acquisition == nil) {
		return model.Diff{}, fmt.Errorf("profiles use different acquisition controls")
	}
	if baseline.Capture.Acquisition != nil {
		acquisitionChecks := []struct {
			label               string
			baseline, candidate string
		}{
			{"acquisition network mode", baseline.Capture.Acquisition.NetworkMode, candidate.Capture.Acquisition.NetworkMode},
			{"acquisition policy version", baseline.Capture.Acquisition.PolicyVersion, candidate.Capture.Acquisition.PolicyVersion},
			{"acquisition allowed authority", baseline.Capture.Acquisition.AllowedAuthority, candidate.Capture.Acquisition.AllowedAuthority},
			{"acquisition proxy image id", baseline.Capture.Acquisition.ProxyRunnerImageID, candidate.Capture.Acquisition.ProxyRunnerImageID},
		}
		for _, check := range acquisitionChecks {
			if check.baseline != check.candidate {
				return model.Diff{}, fmt.Errorf("profiles have different %s: %s and %s", check.label, check.baseline, check.candidate)
			}
		}
	}
	baseline.Normalize()
	candidate.Normalize()
	baselineDigest, err := baseline.StableDigest()
	if err != nil {
		return model.Diff{}, err
	}
	candidateDigest, err := candidate.StableDigest()
	if err != nil {
		return model.Diff{}, err
	}

	baselineByKey := make(map[string]model.Behavior, len(baseline.Behaviors))
	for _, behavior := range baseline.Behaviors {
		baselineByKey[model.BehaviorKey(behavior)] = behavior
	}
	candidateByKey := make(map[string]model.Behavior, len(candidate.Behaviors))
	for _, behavior := range candidate.Behaviors {
		candidateByKey[model.BehaviorKey(behavior)] = behavior
	}

	diff := model.Diff{
		SchemaVersion:    model.DiffSchemaVersion,
		Kind:             model.DiffKind,
		Tool:             model.ToolInfo{Name: "behaviorlock", Version: toolVersion},
		Phase:            candidate.Capture.Phase,
		Baseline:         baseline.Subject,
		Candidate:        candidate.Subject,
		BaselineDigest:   baselineDigest,
		CandidateDigest:  candidateDigest,
		Added:            []model.Change{},
		Removed:          []model.Behavior{},
		AddedSequences:   []model.ObservationSequence{},
		RemovedSequences: []model.ObservationSequence{},
		Limitations: []string{
			fmt.Sprintf("BehaviorLock compares behavior observed during the %s phase, not total package behavior.", candidate.Capture.Phase),
			"A new behavior is a review signal and is not a malware classification.",
			"Profiles and evidence companions are unsigned. Integrity verification does not establish producer authenticity or provenance.",
		},
	}
	if baseline.Capture.TraceIntegrity == "external-unverified" {
		diff.Limitations = append(diff.Limitations, "The caller explicitly allowed external unverified traces; sandbox and capture provenance are not attested.")
	}
	for key, behavior := range candidateByKey {
		if _, exists := baselineByKey[key]; !exists {
			reviewLevel, ruleID, reason := classify(behavior)
			diff.Added = append(diff.Added, model.Change{ReviewLevel: reviewLevel, RuleID: ruleID, Reason: reason, Behavior: behavior, Techniques: techniquesForRule(ruleID)})
		}
	}
	for key, behavior := range baselineByKey {
		if _, exists := candidateByKey[key]; !exists {
			diff.Removed = append(diff.Removed, behavior)
		}
	}
	baselineSequences := make(map[string]model.ObservationSequence, len(baseline.Sequences))
	for _, sequence := range baseline.Sequences {
		baselineSequences[sequence.ID] = sequence
	}
	candidateSequences := make(map[string]model.ObservationSequence, len(candidate.Sequences))
	for _, sequence := range candidate.Sequences {
		candidateSequences[sequence.ID] = sequence
		if _, exists := baselineSequences[sequence.ID]; !exists {
			diff.AddedSequences = append(diff.AddedSequences, sequence)
		}
	}
	for _, sequence := range baseline.Sequences {
		if _, exists := candidateSequences[sequence.ID]; !exists {
			diff.RemovedSequences = append(diff.RemovedSequences, sequence)
		}
	}
	sort.Slice(diff.Added, func(i, j int) bool {
		left, right := diff.Added[i], diff.Added[j]
		if model.ReviewLevelRank(left.ReviewLevel) != model.ReviewLevelRank(right.ReviewLevel) {
			return model.ReviewLevelRank(left.ReviewLevel) > model.ReviewLevelRank(right.ReviewLevel)
		}
		return model.BehaviorKey(left.Behavior) < model.BehaviorKey(right.Behavior)
	})
	sort.Slice(diff.Removed, func(i, j int) bool {
		return model.BehaviorKey(diff.Removed[i]) < model.BehaviorKey(diff.Removed[j])
	})
	sort.Slice(diff.AddedSequences, func(i, j int) bool { return diff.AddedSequences[i].ID < diff.AddedSequences[j].ID })
	sort.Slice(diff.RemovedSequences, func(i, j int) bool { return diff.RemovedSequences[i].ID < diff.RemovedSequences[j].ID })
	highest := "none"
	for _, change := range diff.Added {
		if model.ReviewLevelRank(change.ReviewLevel) > model.ReviewLevelRank(highest) {
			highest = change.ReviewLevel
		}
	}
	diff.Summary = model.DiffSummary{
		Added:              len(diff.Added),
		Removed:            len(diff.Removed),
		ReviewRequired:     len(diff.Added) > 0 || len(diff.AddedSequences) > 0,
		HighestReviewLevel: highest,
	}
	return diff, nil
}

func techniquesForRule(ruleID string) []model.TechniqueRef {
	techniques := map[string][]model.TechniqueRef{
		"BL100": {{Framework: "MITRE ATT&CK", ID: "T1552.004", Relationship: "consistent with"}},
		"BL300": {{Framework: "MITRE ATT&CK", ID: "T1059", Relationship: "consistent with"}},
		"BL303": {{Framework: "MITRE ATT&CK", ID: "T1620", Relationship: "consistent with"}},
		"BL600": {{Framework: "MITRE ATT&CK", ID: "T1497.001", Relationship: "consistent with"}},
	}
	return append([]model.TechniqueRef(nil), techniques[ruleID]...)
}

func classify(behavior model.Behavior) (string, string, string) {
	if behavior.Sensitive {
		return "critical", "BL100", "new access to a common credential or secret path"
	}
	switch behavior.Type {
	case "network.connect":
		return "high", "BL200", "new network connection attempt during the selected observation phase"
	case "network.send":
		return "high", "BL201", "new network send attempt during the selected observation phase"
	case "network.dns":
		return "high", "BL202", "new network send to port 53 during the selected observation phase"
	case "network.bind", "network.listen":
		return "high", "BL203", "new local network listener setup during the selected observation phase"
	case "network.accept":
		return "medium", "BL204", "new inbound connection acceptance attempt"
	case "network.socket":
		return "low", "BL205", "new network socket creation"
	case "process.exec", "process.fileless_exec":
		if behavior.Type == "process.fileless_exec" {
			return "high", "BL303", "new descriptor-backed executable launch"
		}
		base := strings.ToLower(filepath.Base(behavior.Target))
		highRisk := map[string]bool{
			"sh": true, "bash": true, "dash": true, "zsh": true, "curl": true,
			"wget": true, "nc": true, "ncat": true, "ssh": true, "scp": true,
		}
		if highRisk[base] {
			return "high", "BL300", "new shell, downloader, or remote access process"
		}
		return "medium", "BL301", "new executable process"
	case "process.create":
		return "medium", "BL302", "new child process creation"
	case "process.memfd":
		return "high", "BL303", "new anonymous memory file creation"
	case "process.ptrace":
		return "medium", "BL304", "new process tracing or inspection attempt"
	case "filesystem.write", "filesystem.create", "filesystem.rename":
		if !allowedWriteTarget(behavior.Target) {
			return "high", "BL400", "new filesystem mutation outside the disposable work and temporary roots"
		}
		return "medium", "BL401", "new filesystem mutation"
	case "filesystem.delete", "filesystem.permission":
		return "medium", "BL402", "new destructive or permission changing filesystem operation"
	case "filesystem.truncate", "filesystem.descriptor_write":
		return "high", "BL403", "new truncation or descriptor-backed file mutation"
	case "filesystem.enumerate":
		return "low", "BL501", "new directory enumeration"
	case "filesystem.read":
		if isEnvironmentFingerprintPath(behavior.Target) {
			return "medium", "BL600", "new access to a path commonly used to detect containers or tracing"
		}
		return "low", "BL500", "new filesystem read or metadata inspection"
	case "environment.timing":
		return "low", "BL601", "new clock inspection or requested delay observation"
	default:
		return "low", "BL900", "new observed behavior"
	}
}

func isEnvironmentFingerprintPath(target string) bool {
	switch target {
	case "/.dockerenv",
		"/run/.containerenv",
		"/proc/$PID/cgroup",
		"/proc/self/status",
		"/proc/self/mountinfo",
		"/proc/cpuinfo",
		"/proc/meminfo",
		"/proc/uptime",
		"/sys/class/dmi":
		return true
	default:
		return strings.HasPrefix(target, "/sys/class/dmi/")
	}
}

func allowedWriteTarget(target string) bool {
	return target == "$WORK" || strings.HasPrefix(target, "$WORK/") ||
		target == "$TMP" || strings.HasPrefix(target, "$TMP/") ||
		target == "$HOME/.npm" || strings.HasPrefix(target, "$HOME/.npm/")
}
