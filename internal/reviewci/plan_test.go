package reviewci

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func testReference() PullRequestRef {
	return PullRequestRef{
		Repository: "owner/project", Number: 42, BaseRepository: "owner/project", BaseSHA: strings.Repeat("a", 40),
		HeadRepository: "contributor/project", HeadSHA: strings.Repeat("b", 40),
	}
}

func packageManifest(scope, name, version string) []byte {
	return []byte(fmt.Sprintf(`{"name":"consumer","packageManager":"npm@11.0.0","%s":{"%s":"%s"}}`, scope, name, version))
}

func TestBuildPlanAcceptsOneExactVersionChange(t *testing.T) {
	t.Parallel()
	plan, err := BuildPlan(testReference(),
		packageManifest("dependencies", "@scope/example", "1.2.3"),
		packageManifest("dependencies", "@scope/example", "1.3.0-beta.1+build.7"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Skipped || plan.BaselinePackage != "@scope/example@1.2.3" ||
		plan.CandidatePackage != "@scope/example@1.3.0-beta.1+build.7" || plan.DependencyScope != "dependencies" {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildPlanRejectsAmbiguousDependencySources(t *testing.T) {
	t.Parallel()
	for _, version := range []string{
		"latest", "^2.0.0", "2.x", "https://example.invalid/pkg.tgz", "git+https://example.invalid/repo.git",
		"file:../package", "../package", "--privileged", "2.0.0\n--network=host",
	} {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			candidate, _ := json.Marshal(map[string]any{"dependencies": map[string]string{"example": version}})
			if _, err := BuildPlan(testReference(), packageManifest("dependencies", "example", "1.0.0"), candidate); err == nil {
				t.Fatalf("ambiguous dependency source %q unexpectedly passed", version)
			}
		})
	}
}

func TestBuildPlanRejectsMultipleOrDuplicateChanges(t *testing.T) {
	t.Parallel()
	baseline := []byte(`{"dependencies":{"left":"1.0.0","right":"1.0.0"}}`)
	candidate := []byte(`{"dependencies":{"left":"2.0.0","right":"2.0.0"}}`)
	if _, err := BuildPlan(testReference(), baseline, candidate); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("multiple dependency changes were not rejected: %v", err)
	}
	for _, malformed := range [][]byte{
		[]byte(`{"dependencies":{"example":"1.0.0","example":"2.0.0"}}`),
		[]byte(`{"dependencies":{"example":"1.0.0"},"dependencies":{"example":"2.0.0"}}`),
		[]byte(`{"dependencies":{"example":"1.0.0"},"devDependencies":{"example":"1.0.0"}}`),
	} {
		if _, err := BuildPlan(testReference(), malformed, packageManifest("dependencies", "example", "2.0.0")); err == nil {
			t.Fatalf("duplicate dependency declaration unexpectedly passed: %s", malformed)
		}
	}
}

func TestBuildPlanSkipsUnsupportedPairsAndLockfileOnlyUpdates(t *testing.T) {
	t.Parallel()
	unchanged := packageManifest("dependencies", "example", "1.0.0")
	plan, err := BuildPlan(testReference(), unchanged, unchanged)
	if err != nil || !plan.Skipped || !strings.Contains(plan.SkipReason, "no root exact-version") {
		t.Fatalf("lockfile-only plan = %#v err=%v", plan, err)
	}
	plan, err = BuildPlan(testReference(), unchanged, []byte(`{"dependencies":{}}`))
	if err != nil || !plan.Skipped || !strings.Contains(plan.SkipReason, "additions and removals") {
		t.Fatalf("removed dependency plan = %#v err=%v", plan, err)
	}
	plan, err = BuildPlan(testReference(), nil, nil)
	if err != nil || !plan.Skipped {
		t.Fatalf("missing manifests plan = %#v err=%v", plan, err)
	}
}

func TestBuildPlanRejectsUnsupportedPackageManagerAndIgnoresScopeOnlyMove(t *testing.T) {
	t.Parallel()
	if _, err := BuildPlan(testReference(),
		[]byte(`{"packageManager":"yarn@4.0.0","dependencies":{"example":"1.0.0"}}`),
		[]byte(`{"packageManager":"yarn@4.0.0","dependencies":{"example":"2.0.0"}}`)); err == nil {
		t.Fatal("unsupported package manager unexpectedly passed")
	}
	plan, err := BuildPlan(testReference(),
		packageManifest("dependencies", "example", "1.0.0"),
		packageManifest("devDependencies", "example", "1.0.0"))
	if err != nil || !plan.Skipped {
		t.Fatalf("scope-only move should not execute package code: %#v err=%v", plan, err)
	}
}

func TestPullRequestEventUsesDependabotAndOrdinaryPRsIdentically(t *testing.T) {
	t.Parallel()
	base := map[string]any{
		"action":     "synchronize",
		"repository": map[string]any{"full_name": "owner/project"},
		"pull_request": map[string]any{
			"number": 42,
			"base":   map[string]any{"sha": strings.Repeat("a", 40), "repo": map[string]any{"full_name": "owner/project"}},
			"head":   map[string]any{"sha": strings.Repeat("b", 40), "repo": map[string]any{"full_name": "contributor/project"}},
		},
	}
	ordinary := cloneMap(base)
	ordinary["sender"] = map[string]any{"login": "contributor"}
	dependabot := cloneMap(base)
	dependabot["sender"] = map[string]any{"login": "dependabot[bot]"}
	ordinaryRaw, _ := json.Marshal(ordinary)
	dependabotRaw, _ := json.Marshal(dependabot)
	left, leftErr := ParsePullRequestEvent(ordinaryRaw)
	right, rightErr := ParsePullRequestEvent(dependabotRaw)
	if leftErr != nil || rightErr != nil || !reflect.DeepEqual(left, right) {
		t.Fatalf("ordinary=%#v err=%v dependabot=%#v err=%v", left, leftErr, right, rightErr)
	}
}

func TestPullRequestEventRejectsInvalidIdentityAndTrailingJSON(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"action":"opened","repository":{"full_name":"owner/project"},"pull_request":{"number":1,"base":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"full_name":"owner/project"}},"head":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"fork/project"}}}}`)
	if _, err := ParsePullRequestEvent(append(raw, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing event JSON unexpectedly passed")
	}
	invalidAction := strings.Replace(string(raw), `"opened"`, `"closed"`, 1)
	if _, err := ParsePullRequestEvent([]byte(invalidAction)); err == nil {
		t.Fatal("unsupported pull request action unexpectedly passed")
	}
	invalidSHA := strings.Replace(string(raw), strings.Repeat("b", 40), "not-a-sha", 1)
	if _, err := ParsePullRequestEvent([]byte(invalidSHA)); err == nil {
		t.Fatal("invalid head SHA unexpectedly passed")
	}
}

func cloneMap(source map[string]any) map[string]any {
	raw, _ := json.Marshal(source)
	var cloned map[string]any
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}
