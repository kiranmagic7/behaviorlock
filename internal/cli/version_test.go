package cli

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersionPrefersInjectedReleaseVersion(t *testing.T) {
	t.Parallel()
	info := &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}}
	if got := resolveVersion("v0.1.0", info); got != "v0.1.0" {
		t.Fatalf("version = %q", got)
	}
}

func TestResolveVersionUsesModuleVersion(t *testing.T) {
	t.Parallel()
	info := &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}}
	if got := resolveVersion("", info); got != "v0.2.0" {
		t.Fatalf("version = %q", got)
	}
}

func TestResolveVersionRejectsUntrustedVersionText(t *testing.T) {
	t.Parallel()
	info := &debug.BuildInfo{Main: debug.Module{Version: "bad\nversion"}}
	if got := resolveVersion(" bad ", info); got != developmentVersion {
		t.Fatalf("version = %q", got)
	}
}
