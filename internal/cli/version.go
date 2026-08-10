package cli

import (
	"runtime/debug"
	"strings"
	"unicode"
)

const developmentVersion = "0.1.0-dev"

// injectedVersion is set by release builds with -ldflags -X.
var injectedVersion string

var Version = resolveVersion(injectedVersion, readBuildInfo())

func readBuildInfo() *debug.BuildInfo {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return info
}

func resolveVersion(injected string, info *debug.BuildInfo) string {
	if validVersion(injected) {
		return injected
	}
	if info != nil && info.Main.Version != "(devel)" && validVersion(info.Main.Version) {
		return info.Main.Version
	}
	return developmentVersion
}

func validVersion(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
