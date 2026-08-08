package npm

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	namePartPattern = `[a-z0-9](?:[a-z0-9._~-]{0,212}[a-z0-9])?`
	namePattern     = regexp.MustCompile(`^(?:@(` + namePartPattern + `)/)?(` + namePartPattern + `)$`)
	versionPattern  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
)

type Spec struct {
	Name    string
	Version string
}

func ParseExactSpec(value string) (Spec, error) {
	if value == "" || len(value) > 256 {
		return Spec{}, fmt.Errorf("package specification must contain at most 256 ASCII characters")
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return Spec{}, fmt.Errorf("package specification must use printable ASCII without whitespace")
		}
	}
	separator := strings.LastIndex(value, "@")
	if separator <= 0 || separator == len(value)-1 {
		return Spec{}, fmt.Errorf("expected an exact registry package version such as lodash@4.17.21")
	}
	name := value[:separator]
	version := value[separator+1:]
	if !namePattern.MatchString(name) {
		return Spec{}, fmt.Errorf("invalid npm package name %q", name)
	}
	if !versionPattern.MatchString(version) {
		return Spec{}, fmt.Errorf("version must be an exact semantic version, received %q", version)
	}
	return Spec{Name: name, Version: version}, nil
}

func (s Spec) String() string {
	return s.Name + "@" + s.Version
}

func (s Spec) PURL() string {
	name := s.Name
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		name = "%40" + url.PathEscape(strings.TrimPrefix(parts[0], "@")) + "/" + url.PathEscape(parts[1])
	} else {
		name = url.PathEscape(name)
	}
	return "pkg:npm/" + name + "@" + url.PathEscape(s.Version)
}
