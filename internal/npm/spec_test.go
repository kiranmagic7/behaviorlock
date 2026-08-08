package npm

import "testing"

func TestParseExactSpecAcceptsRegistryVersions(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"lodash@4.17.21", "@scope/name@1.2.3", "pkg-name@1.0.0-beta.1+build.7"} {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseExactSpec(input); err != nil {
				t.Fatalf("ParseExactSpec(%q): %v", input, err)
			}
		})
	}
}

func TestParseExactSpecRejectsAmbiguousOrInjectableInputs(t *testing.T) {
	t.Parallel()
	inputs := []string{
		"lodash", "lodash@latest", "lodash@^4.0.0", "lodash@4.x",
		"lodash@4.17.21;id", "lodash@4.17.21\n--privileged",
		"--privileged@1.0.0", "file:../pkg@1.0.0", "https://example.com/x.tgz@1.0.0",
		"pkg@v1.2.3", "pkg@01.2.3", "pkg@1.2",
	}
	for _, input := range inputs {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseExactSpec(input); err == nil {
				t.Fatalf("ParseExactSpec(%q) unexpectedly succeeded", input)
			}
		})
	}
}

func TestPURL(t *testing.T) {
	t.Parallel()
	spec, err := ParseExactSpec("@scope/name@1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := spec.PURL(), "pkg:npm/%40scope/name@1.2.3"; got != want {
		t.Fatalf("PURL() = %q, want %q", got, want)
	}
}
