package doccheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckAcceptsRelativeAndExternalLinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("[guide](docs/guide.md) [site](https://example.com)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "guide.md"), []byte("# Guide\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	issues, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("valid links were rejected: %#v", issues)
	}
}

func TestCheckReportsMissingAndEscapingLinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	markdown := "[missing](missing.md)\n[escape](../outside.md)\n"
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte(markdown), 0o600); err != nil {
		t.Fatal(err)
	}
	issues, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 2 || issues[0].Line != 1 || issues[1].Line != 2 {
		t.Fatalf("unexpected link issues: %#v", issues)
	}
}
