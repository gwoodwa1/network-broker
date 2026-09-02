package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsConstructorBypass(t *testing.T) {
	root := writeFixture(t, `package main

import "example.com/project/internal/widget"

func main() { _ = widget.Widget{} }
`)

	err := run(root)
	if err == nil || !strings.Contains(err.Error(), "direct struct construction") {
		t.Fatalf("run() error = %v, want constructor bypass error", err)
	}
}

func TestRunAcceptsConstructorCall(t *testing.T) {
	root := writeFixture(t, `package main

import "example.com/project/internal/widget"

func main() { _ = widget.NewWidget() }
`)

	if err := run(root); err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func writeFixture(t *testing.T, mainSource string) string {
	t.Helper()

	root := t.TempDir()
	writeFixtureFile(t, root, "go.mod", "module example.com/project\n\ngo 1.27.1\n")
	writeFixtureFile(t, root, "internal/widget/widget.go", `package widget

type Widget struct{}

func NewWidget() *Widget { return &Widget{} }
`)
	writeFixtureFile(t, root, "cmd/app/main.go", mainSource)

	return root
}

func writeFixtureFile(t *testing.T, root, relativePath, contents string) {
	t.Helper()

	path := filepath.Join(root, relativePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
}
