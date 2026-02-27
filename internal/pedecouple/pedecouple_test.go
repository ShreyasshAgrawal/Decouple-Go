package pedecouple

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"decouple/internal/scanconfig"
)

func TestDecouplePE_ParsesSections(t *testing.T) {
	pePath := buildTestPE(t)
	defer os.Remove(pePath)

	rep, err := DecouplePE(pePath, "exe", &scanconfig.Config{
		MaxPESections: 96,
	})
	if err != nil {
		t.Fatalf("DecouplePE: %v", err)
	}
	if len(rep.Nodes) == 0 {
		t.Fatalf("expected at least one section node")
	}

	for _, n := range rep.Nodes {
		if !strings.HasPrefix(n.Path, "sections/") {
			t.Fatalf("unexpected section path %q", n.Path)
		}
		if n.SHA256 == nil && n.HashError == "" {
			t.Fatalf("expected sha256 or hash error on node %q", n.Path)
		}
	}
	if rep.Artifact.InputPath != pePath {
		t.Fatalf("artifact input path = %q, want %q", rep.Artifact.InputPath, pePath)
	}
	if rep.Artifact.Kind != "exe" {
		t.Fatalf("artifact kind = %q, want exe", rep.Artifact.Kind)
	}
}

func buildTestPE(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "main.go")
	outPath := filepath.Join(tmpDir, "sample.exe")

	src := "package main\nfunc main(){}\n"
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", outPath, srcPath)
	cmd.Env = append(os.Environ(),
		"GOOS=windows",
		"GOARCH=amd64",
		"CGO_ENABLED=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build test pe: %v\n%s", err, string(out))
	}
	return outPath
}
