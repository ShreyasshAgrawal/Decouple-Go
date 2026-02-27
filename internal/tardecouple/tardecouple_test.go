package tardecouple

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDecoupleTar_KnownHashes(t *testing.T) {
	// Use .tar.gz - gzip is reliably detected
	tarPath := filepath.Join("..", "..", "testdata", "sample.tar.gz")
	if _, err := os.Stat(tarPath); err != nil {
		t.Skipf("testdata/sample.tar.gz not found: %v", err)
	}

	report, err := DecoupleTar(tarPath, "tar.gz", nil)
	if err != nil {
		t.Fatalf("DecoupleTar: %v", err)
	}

	// Same content as sample.zip: a.txt="hello\n", sub/b.txt="world\n"
	h1 := sha256.Sum256([]byte("hello\n"))
	h2 := sha256.Sum256([]byte("world\n"))
	wantHashes := map[string]string{
		"a.txt":     hex.EncodeToString(h1[:]),
		"sub/b.txt": hex.EncodeToString(h2[:]),
	}

	for path, wantHash := range wantHashes {
		var found *string
		for i := range report.Nodes {
			if report.Nodes[i].Path == path {
				found = report.Nodes[i].SHA256
				break
			}
		}
		if found == nil {
			t.Errorf("node %q not found", path)
			continue
		}
		if *found != wantHash {
			t.Errorf("node %q sha256 = %q, want %q", path, *found, wantHash)
		}
	}
}

func TestDecoupleTar_Deterministic(t *testing.T) {
	tarPath := filepath.Join("..", "..", "testdata", "sample.tar.gz")
	if _, err := os.Stat(tarPath); err != nil {
		t.Skipf("testdata/sample.tar.gz not found: %v", err)
	}

	r1, err := DecoupleTar(tarPath, "tar.gz", nil)
	if err != nil {
		t.Fatalf("DecoupleTar 1: %v", err)
	}
	r2, err := DecoupleTar(tarPath, "tar.gz", nil)
	if err != nil {
		t.Fatalf("DecoupleTar 2: %v", err)
	}

	j1, _ := json.Marshal(r1)
	j2, _ := json.Marshal(r2)
	if string(j1) != string(j2) {
		t.Error("output is not deterministic: two runs produced different JSON")
	}
}

func TestDecoupleTar_Stats(t *testing.T) {
	tarPath := filepath.Join("..", "..", "testdata", "sample.tar.gz")
	if _, err := os.Stat(tarPath); err != nil {
		t.Skipf("testdata/sample.tar.gz not found: %v", err)
	}

	report, err := DecoupleTar(tarPath, "tar.gz", nil)
	if err != nil {
		t.Fatalf("DecoupleTar: %v", err)
	}

	if report.Stats.TotalNodes != 2 {
		t.Errorf("TotalNodes = %d, want 2", report.Stats.TotalNodes)
	}
	if report.Stats.Files != 2 {
		t.Errorf("Files = %d, want 2", report.Stats.Files)
	}
	if report.Stats.Dirs != 0 {
		t.Errorf("Dirs = %d, want 0", report.Stats.Dirs)
	}
	if report.Stats.BytesHashed != 12 {
		t.Errorf("BytesHashed = %d, want 12 (6+6)", report.Stats.BytesHashed)
	}
}
